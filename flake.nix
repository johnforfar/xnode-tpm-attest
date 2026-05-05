{
  description = "xnode-tpm-attest — TPM2 remote-attestation self-test for xnodes, Own1 nodes, and any Linux machine with a TPM";

  inputs = {
    xnode-manager.url = "github:Openmesh-Network/xnode-manager";
    # Follow openclaw's nixpkgs pin — known-working with xnode-manager's
    # nixos-containers (dhcpcd starts, mDNS publishes). xnode-manager's own
    # bleeding-edge unstable causes container-boot failures.
    openclaw.url = "github:openclaw/nix-openclaw";
    nixpkgs.follows = "openclaw/nixpkgs";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, xnode-manager, openclaw, flake-utils }:
    let
      # Runtime closure — every binary attest.sh shells out to is pinned here.
      attestRuntime = pkgs: pkgs.symlinkJoin {
        name = "xnode-tpm-attest-runtime";
        paths = with pkgs; [
          tpm2-tools
          openssl
          coreutils
          gnugrep
          gnused
          gawk
          util-linux
          xxd
          bash
        ];
      };

      # Wrapped attest.sh with PATH pre-baked.
      attestApp = pkgs:
        let runtime = attestRuntime pkgs; in
        pkgs.writeShellApplication {
          name = "xnode-tpm-attest";
          runtimeInputs = [ runtime ];
          text = ''
            CA_DIR_DEFAULT=${./ca-bundle}
            export CA_DIR="''${CA_DIR:-$CA_DIR_DEFAULT}"
            exec ${./scripts/attest.sh} "$@"
          '';
        };

    in
    (flake-utils.lib.eachDefaultSystem (system:
      let pkgs = import nixpkgs { inherit system; }; in
      {
        # `nix run github:johnforfar/xnode-tpm-attest`
        apps.default = {
          type = "app";
          program = "${attestApp pkgs}/bin/xnode-tpm-attest";
        };

        # `nix build` produces a runnable artifact.
        packages.default = attestApp pkgs;

        # `nix develop` for hacking on the script.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [ tpm2-tools openssl xxd shellcheck ];
        };
      }))

    //

    {
      # `om app deploy --flake github:johnforfar/xnode-tpm-attest <name>`
      # produces a systemd-nspawn container that runs attest.sh once at
      # startup and once an hour, with output captured by the journal.
      nixosConfigurations.container = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        specialArgs = { inherit self; };
        modules = [
          xnode-manager.nixosModules.container
          {
            services.xnode-container.xnode-config = {
              host-platform = ./xnode-config/host-platform;
              state-version = ./xnode-config/state-version;
              hostname      = ./xnode-config/hostname;
            };
            # PIPELINE-LESSONS #6: dhcpcd doesn't auto-start in xnode-manager
            # containers; force it so the container registers its hostname
            # with the host's dnsmasq.
            networking.useDHCP = true;
            networking.dhcpcd.enable = true;
            systemd.services.dhcpcd.wantedBy = [ "multi-user.target" ];
            systemd.services.dhcpcd.enable = true;
          }
          ./nix/module.nix
        ];
      };
    };
}
