{ config, lib, pkgs, self, ... }:
let
  attestScript = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
in
{
  # Tools available inside the container for ad-hoc debugging.
  environment.systemPackages = with pkgs; [
    tpm2-tools openssl xxd attestScript
  ];

  # systemd oneshot: runs attest.sh, output goes to journal.
  # Retrievable via `om app logs xnode-tpm-attest`.
  systemd.services.xnode-tpm-attest = {
    description = "xnode-tpm-attest — TPM2 remote-attestation self-test";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${attestScript}/bin/xnode-tpm-attest";
      StandardOutput = "journal";
      StandardError = "journal";
      # Best-effort: try to access TPM if the host nspawn config bind-mounts it.
      # If not bind-mounted, attest.sh detects "no TPM device" and exits cleanly
      # with a useful diagnostic message rather than crashing.
      DeviceAllow = [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
      User = "root";
    };
  };

  # Re-run hourly so `om app logs` always has a recent attestation.
  systemd.timers.xnode-tpm-attest = {
    description = "xnode-tpm-attest hourly re-run";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "30s";
      OnUnitActiveSec = "1h";
      Unit = "xnode-tpm-attest.service";
    };
  };
}
