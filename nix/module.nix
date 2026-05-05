{ config, lib, pkgs, ... }:
let
  attestScript = pkgs.writeShellApplication {
    name = "xnode-tpm-attest";
    runtimeInputs = with pkgs; [
      tpm2-tools openssl coreutils gnugrep gnused gawk util-linux xxd bash
    ];
    text = builtins.readFile ../scripts/attest.sh;
  };
in
{
  environment.systemPackages = with pkgs; [
    tpm2-tools openssl xxd attestScript
  ];

  systemd.services.xnode-tpm-attest = {
    description = "xnode-tpm-attest — TPM2 remote-attestation self-test";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${attestScript}/bin/xnode-tpm-attest";
      StandardOutput = "journal";
      StandardError = "journal";
      DeviceAllow = [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
      User = "root";
    };
  };

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
