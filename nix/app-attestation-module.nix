{ config, lib, pkgs, ... }:
let
  cfg = config.services.xnode-app-attestation;

  attestRuntime = pkgs.symlinkJoin {
    name = "xnode-app-attestation-runtime";
    paths = with pkgs; [ tpm2-tools openssl curl coreutils gnugrep gnused gawk util-linux bash ];
  };

  pcrExtendApp = pkgs.runCommand "pcr-extend-app" { } ''
    install -Dm755 ${../scripts/pcr-extend-app.sh} $out/bin/pcr-extend-app
  '';

  runAttestedApp = pkgs.runCommand "run-attested-app" { } ''
    install -Dm755 ${../scripts/run-attested-app.sh} $out/bin/run-attested-app
  '';

  heartbeatScript = pkgs.writeShellApplication {
    name = "xnode-attest-heartbeat";
    runtimeInputs = [ attestRuntime ];
    text = ''
      set -u
      APP_NAME="${cfg.appName}"
      VERIFIER_URL="${cfg.verifierUrl}"
      EXEC_PATH="${cfg.execPath}"
      PCR="${toString cfg.pcr}"
      EK_HANDLE="${cfg.ekHandle}"

      export TPM2TOOLS_TCTI="''${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
      WORK=$(mktemp -d)
      trap 'rm -rf "$WORK"; tpm2 evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true' EXIT
      cd "$WORK"

      # Compute current closure hash and re-extend PCR (idempotent each cycle)
      ACTUAL=$(sha256sum "$EXEC_PATH" | awk '{print $1}')

      tpm2 evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true
      tpm2 createek -c "$EK_HANDLE" -G rsa -u ek.pub
      tpm2 createak -C "$EK_HANDLE" -c ak.ctx -G rsa -g sha256 -s rsassa \
                    -u ak.pub -n ak.name -f pem >/dev/null
      tpm2 pcrextend "$PCR:sha256=$ACTUAL"

      NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
      tpm2 quote -c ak.ctx -l "sha256:0,4,7,9,11,$PCR" -q "$NONCE" \
                 -m quote.msg -s quote.sig -o pcrs.bin -g sha256 -f plain >/dev/null

      QUOTE_B64=$(base64 -w0 < quote.msg 2>/dev/null || base64 < quote.msg | tr -d '\n')
      SIG_B64=$(base64 -w0 < quote.sig 2>/dev/null || base64 < quote.sig | tr -d '\n')
      AK_PEM=$(awk 'BEGIN{ORS="\\n"}{print}' < ak.pub)

      # Read the live PCR values so the verifier can compare against
      # registered expected_pcrs and report drift. Without this the
      # mismatches list is always empty and "attested" only means "AK
      # signature valid" — not "boot stack matches the published build".
      LIVE_JSON=$(tpm2 pcrread "sha256:0,4,7,9,11,$PCR" 2>/dev/null \
        | grep -oE '[0-9]+\s*:\s*0x[0-9A-Fa-f]+' \
        | sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]*:[[:space:]]*0x([0-9A-Fa-f]+)[[:space:]]*$/  "\1": "\2"/' \
        | tr 'A-F' 'a-f' | paste -sd ',' -)
      LIVE_JSON="{''${LIVE_JSON}}"

      cat > req.json <<JSON
      {
        "app_name": "$APP_NAME",
        "client_nonce_hex": "$NONCE",
        "quote_msg_b64": "$QUOTE_B64",
        "quote_sig_b64": "$SIG_B64",
        "ak_pub_pem": "$AK_PEM",
        "live_pcrs": $LIVE_JSON
      }
      JSON

      RESP=$(curl -fsS -H 'content-type: application/json' \
              --data-binary @req.json "$VERIFIER_URL/heartbeat" || echo '{"error":"heartbeat post failed"}')
      printf '[xnode-attest-heartbeat] %s app=%s\n' "$(date -uIs)" "$APP_NAME"
      printf '%s\n' "$RESP"
    '';
  };

in {
  options.services.xnode-app-attestation = {
    enable = lib.mkEnableOption "xnode-app-attestation — bind app identity to a TPM PCR + heartbeat to verifier";

    appName = lib.mkOption {
      type = lib.types.str;
      example = "ollama";
      description = "Name registered with the verifier; must match /register-app on the verifier side.";
    };

    service = lib.mkOption {
      type = lib.types.str;
      example = "ollama";
      description = "systemd unit name to gate. ExecStartPre will hash execPath and extend the PCR before the unit starts.";
    };

    execPath = lib.mkOption {
      type = lib.types.str;
      example = "/run/current-system/sw/bin/ollama";
      description = "Absolute path to the binary whose hash binds this app. Hashed at every heartbeat.";
    };

    pcr = lib.mkOption {
      type = lib.types.int;
      default = 16;
      description = "PCR index (16-22 are user-extendable per TCG spec).";
    };

    verifierUrl = lib.mkOption {
      type = lib.types.str;
      default = "https://attest.build.openmesh.cloud";
      description = "Verifier service base URL.";
    };

    ekHandle = lib.mkOption {
      type = lib.types.str;
      default = "0x81010009";
      description = "TPM persistent handle to provision the EK at. Must be free.";
    };

    heartbeatInterval = lib.mkOption {
      type = lib.types.str;
      default = "5min";
      description = "Re-attestation cadence (systemd OnUnitActiveSec format).";
    };

    failClosed = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        If true, the gated unit will fail to start if the initial pcr-extend
        fails (no TPM, attestation cannot proceed). If false (default), the
        ExecStartPre is best-effort and the service still starts; only the
        heartbeat loop reports drift to the verifier.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ attestRuntime pcrExtendApp runAttestedApp heartbeatScript ];

    # Layer 2: ExecStartPre extends the PCR with the binary's hash before the unit starts.
    # `-` prefix on non-fail-closed makes the pre-step best-effort.
    systemd.services.${cfg.service} = {
      serviceConfig.ExecStartPre = lib.mkBefore [
        (
          let cmd = "${pcrExtendApp}/bin/pcr-extend-app ${toString cfg.pcr} ${cfg.execPath}";
          in if cfg.failClosed then cmd else "-${cmd}"
        )
      ];
      serviceConfig.DeviceAllow = lib.mkAfter [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
    };

    # Layer 4: continuous attestation via systemd timer.
    systemd.services.xnode-attest-heartbeat = {
      description = "xnode-app-attestation heartbeat for ${cfg.appName}";
      after = [ "network.target" config.systemd.services.${cfg.service}.name ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${heartbeatScript}/bin/xnode-attest-heartbeat";
        StandardOutput = "journal";
        StandardError = "journal";
        DeviceAllow = [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
        User = "root";
      };
    };

    systemd.timers.xnode-attest-heartbeat = {
      description = "xnode-app-attestation heartbeat schedule";
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnBootSec = "60s";
        OnUnitActiveSec = cfg.heartbeatInterval;
        Unit = "xnode-attest-heartbeat.service";
      };
    };
  };
}
