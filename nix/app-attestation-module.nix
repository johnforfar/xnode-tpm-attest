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

  # Heartbeat script — one binary per registered app so they don't race
  # on the TPM EK handle (each invocation is serialised under the systemd
  # timer; per-app units keep names + journal output discoverable).
  mkHeartbeatScript = appName: appCfg: pkgs.writeShellApplication {
    name = "xnode-attest-heartbeat-${appName}";
    runtimeInputs = [ attestRuntime ];
    text = ''
      set -u
      APP_NAME="${appName}"
      VERIFIER_URL="${appCfg.verifierUrl}"
      EXEC_PATH="${appCfg.execPath}"
      PCR="${toString appCfg.pcr}"
      EK_HANDLE="${appCfg.ekHandle}"

      export TPM2TOOLS_TCTI="''${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
      WORK=$(mktemp -d)
      trap 'rm -rf "$WORK"; tpm2 evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true' EXIT
      cd "$WORK"

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

  appSubmodule = lib.types.submodule {
    options = {
      service = lib.mkOption {
        type = lib.types.str;
        description = "systemd unit to gate. ExecStartPre extends the PCR with execPath's hash before this unit starts.";
      };
      execPath = lib.mkOption {
        type = lib.types.str;
        description = "Absolute path to the binary whose hash binds this app's identity.";
      };
      pcr = lib.mkOption {
        type = lib.types.int;
        default = 16;
        description = ''
          PCR index to extend. On Intel PTT only PCR 16 is reliably
          user-extendable (17-22 require locality 4 / DRTM). All apps on
          the same box typically share PCR 16; their hashes accumulate.
        '';
      };
      verifierUrl = lib.mkOption {
        type = lib.types.str;
        default = "https://attest.build.openmesh.cloud";
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
          If true, the gated unit fails to start when the initial pcr-extend
          fails. If false (default), the ExecStartPre is best-effort.
        '';
      };
    };
  };

in {
  options.services.xnode-app-attestation = {
    apps = lib.mkOption {
      type = lib.types.attrsOf appSubmodule;
      default = { };
      example = lib.literalExpression ''
        {
          own1-inference-llm = {
            service = "own1-inference-llm";
            execPath = "''${pkg}/bin/llama-server";
          };
          own1-inference-image = {
            service = "own1-inference-image";
            execPath = "''${pkg}/bin/sd-server";
          };
        }
      '';
      description = ''
        Per-app attestation registry. Each entry produces an ExecStartPre
        hook on the named systemd service (extends a PCR with the binary's
        hash before start) and a heartbeat timer that re-quotes the PCR set
        to the verifier on heartbeatInterval.
      '';
    };
  };

  # Config-block shape is fixed (keys = environment.systemPackages,
  # systemd.services, systemd.timers). Dynamic per-app expansion happens
  # inside each value. Putting `lib.mkMerge` at the top of `config = ...`
  # forces NixOS to enumerate cfg.apps during module-merge and that cycles
  # because cfg.apps lives inside the same config the merge produces.
  config = {
    environment.systemPackages =
      [ attestRuntime pcrExtendApp runAttestedApp ]
      ++ lib.mapAttrsToList mkHeartbeatScript cfg.apps;

    systemd.services = lib.mkMerge (
      lib.mapAttrsToList
        (appName: appCfg:
          let
            unit = "xnode-attest-heartbeat-${appName}";
            cmd = "${pcrExtendApp}/bin/pcr-extend-app ${toString appCfg.pcr} ${appCfg.execPath}";
          in {
            # Layer 2: PCR-extend the app's binary hash before the unit starts.
            # `-` prefix on non-fail-closed makes ExecStartPre best-effort.
            ${appCfg.service} = {
              serviceConfig.ExecStartPre = lib.mkBefore [
                (if appCfg.failClosed then cmd else "-${cmd}")
              ];
              serviceConfig.DeviceAllow = lib.mkAfter [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
            };

            # Layer 4: continuous attestation via per-app systemd unit.
            ${unit} = {
              description = "xnode-app-attestation heartbeat for ${appName}";
              after = [ "network.target" "${appCfg.service}.service" ];
              serviceConfig = {
                Type = "oneshot";
                ExecStart = "${mkHeartbeatScript appName appCfg}/bin/${unit}";
                StandardOutput = "journal";
                StandardError = "journal";
                DeviceAllow = [ "/dev/tpm0 rw" "/dev/tpmrm0 rw" ];
                User = "root";
              };
            };
          }
        )
        cfg.apps
    );

    systemd.timers = lib.mapAttrs'
      (appName: appCfg:
        lib.nameValuePair "xnode-attest-heartbeat-${appName}" {
          description = "xnode-app-attestation heartbeat schedule for ${appName}";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = "60s";
            OnUnitActiveSec = appCfg.heartbeatInterval;
            Unit = "xnode-attest-heartbeat-${appName}.service";
          };
        }
      )
      cfg.apps;
  };
}
