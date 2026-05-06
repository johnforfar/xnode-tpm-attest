#!/usr/bin/env bash
# pcr-extend-app.sh — extend a PCR with the SHA-256 of an app artifact.
#
# Used by an app's ExecStartPre (via the app-attestation NixOS module) or
# from run-attested-app.sh just before launching the workload.
#
# Usage:
#   pcr-extend-app.sh <pcr-index> <path-or-hex>
#
# - If the second arg is a path, sha256 of the file is extended into the PCR.
# - If the second arg is exactly 64 hex chars, that hex is extended directly
#   (lets you bind a closure-hash, manifest digest, or any other identifier).

set -eu
PCR="${1:?pcr index required}"
TARGET="${2:?path or hex required}"

if [ -f "$TARGET" ]; then
  HEX=$(sha256sum "$TARGET" | awk '{print $1}')
elif [ ${#TARGET} -eq 64 ] && printf '%s' "$TARGET" | grep -qE '^[0-9a-fA-F]{64}$'; then
  HEX="$TARGET"
else
  echo "ERROR: $TARGET is neither a readable file nor a 64-hex-char hash" >&2
  exit 2
fi

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"
tpm2 pcrextend "${PCR}:sha256=${HEX}"
echo "PCR ${PCR} extended with sha256:${HEX}"
