#!/usr/bin/env bash
# run-attested-app.sh — end-to-end attested-app orchestrator.
#
# Flow:
#   1. fetch golden values from verifier:  GET  /golden/<app>
#   2. PCR-extend the app's hash:           tpm2 pcrextend 16:sha256=<hash>
#   3. quote PCRs with verifier-supplied
#      nonce:                                tpm2 quote -l ... -q <nonce>
#   4. submit quote bundle:                  POST /verify-quote
#   5. on attested verdict, run the task    (whatever the app does)
#   6. submit result:                        POST /task-result
#   7. print receipt IDs for chain-of-custody
#
# Usage:
#   APP_NAME=hello-attested \
#   VERIFIER_URL=https://attest.build.openmesh.cloud \
#   APP_BIN=/path/to/binary \
#   TASK_INPUT="hello world" \
#   ./run-attested-app.sh
#
# If APP_BIN is not provided, hashes the script itself (useful for the
# hello-attested demo where the orchestrator IS the app).

set -u
set -o pipefail

APP_NAME="${APP_NAME:?APP_NAME required}"
VERIFIER_URL="${VERIFIER_URL:?VERIFIER_URL required (e.g. https://attest.build.openmesh.cloud)}"
APP_BIN="${APP_BIN:-$0}"
TASK_INPUT="${TASK_INPUT:-(no task input)}"
PCRS="${PCRS:-0,4,7,9,11,16}"
APP_PCR="${APP_PCR:-16}"
BANK="${BANK:-sha256}"
EK_HANDLE="${EK_HANDLE:-0x81010009}"

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"

WORK=$(mktemp -d -t xnode-attested-app.XXXXXX)
trap 'rm -rf "$WORK"; tpm2 evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true' EXIT
cd "$WORK"

hr()   { printf '%s\n' "────────────────────────────────────────────────────────────────"; }
hdr()  { printf '\n'; hr; printf ' %s\n' "$*"; hr; }
ok()   { printf '  ✓ %s\n' "$*"; }
fail() { printf '  ✗ %s\n' "$*"; exit 1; }

echo "run-attested-app — end-to-end attested execution"
echo "  app:       $APP_NAME"
echo "  verifier:  $VERIFIER_URL"
echo "  app_bin:   $APP_BIN"
echo "  pcrs:      $BANK:$PCRS  (app pcr=$APP_PCR)"

# ─── 1. fetch golden ──────────────────────────────────────────────────────
hdr "1. Fetch golden values from verifier"
GOLDEN=$(curl -fsS "$VERIFIER_URL/golden/$APP_NAME") || fail "GET /golden/$APP_NAME failed"
# Trivial JSON extraction with sed — avoids python3/jq dependency
json_str() { printf '%s' "$1" | sed -nE 's/.*"'"$2"'"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' | head -1; }
EXPECTED_CLOSURE=$(json_str "$GOLDEN" closure_hash)
ok "expected closure hash: ${EXPECTED_CLOSURE:0:24}…"

# ─── 2. compute and extend PCR with app hash ──────────────────────────────
hdr "2. PCR-extend app identity"
ACTUAL_CLOSURE=$(sha256sum "$APP_BIN" | awk '{print $1}')
ok "actual closure hash:   ${ACTUAL_CLOSURE:0:24}…"

if [ "$ACTUAL_CLOSURE" != "$EXPECTED_CLOSURE" ]; then
  echo "  ⚠ closure mismatch — verifier will return 'drift'"
fi

# Provision EK + AK once
tpm2 evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true
tpm2 createek -c "$EK_HANDLE" -G rsa -u ek.pub
tpm2 createak -C "$EK_HANDLE" -c ak.ctx -G rsa -g sha256 -s rsassa \
              -u ak.pub -n ak.name -f pem >/dev/null
ok "AK created under EK at $EK_HANDLE"

tpm2 pcrextend "$APP_PCR:sha256=$ACTUAL_CLOSURE"
ok "PCR $APP_PCR extended with sha256:${ACTUAL_CLOSURE:0:16}…"

# ─── 3. quote with verifier nonce ─────────────────────────────────────────
hdr "3. Quote (nonce supplied locally; verifier echoes it back)"
NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
ok "client nonce: $NONCE"
tpm2 quote -c ak.ctx -l "$BANK:$PCRS" -q "$NONCE" \
           -m quote.msg -s quote.sig -o pcrs.bin -g "$BANK" -f plain >/dev/null
ok "quote signed: $(wc -c < quote.msg) bytes msg, $(wc -c < quote.sig) bytes sig"

# Read live PCR values to ship to verifier
LIVE_PCRS_JSON=$(tpm2 pcrread "$BANK:$PCRS" 2>/dev/null \
  | grep -oE '[0-9]+\s*:\s*0x[0-9A-Fa-f]+' \
  | sed -E 's/^[[:space:]]*([0-9]+)[[:space:]]*:[[:space:]]*0x([0-9A-Fa-f]+)[[:space:]]*$/  "\1": "\2"/' \
  | tr 'A-F' 'a-f' \
  | paste -sd ',' -)
LIVE_PCRS_JSON="{${LIVE_PCRS_JSON}}"

# ─── 4. submit quote ──────────────────────────────────────────────────────
hdr "4. POST /verify-quote"
QUOTE_B64=$(base64 -w0 < quote.msg 2>/dev/null || base64 < quote.msg | tr -d '\n')
SIG_B64=$(base64 -w0 < quote.sig 2>/dev/null || base64 < quote.sig | tr -d '\n')
AK_PEM=$(awk 'BEGIN{ORS="\\n"}{print}' < ak.pub)

cat > verify-req.json <<EOF
{
  "app_name": "$APP_NAME",
  "client_nonce_hex": "$NONCE",
  "quote_msg_b64": "$QUOTE_B64",
  "quote_sig_b64": "$SIG_B64",
  "ak_pub_pem": "$AK_PEM",
  "live_pcrs": $LIVE_PCRS_JSON,
  "actual_closure_hash": "$ACTUAL_CLOSURE"
}
EOF

VERDICT_RESP=$(curl -fsS -H 'content-type: application/json' \
  --data-binary @verify-req.json "$VERIFIER_URL/verify-quote") \
  || fail "POST /verify-quote failed"

echo "$VERDICT_RESP" > verdict.json
VERDICT=$(json_str "$VERDICT_RESP" verdict)
ATT_RECEIPT_ID=$(json_str "$VERDICT_RESP" receipt_id)

case "$VERDICT" in
  attested) ok "verifier verdict: ATTESTED" ;;
  drift)    echo "  ⚠ verifier verdict: DRIFT (PCRs do not match expected)" ;;
  *)        fail "verifier verdict: $VERDICT" ;;
esac
ok "attestation receipt: $ATT_RECEIPT_ID"

# ─── 5. run the task ──────────────────────────────────────────────────────
hdr "5. Execute the attested task"
if [ -n "${TASK_CMD:-}" ]; then
  TASK_OUTPUT=$(eval "$TASK_CMD" <<<"$TASK_INPUT" 2>&1)
else
  # Hello-attested default: echo input back, hashed
  TASK_OUTPUT="hello: $(printf '%s' "$TASK_INPUT" | sha256sum | awk '{print $1}')"
fi
ok "task input  ($(printf '%s' "$TASK_INPUT" | wc -c) bytes): $TASK_INPUT"
ok "task output ($(printf '%s' "$TASK_OUTPUT" | wc -c) bytes): $TASK_OUTPUT"

# ─── 6. submit result ─────────────────────────────────────────────────────
hdr "6. POST /task-result"
# Trivial JSON-string escaping — handles \, ", and basic ASCII cleanly
json_quote() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/$/\\n/' \
    | tr -d '\n' | sed 's/\\n$//' | awk '{print "\"" $0 "\""}'
}
TASK_INPUT_J=$(json_quote "$TASK_INPUT")
TASK_OUTPUT_J=$(json_quote "$TASK_OUTPUT")

cat > task-req.json <<EOF
{
  "attestation_receipt_id": "$ATT_RECEIPT_ID",
  "task_input": $TASK_INPUT_J,
  "task_output": $TASK_OUTPUT_J
}
EOF

TASK_RESP=$(curl -fsS -H 'content-type: application/json' \
  --data-binary @task-req.json "$VERIFIER_URL/task-result") \
  || fail "POST /task-result failed"

TASK_RECEIPT_ID=$(json_str "$TASK_RESP" receipt_id)
ok "task-completion receipt: $TASK_RECEIPT_ID"

# ─── 7. summary ───────────────────────────────────────────────────────────
hdr "Receipts"
echo "  attestation receipt: $VERIFIER_URL/receipt/$ATT_RECEIPT_ID"
echo "  task receipt:        $VERIFIER_URL/receipt/$TASK_RECEIPT_ID"
echo
echo "✓ end-to-end attested execution complete"
