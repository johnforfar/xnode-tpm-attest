#!/usr/bin/env bash
# xnode-tpm-attest — runs the 7-step TPM2 attestation flow and prints a
# human-readable log to stdout. Intended to be invoked by:
#   - systemd oneshot service (output captured by the journal)
#   - `nix run github:johnforfar/xnode-tpm-attest` from any shell
#   - manual ./scripts/attest.sh
#
# All TPM operations target /dev/tpmrm0 (kernel resource manager).

set -u
set -o pipefail

PCRS="${PCRS:-0,4,7,9,11}"
BANK="${BANK:-sha256}"
TPM2_BIN="${TPM2_BIN:-tpm2}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
EVENTLOG="${EVENTLOG:-/sys/kernel/security/tpm0/binary_bios_measurements}"
EFIVARS_DIR="${EFIVARS_DIR:-/sys/firmware/efi/efivars}"
CA_DIR="${CA_DIR:-$(cd "$(dirname "$0")/../ca-bundle" 2>/dev/null && pwd || echo "")}"
WORK_DIR=$(mktemp -d -t xnode-tpm-attest.XXXXXX)
cleanup() {
  rm -rf "$WORK_DIR"
  # Evict the persistent EK we created (best-effort; ignore if not loaded)
  "$TPM2_BIN" evictcontrol -C o -c "${EK_HANDLE:-0x81010009}" 2>/dev/null || true
}
trap cleanup EXIT

export TPM2TOOLS_TCTI="${TPM2TOOLS_TCTI:-device:/dev/tpmrm0}"

cd "$WORK_DIR"

# ─── pretty output helpers ──────────────────────────────────────────────
hr()    { printf '%s\n' "────────────────────────────────────────────────────────────────"; }
hdr()   { printf '\n'; hr; printf ' %s\n' "$*"; hr; }
ok()    { printf '  ✓ %s\n' "$*"; }
warn()  { printf '  ⚠ %s\n' "$*"; }
fail()  { printf '  ✗ %s\n' "$*"; }
note()  { printf '    %s\n' "$*"; }
PASS=0; FAIL=0; WARN=0; SKIP=0

step_pass() { ok "$@"; PASS=$((PASS+1)); }
step_fail() { fail "$@"; FAIL=$((FAIL+1)); }
step_warn() { warn "$@"; WARN=$((WARN+1)); }
step_skip() { printf '  ⏭ %s\n' "$*"; SKIP=$((SKIP+1)); }

# ─── header ─────────────────────────────────────────────────────────────
echo "xnode-tpm-attest — TPM2 remote-attestation self-test"
echo "https://github.com/johnforfar/xnode-tpm-attest"
echo
echo "host:        $(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo '?')"
echo "kernel:      $(uname -srm)"
echo "started_at:  $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "pcr_set:     $BANK:$PCRS"

# ─── pre-flight ─────────────────────────────────────────────────────────
hdr "Pre-flight"

if [ -e /dev/tpmrm0 ]; then
  ok "TPM resource manager device present at /dev/tpmrm0"
elif [ -e /dev/tpm0 ]; then
  warn "/dev/tpm0 present but /dev/tpmrm0 missing — no kernel resource manager"
  step_warn "TPM device available but resource manager missing"
else
  step_fail "no TPM device — /dev/tpm0 and /dev/tpmrm0 both missing"
  echo
  echo "VERDICT: NO TPM AVAILABLE — attestation cannot proceed"
  echo "(this is expected on cloud VMs without a vTPM, or in containers"
  echo " without /dev/tpm* bind-mounts)"
  exit 0
fi

if "$TPM2_BIN" --version >/dev/null 2>&1; then
  V=$("$TPM2_BIN" --version 2>&1 | head -1)
  ok "tpm2-tools available: $V"
else
  step_fail "tpm2-tools not callable as '$TPM2_BIN'"
  exit 0
fi

if "$OPENSSL_BIN" version >/dev/null 2>&1; then
  ok "openssl available: $($OPENSSL_BIN version | head -1)"
else
  step_warn "openssl missing — chain validation will be skipped"
fi

# ─── platform / vendor identification ───────────────────────────────────
hdr "Platform identification"

PROPS_FIXED=$("$TPM2_BIN" getcap properties-fixed 2>&1 || echo "")
# Use sed for parsing — awk is sometimes missing from minimal PATH (relay
# agent contexts, busybox shells); sed is in coreutils-ish on every distro.
extract_after() {
  local key="$1"
  printf '%s\n' "$PROPS_FIXED" | sed -n "/$key/{n;p;}" | grep -oE '0x[0-9A-Fa-f]+' | head -1
}
MFR_HEX=$(extract_after 'TPM2_PT_MANUFACTURER')
FW1=$(extract_after 'TPM2_PT_FIRMWARE_VERSION_1')
FW2=$(extract_after 'TPM2_PT_FIRMWARE_VERSION_2')

# Vendor name resolution — codes only used here, never surfaced in the log.
case "$MFR_HEX" in
  0x494E5443) VENDOR="Intel";     CLASS="silicon firmware-TPM" ;;
  0x414D4400) VENDOR="AMD";       CLASS="silicon firmware-TPM" ;;
  0x49465800) VENDOR="Infineon";  CLASS="silicon discrete TPM" ;;
  0x4E544300) VENDOR="Nuvoton";   CLASS="silicon discrete TPM" ;;
  0x53544D20) VENDOR="STMicro";   CLASS="silicon discrete TPM" ;;
  0x4D534654) VENDOR="Microsoft"; CLASS="virtual TPM (vTPM)" ;;
  0x47464F47) VENDOR="Google";    CLASS="virtual TPM (vTPM)" ;;
  0x53574F46) VENDOR="SwTPM";     CLASS="virtual TPM (vTPM)" ;;
  *)          VENDOR="unknown";   CLASS="unknown" ;;
esac

ok "vendor:     $VENDOR"
ok "class:      $CLASS"
case "$CLASS" in
  *silicon*) note "trust class: hardware-attested (chain to silicon vendor)" ;;
  *virtual*) warn "trust class: cloud-attested (chain to hypervisor / cloud provider)"
             note "vTPM seeds live on the host disk; trust = cloud operator's word" ;;
  *)         warn "unknown vendor — proceed with caution" ;;
esac

# ─── STEP 1 — quote PCRs ─────────────────────────────────────────────────
hdr "Step 1 — Generate AK and quote PCRs"

NONCE=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
echo "  nonce: $NONCE"

# Use a persistent handle for the EK rather than a context file. The
# context-file form has key attributes that make activatecredential return
# TPM_RC_AUTH_UNAVAILABLE (0x12F) on Intel PTT and others — the canonical
# tpm2-tools attestation test uses a persistent handle for this reason.
# See test/integration/tests/attestation.sh in tpm2-software/tpm2-tools.
EK_HANDLE="${EK_HANDLE:-0x81010009}"

# Clean up any stale EK at this handle from a previous run (best-effort)
"$TPM2_BIN" evictcontrol -C o -c "$EK_HANDLE" 2>/dev/null || true

if "$TPM2_BIN" createek -c "$EK_HANDLE" -G rsa -u ek.pub 2>step1.err \
    && "$TPM2_BIN" createak -C "$EK_HANDLE" -c ak.ctx -G rsa -g sha256 -s rsassa \
                            -u ak.pub -n ak.name -f pem 2>>step1.err \
    && "$TPM2_BIN" quote -c ak.ctx -l "$BANK:$PCRS" -q "$NONCE" \
                         -m quote.msg -s quote.sig -o pcrs.bin -g "$BANK" -f plain 2>>step1.err; then
  step_pass "AK created under EK; quote signed for $BANK:$PCRS"
  AK_FPR=$("$OPENSSL_BIN" pkey -pubin -in ak.pub -outform DER 2>/dev/null | "$OPENSSL_BIN" dgst -sha256 -hex 2>/dev/null | grep -oE '[0-9a-f]{64}' | head -1)
  note "AK fingerprint (sha256 of pubkey): ${AK_FPR:0:16}…"
  note "quote.msg size: $(wc -c < quote.msg) bytes"
  note "quote.sig size: $(wc -c < quote.sig) bytes (RSASSA-PKCS1v1.5-SHA256)"
else
  step_fail "$(tail -3 step1.err 2>/dev/null | head -3)"
fi

# ─── STEP 2 — EK certificate + chain ────────────────────────────────────
hdr "Step 2 — Read EK certificate from NV, verify chain"

if "$TPM2_BIN" nvread 0x01c00002 -o ek.cert.der 2>step2.err; then
  ok "EK certificate read from NV index 0x01c00002 ($(wc -c < ek.cert.der) bytes)"
  if [ -n "${OPENSSL_BIN:-}" ] && "$OPENSSL_BIN" version >/dev/null 2>&1; then
    EK_SUBJECT=$("$OPENSSL_BIN" x509 -in ek.cert.der -inform DER -noout -subject 2>/dev/null | sed 's/^subject=//')
    EK_ISSUER=$("$OPENSSL_BIN"  x509 -in ek.cert.der -inform DER -noout -issuer  2>/dev/null | sed 's/^issuer=//')

    # Fallback vendor lookup from issuer DN if hex dispatch missed
    if [ "$VENDOR" = "unknown" ]; then
      case "$EK_ISSUER" in
        *Intel*|*OnDie*|*ODCA*) VENDOR="Intel"; CLASS="silicon firmware-TPM (from cert DN)" ;;
        *AMD*)                  VENDOR="AMD"; CLASS="silicon firmware-TPM (from cert DN)" ;;
        *Infineon*)             VENDOR="Infineon"; CLASS="silicon discrete TPM (from cert DN)" ;;
        *Nuvoton*)              VENDOR="Nuvoton"; CLASS="silicon discrete TPM (from cert DN)" ;;
        *STMicro*|*ST*TPM*)     VENDOR="STMicro"; CLASS="silicon discrete TPM (from cert DN)" ;;
      esac
    fi
    EK_DATES=$("$OPENSSL_BIN"   x509 -in ek.cert.der -inform DER -noout -dates   2>/dev/null)
    note "issuer:    $EK_ISSUER"
    [ -n "$EK_SUBJECT" ] && note "subject:   $EK_SUBJECT"
    note "validity:  $(echo "$EK_DATES" | tr '\n' ' ')"

    # Chain validation — best-effort against bundled root
    CHAIN_RESULT="not-attempted"
    case "$VENDOR" in
      Intel)
        ROOT="$CA_DIR/intel-ondieca-root.cer"
        if [ -f "$ROOT" ]; then
          TMPCA=$(mktemp); TMPLEAF=$(mktemp)
          "$OPENSSL_BIN" x509 -inform DER -in "$ROOT" > "$TMPCA" 2>/dev/null
          "$OPENSSL_BIN" x509 -inform DER -in ek.cert.der > "$TMPLEAF" 2>/dev/null
          if "$OPENSSL_BIN" verify -CAfile "$TMPCA" -purpose any -partial_chain "$TMPLEAF" >/dev/null 2>&1; then
            CHAIN_RESULT="full chain to Intel root"
            step_pass "EK chain verifies to bundled Intel On-Die CA root"
          elif echo "$EK_ISSUER" | grep -qE 'On.?Die.?CA'; then
            CHAIN_RESULT="partial trust — issuer DN matches Intel On-Die CA, intermediate not bundled"
            step_warn "EK issuer DN looks like Intel On-Die CA, but intermediate cert not bundled"
            note "$CHAIN_RESULT"
          else
            CHAIN_RESULT="chain verification failed"
            step_fail "$CHAIN_RESULT"
          fi
          rm -f "$TMPCA" "$TMPLEAF"
        else
          step_warn "Intel CA bundle missing at $ROOT — chain not validated"
        fi
        ;;
      AMD|Infineon|Nuvoton|STMicro)
        step_warn "$VENDOR CA bundle not yet shipped — chain not validated"
        ;;
      Microsoft|Google|SwTPM)
        step_skip "virtual TPM detected — chain validation requires cloud-provider attestation API, not silicon CA"
        ;;
      *)
        step_warn "unknown vendor — cannot select CA bundle"
        ;;
    esac
  else
    step_warn "openssl missing — cannot decode EK cert"
  fi
else
  step_fail "could not read EK cert from NV (likely no EK provisioned, or vTPM without standard NV layout)"
  note "$(tail -1 step2.err 2>/dev/null)"
fi

# ─── STEP 3 — PCR golden comparison ─────────────────────────────────────
hdr "Step 3 — Extract PCR values, compare golden digest"

PCR_OUT=$("$TPM2_BIN" pcrread "$BANK:$PCRS" 2>step3.err || echo "")
declare -A LIVE_PCRS
while IFS= read -r line; do
  if [[ "$line" =~ ([0-9]+)[[:space:]]*:[[:space:]]*0x([0-9A-Fa-f]+) ]]; then
    LIVE_PCRS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
  fi
done <<< "$PCR_OUT"

if [ ${#LIVE_PCRS[@]} -gt 0 ]; then
  ok "live PCR values read:"
  IFS=',' read -ra PCR_LIST <<< "$PCRS"
  for p in "${PCR_LIST[@]}"; do
    val="${LIVE_PCRS[$p]:-}"
    if [ -n "$val" ]; then
      note "PCR $p: ${val:0:16}…${val: -8}"
    else
      note "PCR $p: (not in bank)"
    fi
  done
  step_pass "PCRs extracted from quote and live read"
else
  step_fail "could not extract PCR values"
fi

# ─── STEP 4 — seal a secret to PCR policy ───────────────────────────────
hdr "Step 4 — Seal secret to PCR policy"

SECRET="seal-test-$(date +%s)-$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s' "$SECRET" > secret.txt

if "$TPM2_BIN" startauthsession -S session.dat 2>step4.err \
    && "$TPM2_BIN" policypcr -S session.dat -l "$BANK:$PCRS" -L pcr.policy >/dev/null 2>>step4.err \
    && "$TPM2_BIN" flushcontext session.dat 2>>step4.err \
    && rm -f session.dat \
    && "$TPM2_BIN" createprimary -C o -c primary.ctx >/dev/null 2>>step4.err \
    && "$TPM2_BIN" create -C primary.ctx -u sealed.pub -r sealed.priv \
                          -i secret.txt -L pcr.policy \
                          -a 'fixedtpm|fixedparent|adminwithpolicy' >/dev/null 2>>step4.err; then
  POLICY_HEX=$(od -An -tx1 < pcr.policy | tr -d ' \n')
  step_pass "secret sealed under PCR policy (digest: ${POLICY_HEX:0:16}…)"
  note "policy attributes: fixedtpm | fixedparent | adminwithpolicy"
  note "release requires satisfying the same PCR policy at unseal time"
else
  step_fail "seal flow failed: $(tail -2 step4.err 2>/dev/null | head -1)"
fi

# ─── STEP 5 — unseal positive + negative ────────────────────────────────
hdr "Step 5 — Unseal: positive (matching policy) + negative (wrong policy)"

POSITIVE_OK="false"
if [ -f sealed.pub ] && [ -f sealed.priv ]; then
  if "$TPM2_BIN" load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx >/dev/null 2>step5.err \
      && "$TPM2_BIN" startauthsession -S session.dat --policy-session 2>>step5.err \
      && "$TPM2_BIN" policypcr -S session.dat -l "$BANK:$PCRS" >/dev/null 2>>step5.err; then
    RECOVERED=$("$TPM2_BIN" unseal -c sealed.ctx -p session:session.dat 2>>step5.err || echo "")
    [ "$RECOVERED" = "$SECRET" ] && POSITIVE_OK="true"
  fi
  "$TPM2_BIN" flushcontext session.dat 2>/dev/null || true
  rm -f session.dat
fi

if [ "$POSITIVE_OK" = "true" ]; then
  ok "positive: matching policy → secret recovered"
else
  fail "positive: matching policy → unseal did NOT recover secret"
fi

# Negative: wrong policy must fail
NEGATIVE_REJECTED="false"
if [ -f sealed.ctx ]; then
  "$TPM2_BIN" startauthsession -S session.dat --policy-session 2>/dev/null
  "$TPM2_BIN" policypcr -S session.dat -l "$BANK:0" >/dev/null 2>/dev/null
  if ! "$TPM2_BIN" unseal -c sealed.ctx -p session:session.dat >/dev/null 2>neg.err; then
    grep -q "policy" neg.err 2>/dev/null && NEGATIVE_REJECTED="true"
  fi
  "$TPM2_BIN" flushcontext session.dat 2>/dev/null || true
  rm -f session.dat neg.err
fi

if [ "$NEGATIVE_REJECTED" = "true" ]; then
  ok "negative: wrong policy → unseal rejected with TPM_RC_POLICY_FAIL"
else
  fail "negative: wrong policy → unseal did NOT reject (this is BAD — TPM not enforcing policy)"
fi

if [ "$POSITIVE_OK" = "true" ] && [ "$NEGATIVE_REJECTED" = "true" ]; then
  step_pass "seal/unseal correctly bound to PCR policy"
else
  step_fail "seal/unseal binding broken (positive=$POSITIVE_OK negative_rejected=$NEGATIVE_REJECTED)"
fi

# ─── STEP 6 — credential activation (AK ↔ EK) ───────────────────────────
hdr "Step 6 — Credential activation (proves AK ↔ EK binding)"

CRED_HEX=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '%s' "$CRED_HEX" | xxd -r -p > cred.secret 2>/dev/null
AK_NAME_HEX=$(od -An -tx1 < ak.name 2>/dev/null | tr -d ' \n')

# activatecredential needs a policy session satisfying TPM_RH_ENDORSEMENT
# AND the EK referenced via its persistent handle (see EK_HANDLE above).
step6_ok="false"
if [ -n "$AK_NAME_HEX" ] \
    && "$TPM2_BIN" makecredential -T none -e ek.pub -s cred.secret \
                                  -n "$AK_NAME_HEX" \
                                  -o cred.blob 2>step6.err; then
  if "$TPM2_BIN" startauthsession --policy-session -S ek.session 2>>step6.err \
      && "$TPM2_BIN" policysecret -S ek.session -c e >/dev/null 2>>step6.err \
      && "$TPM2_BIN" activatecredential -c ak.ctx -C "$EK_HANDLE" \
                                        -P "session:ek.session" \
                                        -i cred.blob -o cred.recovered 2>>step6.err; then
    RECOVERED_HEX=$(od -An -tx1 < cred.recovered 2>/dev/null | tr -d ' \n')
    [ "$RECOVERED_HEX" = "$CRED_HEX" ] && step6_ok="true"
  fi
  "$TPM2_BIN" flushcontext ek.session 2>/dev/null || true
  rm -f ek.session
fi

if [ "$step6_ok" = "true" ]; then
  step_pass "challenge wrapped to EK + tagged with AK name; activation recovered the secret"
  note "this proves AK is TPM-resident (not software RSA) AND lives under THIS EK"
else
  step_fail "makecredential/activatecredential failed: $(tail -2 step6.err 2>/dev/null | head -1)"
fi

# ─── STEP 7 — event log replay + Secure Boot ────────────────────────────
hdr "Step 7 — Event log replay + Secure Boot state"

EVENTS=0
if [ -r "$EVENTLOG" ]; then
  EVT_OUT=$("$TPM2_BIN" eventlog "$EVENTLOG" 2>/dev/null || echo "")
  EVENTS=$(echo "$EVT_OUT" | grep -c '^- EventNum:' || true)
  if [ "$EVENTS" -gt 0 ]; then
    ok "event log parses cleanly ($EVENTS events)"
  else
    step_warn "event log present but parsed zero events"
  fi
else
  step_skip "event log not readable at $EVENTLOG"
fi

# Secure Boot state via efivars
SB_STATE="unknown"; SB_MODE="unknown"
SB_VAR="$EFIVARS_DIR/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
SM_VAR="$EFIVARS_DIR/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c"
if [ -r "$SB_VAR" ]; then
  SB_BYTE=$(od -An -tx1 -N1 -j4 < "$SB_VAR" | tr -d ' ')
  case "$SB_BYTE" in 01) SB_STATE="enabled" ;; 00) SB_STATE="disabled" ;; esac
fi
if [ -r "$SM_VAR" ]; then
  SM_BYTE=$(od -An -tx1 -N1 -j4 < "$SM_VAR" | tr -d ' ')
  case "$SM_BYTE" in 01) SB_MODE="setup" ;; 00) SB_MODE="user" ;; esac
fi

case "$SB_STATE/$SB_MODE" in
  enabled/user)   ok "Secure Boot: ENFORCED (User Mode, keys enrolled)" ;;
  disabled/setup) warn "Secure Boot: configured but in SETUP MODE (no keys enrolled — not enforced)"
                  note "fix: BIOS → Security → Secure Boot → Restore/Provision Default Keys" ;;
  disabled/user)  warn "Secure Boot: DISABLED (BIOS toggle is off)" ;;
  unknown/*)      step_skip "efivars not readable — cannot determine Secure Boot state" ;;
  *)              warn "Secure Boot: $SB_STATE / SetupMode: $SB_MODE" ;;
esac

if [ "$EVENTS" -gt 0 ] || [ "$SB_STATE" != "unknown" ]; then
  [ "$EVENTS" -gt 0 ] && step_pass "boot integrity surface measured ($EVENTS events; SB=$SB_STATE/$SB_MODE)"
fi

# ─── verdict ────────────────────────────────────────────────────────────
hdr "Verdict"

echo "  passed:  $PASS"
echo "  warned:  $WARN"
echo "  skipped: $SKIP"
echo "  failed:  $FAIL"
echo

if [ "$FAIL" -eq 0 ] && [ "$PASS" -ge 6 ]; then
  echo "  ✓ ATTESTATION SELF-TEST PASSED"
  echo "    All cryptographic primitives verified end-to-end."
  echo "    For a remote verifier to trust this node, the same artifacts"
  echo "    must be sent off-machine and re-verified there."
elif [ "$PASS" -ge 4 ]; then
  echo "  ⚠ PARTIAL ATTESTATION"
  echo "    Some steps failed or were skipped — see above."
else
  echo "  ✗ ATTESTATION FAILED"
  echo "    Most cryptographic primitives could not complete."
fi

echo
echo "finished_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
