# hello-attested — minimal end-to-end attested execution demo

This example proves the full loop works:

```
operator                          node (prover)                 verifier
   │                                  │                            │
   │ POST /register-app               │                            │
   ├─────────────────────────────────────────────────────────────→│
   │                                  │                            │
   │                                  │ GET /golden/hello-attested │
   │                                  ├──────────────────────────→│
   │                                  │                            │
   │                                  │ tpm2 pcrextend 16:sha256=… │
   │                                  │ tpm2 quote ...             │
   │                                  │                            │
   │                                  │ POST /verify-quote          │
   │                                  ├──────────────────────────→│
   │                                  │ ← attestation receipt      │
   │                                  │                            │
   │                                  │ run task (echo + hash)     │
   │                                  │                            │
   │                                  │ POST /task-result          │
   │                                  ├──────────────────────────→│
   │                                  │ ← task-completion receipt  │
```

## Run it

Prereqs: a working TPM 2.0 (or `--emulator` for swtpm), `tpm2-tools`,
`openssl`, `python3`, `curl` on PATH. On Own1 with the `xnode-tpm-attest`
script ecosystem, all of these come from the Nix runtime.

### 1. Operator: register the app (one-time)

```sh
EXPECTED_CLOSURE=$(sha256sum /path/to/run-attested-app.sh | awk '{print $1}')
curl -fsS -H 'content-type: application/json' \
  -d "{
    \"app_name\": \"hello-attested\",
    \"version\": \"0.1.0\",
    \"closure_hash\": \"$EXPECTED_CLOSURE\",
    \"expected_pcrs\": {
      \"16\": \"<computed pcr 16 after extending with closure hash from a clean state>\"
    }
  }" \
  https://attest.build.openmesh.cloud/register-app
```

Note: PCR 16 is a *user-extendable* PCR. Its expected value depends on
its starting state (often all zeros at boot) and the chain of extends
applied. For Phase 1 demo, the operator can register without a PCR-16
expectation (or set it to the known post-extend value after a single
clean run); the verifier returns `attested` if PCRs match the
registered expectation.

### 2. Node: run the attested task

```sh
APP_NAME=hello-attested \
VERIFIER_URL=https://attest.build.openmesh.cloud \
TASK_INPUT="hello world" \
./scripts/run-attested-app.sh
```

This will:
1. Fetch golden values from the verifier
2. Extend PCR 16 with the SHA-256 of the orchestrator binary
3. Quote PCRs 0,4,7,9,11,16 with a fresh nonce
4. POST the quote bundle to `/verify-quote`
5. Run the trivial task: hash the input
6. POST the result to `/task-result`
7. Print receipt URLs

### 3. Anyone: read the receipts

```sh
curl https://attest.build.openmesh.cloud/receipt/<attestation-receipt-id>
curl https://attest.build.openmesh.cloud/receipt/<task-receipt-id>
```

The task receipt links input hash → output hash → attestation receipt →
PCR digest. End-to-end chain of custody.

## What this demo proves

- The verifier-prover protocol round-trips correctly
- Nonces are echoed back in quotes (anti-replay)
- PCR-extending the app's hash binds the app identity to the quote
- Task results are anchored to the prior attestation receipt

## What it does NOT yet prove

- Full AK signature verification on the server side (deferred to Phase 2)
- Sealed credentials gating app startup (Phase 2)
- Continuous re-attestation during long-running tasks (Phase 3)
- Multi-verifier federation / signature on receipts other than HMAC (Phase 3)
