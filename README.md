# xnode-tpm-attest

A self-contained TPM 2.0 remote-attestation tool for xnodes, Own1 nodes,
and any other Linux machine with a TPM. Runs the full seven-step
attestation flow, generates a human-readable HTML report, and serves it
on a local web URL.

Designed to be deployed two ways:

1. **As an xnode app** — `om app deploy --flake github:johnforfar/xnode-tpm-attest <name>` and the report appears at `https://<name>.<your-xnode-domain>/`
2. **Direct on a workstation / bare-metal node** — `nix run github:johnforfar/xnode-tpm-attest` (writes report to a local path; optional `--serve` flag starts a local web server)

The protocol is platform-agnostic: same code runs on bare-metal Beelinks
with firmware TPMs, on workstations with discrete TPMs, on cloud VMs
with virtualised TPMs, and on any future fleet member. The *output*
adapts: the EK certificate chain, the firmware version, the boot-state
PCR digests will all be different on each machine. The protocol's job
is to surface those differences in a way a verifier can act on.

## What it actually does

Runs the canonical seven-step TPM2 attestation flow:

1. **Quote PCRs.** Generate a fresh attestation key (AK) under the
   manufacturer's endorsement key (EK), sign a quote of selected PCRs
   (default: 0, 4, 7, 9, 11) with a verifier-supplied nonce.
2. **Verify TPM provenance.** Read the EK certificate from NV, decode
   it, identify the manufacturer from the certificate's SAN, select the
   matching CA bundle, run `openssl verify` against the bundled root.
3. **Compare PCR golden values.** Compute `sha256(concat(selected PCRs))`
   from the live PCR readings and confirm it equals the `pcrDigest`
   field inside the signed quote — proving the quote is for *these* PCR
   values, not stale or forged ones.
4. **Seal a secret to the PCR policy.** Build a policy digest from the
   live PCR values, then create a sealed object whose unseal
   authorisation requires that exact policy.
5. **Unseal on the same machine.** Open a policy session matching the
   committed policy and unseal — should succeed. Repeat with a
   deliberately wrong policy — should fail with a policy-check error.
6. **Bind AK to EK (credential activation).** Run a self-test of the
   `tpm2_makecredential` / `tpm2_activatecredential` pair: the verifier
   wraps a one-shot secret to the EK pubkey + AK name, the prover
   activates and recovers the secret. Proves the AK is TPM-resident
   (not a software RSA key) and that the AK and EK live in the same
   chip.
7. **Replay the boot event log.** Parse
   `/sys/kernel/security/tpm0/binary_bios_measurements`, replay each
   extend operation, confirm the replayed digest matches the live PCR
   value, and surface specific events of interest (Secure Boot variable,
   kernel/initrd hashes, UKI measurements).

Each step's pass/fail status, the supporting hex/text artifacts, and the
full quote bundle are written to a single HTML page and a parallel JSON
report.

## Why it exists

Most TPM2 attestation tutorials are a wall of `tpm2_*` invocations with
no sense of why they're there or what they prove. This tool is the
opposite: every command's purpose is annotated, every output cross-checked,
and the report tells you not just *what* the digest is but *whether* it
matches the expected boot-integrity story.

Particularly useful for:

- **Operators bringing up new hardware** — prove the TPM is present,
  enrolled, and producing valid quotes before relying on it for fleet
  membership.
- **Verifying boot-integrity changes** — flip Secure Boot, swap the
  kernel, and immediately see which PCRs moved and what the new
  golden-digest is.
- **Comparing platforms** — the same report layout for Intel, AMD,
  Infineon, and virtualised TPMs lets you see the trust differences
  directly.

## Output: what the report looks like

Each step in the report has:

- A traffic-light status (✓ pass / ✗ fail / ⚠ warning / ⏭ skipped)
- A one-line summary of what was checked
- The raw hex/text artifacts for inspection
- A "what this means" annotation explaining the implication

The full bundle (quote.msg, quote.sig, EK cert, AK pubkey, event log) is
also exposed as base64 download links for the verifier-side workflow.

## Quick start

### As an xnode app

```sh
om app deploy --flake github:johnforfar/xnode-tpm-attest xnode-tpm-attest --wait true
om app expose xnode-tpm-attest --port 80 --domain xnode-tpm-attest.<your-xnode-domain>
# report at https://xnode-tpm-attest.<your-xnode-domain>/
# refresh re-runs attestation (cached for 60s to avoid TPM load)
```

The app declares the bind-mounts it needs (`/dev/tpm0`, `/dev/tpmrm0`,
`/sys/kernel/security/tpm0`, `/sys/firmware/efi/efivars`) in its NixOS
module. If your `xnode-manager` build doesn't pass through container
device bind-mounts, the app boots and reports "TPM not visible from
container" — useful diagnostic, not a crash.

### As a workstation / bare-metal tool

```sh
nix run github:johnforfar/xnode-tpm-attest
# writes report to ./xnode-tpm-attest-report-<hostname>-<timestamp>/index.html
# add --serve to start a localhost:8080 web server
```

Requires root (or `CAP_SYS_RAWIO` + access to `/dev/tpmrm0`) because the
TPM resource manager device is owned by root by default.

## Trust model

This is an *attestation* tool, not a *security boundary*. The report it
generates is meant to be **consumed by a verifier elsewhere** — a Pythia
registry, a fleet operator, a peer node — that decides what to do with
the claims. The report includes everything a verifier needs to make
that decision independently: signed quote bundle, EK cert chain
artifacts, event log, raw PCR values.

What the tool **does not** do:

- Make trust decisions on behalf of the verifier (no "✓ this machine is
  trusted" verdict — only "✓ all attestation steps cryptographically
  consistent")
- Pin or persist anything to the network (the entire protocol is local
  + bundle-based)
- Replace the verifier — the verifier needs the same bundled CA roots
  and the same golden-PCR allowlist to make a real decision

## Configuration

Defaults are sensible; everything is override-able via flake options or
environment variables:

| Option | Default | Effect |
|---|---|---|
| `pcrs` | `0,4,7,9,11` | PCR set to quote |
| `bank` | `sha256` | PCR bank algorithm (rejects sha1) |
| `nonce_length` | `16` | bytes of verifier nonce |
| `secret_to_seal` | random 32 bytes | what step 4 seals |
| `ca_bundle_path` | `./ca-bundle/` | trust roots for chain validation |
| `port` | `80` (xnode) / `8080` (workstation) | HTTP listen |
| `cache_ttl_seconds` | `60` | min interval between TPM-touching runs |

## CA bundle: what's required to ship

The `ca-bundle/` directory holds trust roots for verifying EK certs from
each TPM vendor. The application loads these at runtime; **no network
access** is needed for chain validation once the bundle is shipped.

The bundle is built by `tools/bundle-tpm-roots.sh` (run once, results
committed). See [`ca-bundle/README.md`](./ca-bundle/README.md) for what's
currently bundled, what's still TODO, and how to refresh.

For now: the Intel On-Die CA root is bundled. Other vendors require
case-by-case sourcing — covered in the bundle README.

## Architecture

```
┌─ machine under attestation ─────────────────────────────────┐
│                                                              │
│  /dev/tpm0  /dev/tpmrm0   /sys/kernel/security/tpm0          │
│       ▲           ▲              ▲                            │
│       │           │              │                            │
│  ┌─── attest.sh ──────────────────────────────┐              │
│  │  step 1 → quote                            │              │
│  │  step 2 → read EK cert + verify chain      │              │
│  │  step 3 → compare PCR digest               │              │
│  │  step 4 → seal-to-policy                   │              │
│  │  step 5 → unseal (positive + negative)     │              │
│  │  step 6 → makecredential / activate        │              │
│  │  step 7 → event log replay                 │              │
│  └──────────────────────┬──────────────────────┘              │
│                         ▼                                     │
│      ./xnode-tpm-attest-report/index.html + report.json             │
│                         ▼                                     │
│                  nginx :80 (or python -m http.server)         │
│                                                                │
└──────────────────────┬───────────────────────────────────────┘
                       │  HTTPS
                       ▼
              browser / verifier / Pythia registry
```

Three layers, each ~100–300 lines:

- **`scripts/attest.sh`** — the protocol implementation. Pure bash +
  tpm2-tools + openssl. Reads from `/dev/tpmrm0`, writes report files.
- **`nix/module.nix`** — NixOS module that runs `attest.sh` as a
  systemd timer, bind-mounts the right device paths, wires nginx to
  serve the report.
- **`flake.nix`** — entry point for both `nix run` and `om app deploy`.
  Pins `tpm2-tools`, `openssl`, `nginx` versions.

## Comparison with safeboot.dev/attestation

The [Safe Boot project's attestation page](https://safeboot.dev/attestation/)
documents the same underlying protocol — this tool is one packaged
implementation with extra steps (sealing, event-log replay, JSON output,
web report). If you're learning the protocol, read Safe Boot first.
If you want a runnable artifact for an xnode/Own1 fleet, this is that.

## Status

- [x] Step 1 (quote) — verified live on Intel firmware-TPM
- [x] Step 2 (EK cert + chain) — verified; partial-trust chain check against bundled Intel root
- [x] Step 3 (PCR golden) — verified
- [x] Step 4 (seal) — verified
- [x] Step 5 (unseal positive + negative) — verified
- [x] Step 6 (activatecredential) — wired with policy session for the endorsement hierarchy
- [x] Step 7 (event log replay) — `tpm2_eventlog` parses cleanly; explicit Secure Boot check works
- [x] Workstation / direct-host mode — runs anywhere a Linux + TPM2 + Nix stack exists
- [ ] Multi-vendor CA bundle — Intel root only; other vendor roots pending
- [ ] xnode-app deployment — flake structure ready; container TPM-device bind-mounts depend on `xnode-manager` honouring `DeviceAllow=`

## Related

- Safe Boot's attestation reference: https://safeboot.dev/attestation/
- `tpm2-tools` upstream: https://github.com/tpm2-software/tpm2-tools
- TCG TPM 2.0 specification: https://trustedcomputinggroup.org/resource/tpm-library-specification/

## License

MIT.
