# TPM Manufacturer CA Bundle

Trust roots for verifying EK certificates from various TPM2 vendors.
Loaded at runtime; no network access needed for chain validation once
shipped.

## Bundled (publicly fetchable, committed to repo)

| File | Vendor | Status | Source |
|---|---|---|---|
| `intel-ondieca-root.cer` | Intel On-Die CA Root | tested with Intel PTT EK certs | `tsci.intel.com/content/OnDieCA/certs/` |
| `infineon-rsa-root.crt` | Infineon OPTIGA RSA Root CA | bundled, not yet verified on hardware | `pki.infineon.com/OptigaRsaRootCA/` |
| `infineon-rsa-mfr-ca001.crt` | Infineon OPTIGA RSA Manufacturing CA 001 | bundled, not yet verified on hardware | `pki.infineon.com/OptigaRsaMfrCA001/` |
| `infineon-ecc-root.crt` | Infineon OPTIGA ECC Root CA | bundled, not yet verified on hardware | `pki.infineon.com/OptigaEccRootCA/` |
| `infineon-ecc-mfr-ca001.crt` | Infineon OPTIGA ECC Manufacturing CA 001 | bundled, not yet verified on hardware | `pki.infineon.com/OptigaEccMfrCA001/` |

## Known gaps

| Vendor | Reason | Resolution path |
|---|---|---|
| **Intel On-Die CA intermediates** | Per-platform (Meteor Lake / Arrow Lake / Lunar Lake / …); not publicly downloadable from `tsci.intel.com`. Without the intermediate, only the leaf-issuer DN can be verified — partial trust. | Extract via Intel firmware tooling, or AIA-walk from a known-good EK cert chain. |
| **AMD fTPM Root + Intermediate** | AMD ships fTPM EK roots out-of-band; URL moves between AMD security advisories. | AIA-walk from a real AMD-fTPM EK cert when first AMD node enrols. |
| **Nuvoton NPCT75x** | `developer.nuvoton.com` not reachable from build host; the security policy page links to a closed area. | Source from a real Nuvoton TPM device's EK chain when available. |
| **STMicro ST33TP*** | `sw-center.st.com` endpoints 404 the canonical filenames. | Source from a real STMicro TPM device's EK chain when available. |

## Verification policy (what the script does at runtime)

1. **Intel** — full chain check against `intel-ondieca-root.cer`. If the
   intermediate isn't bundled, falls back to issuer-DN match (`partial trust`).
2. **Infineon** — full chain check against bundled root + manufacturing CA;
   tries RSA chain first, then ECC. Marked `EXPERIMENTAL` (logic wired, not
   verified on real Infineon TPMs yet).
3. **AMD / Nuvoton / STMicro** — vendor detected, chain marked
   `bundle-not-yet-shipped` and skipped. Script continues with the rest of
   the protocol; the first operator to run on these vendors gets useful
   telemetry from steps 1, 3, 4, 5, 6, 7 even without a chain check.
4. **vTPMs (Microsoft / Google / SwTPM)** — chain validation skipped;
   trust class reported as `cloud-attested`, not `silicon-attested`.

## Refreshing the bundle

```bash
# Intel root
curl -fsSO https://tsci.intel.com/content/OnDieCA/certs/OnDie_CA_RootCA_Certificate.cer

# Infineon roots
curl -fsSO https://pki.infineon.com/OptigaRsaRootCA/OptigaRsaRootCA.crt
curl -fsSO https://pki.infineon.com/OptigaRsaMfrCA001/OptigaRsaMfrCA001.crt
curl -fsSO https://pki.infineon.com/OptigaEccRootCA/OptigaEccRootCA.crt
curl -fsSO https://pki.infineon.com/OptigaEccMfrCA001/OptigaEccMfrCA001.crt

# AMD / Nuvoton / STMicro: AIA-walk from a real EK cert; not scriptable.
```
