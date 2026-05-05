# TPM Manufacturer CA Bundle

Trust roots for verifying EK certificates from various TPM2 vendors.
The application loads these at runtime; **no network access** is needed
for chain validation once the bundle is shipped.

## Bundled

| File | Vendor | Source | Status |
|---|---|---|---|
| `intel-ondieca-root.cer` | Intel On-Die CA Root | `tsci.intel.com/content/OnDieCA/certs/` | ✓ |

## Known gaps (TODO)

| Vendor | Source | Notes |
|---|---|---|
| Intel On-Die CA Intermediates (per-platform) | Per-platform (Meteor Lake, Arrow Lake, Lunar Lake, …) | Not publicly downloadable; ships via Intel firmware tooling. Without the intermediate, only the leaf-issuer DN can be verified — partial trust. |
| AMD fTPM Root + Intermediate | AIA-walk from a real AMD-fTPM EK cert | URL moves between AMD security advisories. Resolve when the first AMD node enrolls. |
| Infineon SLB 967x | https://pki.infineon.com/ | Required for Own1 variants with discrete Infineon TPM. |
| Nuvoton NPCT75x | https://www.nuvoton.com/security/security-policy/ | Required for Own1 variants with discrete Nuvoton TPM. |
| STMicro ST33TP* | https://sw-center.st.com/ | Required for Own1 variants with discrete STMicro TPM. |

## Verification policy

`scripts/attest.sh` does best-effort chain validation:

1. If the EK's issuer DN matches a bundled root's subject DN: verify the chain.
2. If the EK's issuer DN matches a known intermediate but the intermediate
   isn't bundled: log a warning, treat as "partial trust" (leaf-issuer is a
   well-known TPM CA name).
3. If neither: reject the chain.

The attestation log is explicit about which level of trust applied.
