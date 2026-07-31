# Golden-vector fixtures

Pre-generated `DeviceResponse` presentations that exercise every verification
outcome (ARCHITECTURE.md §7, §13 tier 1). These drive `verify.integration.test.ts`
against the **real** CBOR/COSE backend — no fakes — and are where most correctness
confidence comes from.

## Status

Empty for now. Fixtures are produced by **pavel-authority** (the mock IACA +
issuer), which doesn't exist yet, and consumed by the real mdoc backend, which is
gated on the §14 #1 library spike. Until both land, `verify.integration.test.ts`
holds the scenario list as `it.todo`.

## Planned vectors

Each is a base64url `DeviceResponse` plus the `VerifyContext` (nonce, origin,
minAge) it should be checked against, and the expected outcome:

| File | Expected outcome |
|---|---|
| `valid.json` | `verified` |
| `tampered-issuerauth.json` | `malformed` |
| `flipped-value.json` | `malformed` (digest mismatch) |
| `expired.json` | `expired` |
| `wrong-origin.json` | `replay` |
| `stale-nonce.json` | `replay` |
| `untrusted-issuer.json` | `untrusted_issuer` |
| `predicate-false.json` | `predicate_false` |
| `predicate-absent.json` | `predicate_unavailable` |

## Shape (proposed)

```jsonc
{
  "vpToken": "<base64url DeviceResponse>",
  "context": { "nonce": "…", "expectedOrigin": "https://shop.example", "minAge": 21 },
  "expected": { "outcome": "verified", "predicate": "age_over_21" }
}
```

Generation must be **deterministic** (fixed keys, fixed `signed`/validity
timestamps, fixed salts) so vectors are stable across runs and reviewable in diffs.
