# Golden-vector fixtures

Pre-generated `DeviceResponse` presentations that exercise every verification
outcome (ARCHITECTURE.md §7, §13 tier 1). These drive `verify.integration.test.ts`
against the **real** CBOR/COSE backend — no fakes — and are where most correctness
confidence comes from.

## Vectors

Each `<name>.json` is a base64url `DeviceResponse` plus the `VerifyContext` it is
checked against and the expected outcome. All are verified against the single
shared `trust-anchor.pem` (the "good" mock IACA); the untrusted vector fails
because its token was minted under a *different* IACA not in that anchor set.

| File | Expected outcome |
|---|---|
| `valid.json` | `verified` |
| `tampered-issuerauth.json` | `malformed` (corrupted issuerAuth signature) |
| `flipped-value.json` | `malformed` (disclosed value's digest no longer matches) |
| `expired.json` | `expired` |
| `wrong-origin.json` | `replay` (bound to a different origin) |
| `stale-nonce.json` | `replay` (bound to a different nonce) |
| `untrusted-issuer.json` | `untrusted_issuer` |
| `predicate-false.json` | `predicate_false` |
| `predicate-absent.json` | `predicate_unavailable` |

## Shape

```jsonc
{
  "vpToken": "<base64url DeviceResponse>",
  "context": { "nonce": "…", "expectedOrigin": "https://shop.example", "minAge": 21 },
  "expected": { "outcome": "verified", "predicate": "age_over_21" }
}
```

## Regenerating

```bash
pnpm --filter @justinswork/pavel-mock-authority gen:fixtures
```

The generator mints each vector with `pavel-mock-authority`, applies the two
byte-level mutations (`tampered-issuerauth`, `flipped-value`), and **self-checks
every fixture against the real backend before writing** — so a committed fixture
is guaranteed to produce its stated outcome.

These are **frozen** committed vectors, not byte-reproducible ones: real mdoc
crypto (randomized WebCrypto ECDSA certificate signing, per-element mdoc salts)
makes each run produce different bytes. Regeneration therefore replaces the
fixtures wholesale; the *outcomes* are stable, the bytes are not. Certificates and
the "valid" credential are minted with a ~100-year validity so the frozen vectors
don't lapse over time (the `expired` vector uses a deliberately past window).
