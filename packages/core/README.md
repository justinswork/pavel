# `@justinswork/pavel-core`

Framework-agnostic PAVEL logic: building the OpenID4VP/DCQL request (ARCHITECTURE.md
§5) and running the mdoc verification pipeline (§7). No Express or DOM coupling.

## Develop (TDD)

```bash
npm install
npm run test:watch    # red/green loop
npm test              # single run (CI)
npm run typecheck
```

The intended workflow: write a failing test that states the behavior, then make it
pass. `test/*.test.ts` is the executable spec.

## What's implemented vs. stubbed

Following the "pure logic first" plan, the deterministic, crypto-free surface is
real and fully tested today:

- **`buildAgeRequest` / `agePredicate`** (`request.ts`) — the §5 request, with the
  data-minimization invariant enforced *and asserted* (it can only ever ask for one
  `age_over_NN` claim; a test fails if DOB/name/etc. could leak in).
- **`normalizeProtocol`** (`protocol.ts`) — folds `openid4vp` / `org-iso-mdoc` (§14 #3).
- **`verifyPresentation`** (`pipeline.ts`) — the §7 pipeline's *control flow*:
  ordering, fail-closed, and outcome selection, tested against a fake backend.

The crypto itself is the seam **`MdocBackend`** (`backend.ts`). The real
implementation — wrapping whatever the §14 #1 spike picks — lands behind that
interface later; its tests use golden vectors (see `test/fixtures/README.md`).

## Design decisions the tests pin

The §7 outcome enum is intentionally coarse, so the pipeline maps several distinct
crypto failures onto `malformed` ("this credential is not authentic/valid as
presented"):

| §7 step that fails | Outcome |
|---|---|
| decode / wrong docType | `malformed` |
| issuer trust chain (step 2) | `untrusted_issuer` |
| issuer signature (step 3) | `malformed` |
| validity window (step 4) | `expired` |
| holder binding — deviceAuth (step 5) | `malformed` |
| freshness / origin (step 6) | `replay` |
| digest integrity (step 7) | `malformed` |
| predicate absent / false (step 8) | `predicate_unavailable` / `predicate_false` |

Ordering matters and is asserted: e.g. an untrusted **and** expired credential
reports `untrusted_issuer`, because the trust chain is checked first. If any of
these mappings should be finer-grained (e.g. a distinct `invalid_signature` or
`holder_binding_failed`), change the test first — that's the whole point of the
setup.

## Layout

```
core/
├─ src/
│  ├─ types.ts      # outcomes, request/response shapes, VerifyContext/Result
│  ├─ request.ts    # buildAgeRequest, agePredicate  [pure, done]
│  ├─ protocol.ts   # normalizeProtocol              [pure, done]
│  ├─ backend.ts    # MdocBackend interface           [the crypto seam]
│  ├─ pipeline.ts   # verifyPresentation              [control flow, done]
│  └─ index.ts
└─ test/
   ├─ request.test.ts
   ├─ protocol.test.ts
   ├─ pipeline.test.ts             # fake backend
   ├─ verify.integration.test.ts   # real backend, golden vectors (todo)
   └─ fixtures/                     # golden vectors (empty until pavel-authority exists)
```
