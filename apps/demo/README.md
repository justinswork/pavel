# PAVEL Demo Store (`pavel-demo`)

A minimal age-gated e-commerce store that serves as the **end-to-end testbed** for
PAVEL. Browse → add to cart → checkout; a cart containing an age-restricted item
forces the PAVEL verification ceremony before the order completes.

> **This uses a MOCK age-gate.** No real wallet, credential, or cryptography is
> involved. The mock mirrors the real contract from [`../../docs/ARCHITECTURE.md`](../../docs/ARCHITECTURE.md)
> so the real `@justinswork/pavel*` packages can drop in behind the same
> interface later. See [The swap point](#the-swap-point).

## Run

```bash
npm install
npm start        # or: npm run dev  (auto-restart on change)
```

Then open the printed URL (defaults to `http://localhost:3000`; set `PORT` to
change it). `ORIGIN` overrides the origin bound into the request/verify ceremony.

## What's real vs. mocked

| Real (production-shaped) | Mocked (stubbed for the testbed) |
|---|---|
| Server-minted single-use nonce, TTL, session binding | The wallet UI (a labelled in-page modal) |
| Origin / audience binding, replay rejection | The `vp_token` (plaintext JSON, not CBOR/COSE) |
| Session flag, session-fixation regeneration | Issuer trust (a string compare, not an IACA cert chain) |
| The `pavel()` + `requireAgeProof()` API surface (§8) | The credential signatures (no COSE_Sign1) |
| The verification **outcome** vocabulary (§7) | |

## The swap point

Only one file fakes cryptography: [`src/pavel-mock/verify.ts`](src/pavel-mock/verify.ts).
It performs the *same logical checks* as ARCHITECTURE.md §7's pipeline and returns
the same outcome enum (`verified | predicate_false | predicate_unavailable |
untrusted_issuer | expired | replay | malformed`). Replacing it with the real
`@justinswork/pavel-core` verifier is the entire go-live step for this demo — the
middleware ([`src/pavel-mock/index.ts`](src/pavel-mock/index.ts)) and the store
never change.

## Exercising the outcomes

The mock wallet modal offers a scenario button for each outcome, so you can drive
the store through every branch by hand:

- **Present credential — over 21** → `verified`, order completes
- **Present credential — under 21** → `predicate_false`, stays gated
- **Credential without this predicate** → `predicate_unavailable`
- **Credential from untrusted issuer** → `untrusted_issuer`
- **Cancel / decline** → `declined`

Replay, malformed, and expired outcomes are covered by the middleware (single-use
nonce, TTL) and are reachable via the HTTP API directly.

## Re-verifying at every checkout (`forceReverify`)

By default PAVEL is **verify-once-per-session**: the ceremony runs once and the
cached flag gates later requests (ARCHITECTURE.md §4/§8). Some stores must instead
re-verify on **every** purchase regardless of a recent prior verification. Pass
`forceReverify: true` to the gate:

```js
// Verify once, cache for the session (default):
requireAgeProof({ minAge: 21 })

// Require a fresh proof for every gated action:
requireAgeProof({ minAge: 21, forceReverify: true })
```

`forceReverify` makes the proof **one-shot**: it authorizes exactly one gated
action and is consumed once that action completes successfully (`res.on('finish')`,
status < 400), so the next request re-runs the ceremony. A failed action does not
burn the verification.

The store exposes this as the **"Re-verify age at every checkout"** toggle in the
cart. (A real store hard-codes the policy; the toggle just lets you compare both
modes in one session — watch the header badge flip back to "Not age-verified" after
a checkout when it's on.)

## Layout

```
demo/
├─ src/
│  ├─ server.ts            # Express store: catalog, cart, gated checkout
│  ├─ catalog.ts           # product data (some age-restricted)
│  └─ pavel-mock/
│     ├─ index.ts          # pavel() ceremony endpoints + requireAgeProof() gate  [REAL plumbing]
│     ├─ verify.ts         # verifyPresentation() — THE SWAP POINT               [mock crypto]
│     └─ types.ts          # shared types mirroring ARCHITECTURE.md
└─ public/
   ├─ index.html
   ├─ zk-age.js            # mock client SDK: requestAgeProof() + simulated wallet
   ├─ app.js               # store front-end
   └─ styles.css
```

## HTTP surface

| Method + path | Purpose |
|---|---|
| `GET /pavel/request?minAge=NN` | Mint nonce, return the OpenID4VP request (§5) |
| `POST /pavel/verify` `{ vp_token }` | Run the pipeline, set the session flag (§7) |
| `GET /api/catalog` | Products + configured `minAge` |
| `GET/POST /api/cart`, `POST /api/cart/clear` | Session cart |
| `POST /api/checkout` | Completes; gated by `requireAgeProof` iff cart has a restricted item |
| `GET /api/status` | Current verification badge state |
| `GET /premium-content` | Standalone gated route mirroring the README example |
