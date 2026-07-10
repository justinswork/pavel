# PAVEL

**P**rivacy-first **A**ge **V**erification & **E**ligibility **L**ibrary — a two-lines-of-code gateway that lets web developers verify a user meets an eligibility predicate (e.g. *over 21*) **without ever receiving their personal data**.

> **Status:** early development. PAVEL began as a graduate capstone project; see the [Roadmap](#roadmap--scope) for what's built and what's planned.

```js
// Backend: gate a route behind a cryptographically verified age check
app.post('/premium-content', requireAgeProof({ minAge: 21 }), (req, res) => {
  res.send('Access granted — age verified, no personal data received.');
});
```

---

## Why

New global regulations require websites to strictly enforce age gates. Traditional solutions — uploading a photo of an ID card — compromise user privacy by exposing highly sensitive PII to arbitrary web servers.

Emerging browser standards (the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/), shipped in stable Chrome and Safari) now let a user present a **selectively-disclosed** attribute from their mobile wallet — proving `age_over_21 = true` while their name, birthdate, address, and photo never leave the phone. Newer cryptographic libraries (Google's [Longfellow-ZK](https://github.com/google/longfellow-zk)) push this further toward full zero-knowledge *unlinkability*, but remain early-stage.

In both cases the raw browser-wallet integration is complex, leaving a gap for everyday web developers. **PAVEL is a plug-and-play, web-first gateway** that abstracts this cryptography into an ergonomic, declarative middleware framework — grounded in the selective-disclosure mechanism that ships today, with full zero-knowledge proofs pursued as a stretch goal.

## How It Works

PAVEL is a cohesive, two-part full-stack utility:

- **Client SDK (`zk-age.js`)** — a lightweight front-end library. It triggers the browser's native `navigator.credentials.get()` to request a selectively-disclosed age attribute from the user's wallet (Apple / Google) and forwards the resulting token to your backend.
- **Server Middleware (Node.js / Express)** — a drop-in router module. It intercepts the client token, cryptographically verifies the issuer signature (COSE Sign1 / MSO) against a trusted authority's public key (e.g. a state DMV), and manages the user's logged-in session state.

## Roadmap & Scope

PAVEL targets **ISO 18013-7 mdoc selective disclosure** — the presentation mechanism live in stable Chrome and Safari today — as its production baseline. Full zero-knowledge unlinkability (Longfellow-ZK) is a clearly-scoped stretch objective.

| # | Deliverable | Description |
|---|---|---|
| 1 | **Mock Authority Simulator** | Mints mock, cryptographically signed mDLs — a local root-of-trust so the whole system is testable offline against pre-trusted keys. *(No relying-party registration required.)* |
| 2 | **Client SDK (`zk-age.js`)** | Front-end library wrapping `navigator.credentials.get()` with a declarative request for an age predicate (e.g. `age_over_21`). |
| 3 | **Server Middleware** | The `requireAgeProof({ minAge })` router: parses the returned mdoc, verifies the issuer signature against the trusted authority key, manages session state. |
| 4 | **Reference Web App** | A fully functional, age-gated e-commerce demo showing the gateway working end-to-end against an emulated wallet. |
| 5 | **Performance & Latency Evaluation** | Benchmarks of token payload sizes and sustained concurrent verifications-per-second before latency degrades. |

**Stretch — Zero-Knowledge Unlinkability:** integrate verification of a Longfellow-ZK range proof (via a WASM-compiled or native binding of the Apache-2.0 library), eliminating issuer-signature linkability. The five core deliverables stand independently if this proves infeasible.

## Testing

PAVEL is designed to be verifiable **offline, on a single machine, with no external accounts or approvals**:

- **Self-issued trust** — the Mock Authority Simulator acts as the root of trust, so the middleware verifies proofs against a key pair the project controls; no live DMV is contacted.
- **Emulated wallet** — Google's open-source [CMWallet](https://digitalcredentials.dev/docs/samples/android-wallet-sample/) sample runs in an Android emulator as the credential holder, side-loaded with a mock mDL. This exercises the real `navigator.credentials.get()` → wallet-picker → consent → token flow without a physical device or real wallet credential.
- **Sandbox parity** — Google's published Sandbox Mode test keys confirm the middleware behaves identically against pre-trusted, production-shaped metadata.

Registration as an approved relying party (production CSR, verification review) is required only to accept credentials from *real* consumer wallets — out of scope for this project. The delivered code is production-applicable the moment that step is completed.

## License

[Apache-2.0](LICENSE)
