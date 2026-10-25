# Cellar & Co. (`pavel-demo`)

An example store that shows PAVEL working end to end. Some products (wine, beer, a kitchen knife) are marked 21+. Checking out with one of them in the cart triggers a PAVEL age check before the order goes through; other orders are never prompted.

It runs the real `@justinswork/pavel` middleware and verifier. Nothing about the verification is simulated.

## Run

From the repository root:

```bash
corepack pnpm install
corepack pnpm dev
```

Then open `http://localhost:3000`. Set `PORT` to use a different port.

## On a desktop browser

Desktop browsers have no ID wallet, so when no wallet answers, the store opens a clearly labeled stand-in **dev wallet**. It presents real, signed test IDs from PAVEL's mock authority, so the production verifier still runs, and it has a button for each outcome:

- **Present credential, over 21:** `verified`, and the order completes
- **Present credential, under 21:** `predicate_false`
- **Credential without this predicate:** `predicate_unavailable`
- **Credential from untrusted issuer:** `untrusted_issuer`
- **Cancel / decline sharing:** the check is cancelled

The dev wallet exists only in this demo. A real deployment has no such endpoint.

## On a real phone

The Digital Credentials API only works on secure (HTTPS) sites, so make the store reachable over HTTPS, for example with a temporary tunnel, and set `ORIGIN` to that address so it matches what the phone's browser sees:

```bash
ORIGIN=https://your-tunnel.example corepack pnpm dev
```

- **Android:** install Google's [CMWallet](https://github.com/digitalcredentialsdev/CMWallet) test wallet, which includes a sample driver's license. A 21+ checkout in Chrome should end in `verified`.
- **iPhone:** install Apple's free "Wallet Identity Developer" profile from Apple's developer profiles page, which adds a simulated license to Apple Wallet. Apple Wallet accepts the request, but the simulated license has no issuer certificate, so the result is `untrusted_issuer`. That's expected.

## Configuration

| Setting | Effect |
|---|---|
| `PORT` | Port to listen on (default `3000`). |
| `ORIGIN` | The public address the store is reached at (default `http://localhost:<PORT>`). |
| `trust-anchors/*.pem` | Extra issuers to trust, on top of the mock authority. Ships with the CMWallet and Multipaz test issuers; see [trust-anchors/README.md](trust-anchors/README.md). |
| `GW_RP_METADATA_BYTES` | Turns on the Google Wallet signed request (for Google's sandbox or a registered site). |
| `.apple-reader/reader-key.pem` + `reader-cert.pem` | Turns on signed requests for Apple Wallet, using a certificate Apple issued you. Never commit these; the folder is in `.gitignore`. |

## Re-verifying at every checkout

By default, a successful check is remembered for the rest of the session. The cart's **"Re-verify age at every checkout"** checkbox switches the checkout guard to `requireAgeProof({ minAge: 21, forceReverify: true })`, so every purchase needs a fresh check. A real store would choose one policy; the checkbox lets you compare both. The header badge flips back to "Not age-verified" after each checkout when it's on.

## Routes

| Route | Purpose |
|---|---|
| `GET /pavel/request`, `POST /pavel/verify` | The PAVEL endpoints, from `@justinswork/pavel` |
| `POST /api/checkout` | Places the order; guarded by `requireAgeProof` when the cart has a 21+ item |
| `GET /api/catalog` | Products and the store's minimum age |
| `GET`/`POST /api/cart`, `POST /api/cart/clear` | The session cart |
| `GET /api/status` | Whether this session is age-verified (for the header badge) |
| `GET /premium-content` | A standalone guarded page, like the main README's example |
| `POST /dev-wallet/present` | Demo only: the dev wallet's endpoint |
| `POST /debug/log` | Demo only: prints browser-side diagnostics in the server's terminal, for debugging real devices |
