# Cellar & Co.

An example store that shows PAVEL working end to end. Some products (wine, beer, a kitchen knife) are marked 21+. Checking out with one of them in the cart triggers a PAVEL age check before the order goes through; other orders are never prompted.

It runs the real `@justinswork/pavel` middleware and verifier. Nothing about the verification is simulated.

## Run

From the repository root:

```bash
pnpm install
pnpm dev
```

(If you don't have pnpm, run `corepack enable` first.) Then open `http://localhost:3000`. Set `PORT` to use a different port.

## Trying the age check

The age check needs a phone with an ID wallet. On a desktop browser without one, a 21+ checkout explains that the browser doesn't support digital IDs.

The Digital Credentials API only works on secure (HTTPS) sites, so make the store reachable over HTTPS, for example with a temporary tunnel, and set `ORIGIN` to that address so it matches what the phone's browser sees:

```bash
ORIGIN=https://your-tunnel.example pnpm dev
```

- **Android:** install Google's [CMWallet](https://github.com/digitalcredentialsdev/CMWallet) test wallet, which includes a sample driver's license. A 21+ checkout in Chrome should end in `verified`.
- **iPhone:** install Apple's free "Wallet Identity Developer" profile from Apple's developer profiles page, which adds a simulated license to Apple Wallet. Apple Wallet accepts the request, but the simulated license has no issuer certificate, so the result is `untrusted_issuer`. That's expected.

## Configuration

| Setting | Effect |
|---|---|
| `PORT` | Port to listen on (default `3000`). |
| `ORIGIN` | The public address the store is reached at (default `http://localhost:<PORT>`). |
| `trust-anchors/*.pem` | The ID issuers the store accepts. Ships with the CMWallet and Multipaz test issuers; see [trust-anchors/README.md](trust-anchors/README.md). |

## Routes

| Route | Purpose |
|---|---|
| `GET /pavel/request`, `POST /pavel/verify` | The PAVEL endpoints, from `@justinswork/pavel` |
| `POST /api/checkout` | Places the order; guarded by `requireAgeProof` when the cart has a 21+ item |
| `GET /api/catalog` | The products |
| `GET`/`POST /api/cart`, `POST /api/cart/clear` | The session cart |
| `GET /pavel-client.js` | PAVEL's browser script |
