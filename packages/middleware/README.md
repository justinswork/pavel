# `@justinswork/pavel`

Express middleware for PAVEL. It adds two things to your server:

- **`pavel()`**: a router with the endpoints that run an age check (issue a challenge, verify the wallet's answer).
- **`requireAgeProof()`**: a guard you put in front of any route that should only run for users who have proven their age.

It pairs with [`@justinswork/pavel-client`](../client) in the browser. Your server never receives a name, birthdate, address, or photo: only whether the user is over the age you asked about.

## Install

```bash
npm install @justinswork/pavel express express-session
```

> PAVEL is not yet published to npm. Until it is, use the packages from this repository (see the [main README](../../README.md#run-it-locally)).

Tested on Node.js 24.

## Quick start

```js
import express from 'express';
import session from 'express-session';
import { readFileSync } from 'node:fs';
import { pavel, requireAgeProof } from '@justinswork/pavel';

const app = express();
app.use(express.json());
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));

// Mount the age-check endpoints.
app.use(pavel({
  origin: 'https://shop.example',
  trustAnchors: [readFileSync('certs/arizona-iaca.pem', 'utf8')],
}));

// Only users who have proven they are 21 or older reach placeOrder.
app.post('/checkout', requireAgeProof({ minAge: 21 }), placeOrder);
```

And in the browser, when the guard answers 401:

```js
import { requestAgeProof } from '@justinswork/pavel-client';

let response = await fetch('/checkout', { method: 'POST' });
if (response.status === 401) {
  const { minAge } = await response.json();       // the server says which age it needs
  const proof = await requestAgeProof({ minAge });  // opens the phone's wallet
  if (proof.ok) response = await fetch('/checkout', { method: 'POST' });
  else showMessage(proof.reason);
}
```

The page doesn't decide whether an age check is needed; the server does. That keeps the rule in one place and means users are only asked when they have to be.

### Requirements

- **`express.json()`** must run before `pavel()`, because the verify endpoint reads a JSON body.
- **A session middleware** that provides `req.session` with `regenerate()` and `save()`, such as [`express-session`](https://github.com/expressjs/session). PAVEL stores its state in the session.
- **HTTPS.** The browser's Digital Credentials API only works on secure origins, and `origin` is signed into every response, so it must match the address users actually visit (a trailing slash is ignored). `http://localhost` works for local development.

## `pavel(options)`

| Option | Default | Description |
|---|---|---|
| `origin` | required | Your site's origin, e.g. `https://shop.example`. |
| `trustAnchors` | required | Root certificates (PEM strings) of the ID issuers you accept. See [Trust anchors](#trust-anchors). |
| `clientName` | none | Your site's name, included in the Chrome/Android request for wallets that display it. |
| `nonceTtlMs` | `300000` | How long a challenge stays valid, in milliseconds (default 5 minutes). |
| `google` | none | Google Wallet configuration for real IDs. See [Accepting real IDs](#accepting-real-ids). |
| `apple` | none | Apple Wallet configuration for real IDs. See [Accepting real IDs](#accepting-real-ids). |

### Endpoints

The client SDK calls these for you; you don't need to call them directly.

**`GET /pavel/request?minAge=21`** creates a single-use challenge, stores it in the session, and returns the request for the wallet. It offers every format the server supports, and the browser picks the one it understands:

| Protocol | Used by | When offered |
|---|---|---|
| `openid4vp-v1-signed` | Google Wallet (real IDs) | only when `google` is configured |
| `openid4vp-v1-unsigned` | Chrome on Android, test wallets | always |
| `org-iso-mdoc` | Safari on iPhone and iPad | always (signed when `apple` is configured) |

`minAge` must be a whole number from 1 to 120; otherwise the response is `400 { "error": "invalid_min_age" }`.

**`POST /pavel/verify`** checks the wallet's answer against the stored challenge. The challenge is used up whether or not the answer verifies.

- On success: `200 { "ok": true, "outcome": "verified" }`. The session gets a new ID (which prevents session-fixation attacks), your app's own session data is carried over, and the session records that the user is verified.
- On failure: `400 { "ok": false, "outcome": "…" }`, where `outcome` is one of:

| Outcome | Meaning |
|---|---|
| `predicate_false` | The ID is valid, but the user is under the required age. |
| `predicate_unavailable` | The ID doesn't include the requested age field. |
| `untrusted_issuer` | The ID wasn't issued by anyone in `trustAnchors`. |
| `expired` | The ID is outside its validity dates. |
| `replay` | The answer wasn't made for this site and this challenge (reused, forwarded, or the challenge expired). |
| `malformed` | The answer couldn't be decrypted or decoded, or its signature is invalid. |

## `requireAgeProof(options)`

| Option | Default | Description |
|---|---|---|
| `minAge` | required | The age the user must have proven. |
| `forceReverify` | `false` | When `true`, each proof can be used for only one request. |

The guard lets a request through if the session has a verified proof for at least `minAge`. Proving 21, for example, also satisfies a guard that requires 18. Otherwise it responds:

```json
401 { "error": "age_verification_required", "minAge": 21, "requestUrl": "/pavel/request?minAge=21" }
```

**`forceReverify`.** By default a successful check is remembered for the rest of the session. With `forceReverify: true`, the proof is used up by the first guarded request that succeeds (status below 400), so the user verifies again next time. If the guarded request fails, the proof is released so the user can retry without verifying again.

> **Limitation:** used-up proofs are tracked in memory, per server process. If you run several instances behind a load balancer, `forceReverify` only holds within each instance. A shared store is not provided yet.

## Trust anchors

`trustAnchors` is the list of issuers whose IDs you accept: the official root certificate (called an IACA certificate) of each issuing authority, usually one per state, as PEM text. A credential from any other issuer is rejected as `untrusted_issuer`, even if its signatures are valid.

PAVEL does not ship or download these certificates; you choose and supply them. States publish their root certificates, and AAMVA collects them through its Digital Trust Service. One way to load a folder of them:

```js
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

const trustAnchors = readdirSync('certs')
  .filter((f) => f.endsWith('.pem'))
  .map((f) => readFileSync(path.join('certs', f), 'utf8'));
```

For local development, [`@justinswork/pavel-mock-authority`](../mock_authority) creates a test issuer and test IDs. Never trust its certificate in production.

## Accepting real IDs

Test wallets work without extra configuration. To accept real state IDs from Google Wallet and Apple Wallet, your site must first register with each platform, because the wallets only release real IDs to registered sites:

- **Google Wallet:** apply to Google as a verifier. Google provides the metadata (`gwRpMetadataBytes`) and signs your reader certificate.
- **Apple Wallet:** a verified organization in an eligible category (for example, licensed alcohol sales) registers through Apple Business for "Verify with Wallet on the Web," and receives a reader certificate.

Then pass the key and certificates you were issued:

```js
import { readerFromPem } from '@justinswork/pavel-core';

app.use(pavel({
  origin: 'https://shop.example',
  trustAnchors,
  google: {
    origin: 'https://shop.example',
    reader: readerFromPem(googleKeyPem, [googleCertPem]),
    gwRpMetadataBytes: process.env.GW_RP_METADATA_BYTES,
  },
  apple: {
    reader: readerFromPem(appleKeyPem, [appleCertPem]),
  },
}));
```

When `google` is set, PAVEL also offers Google Wallet's signed and encrypted request. When `apple` is set, PAVEL signs its Safari requests, which Apple requires for real IDs. No other code changes are needed.

> **Status:** both paths are built and tested against simulated wallets, but have not yet been confirmed with real IDs, because that requires a registered site.

## Session data

After a successful check, `req.session.pavel` holds only:

```ts
{ verified: true, verifiedMinAge: 21, verifiedAt: 1761400000000, proofId: '…' }
```

No personal data is stored. The package's types extend `express-session`'s `SessionData`, so `req.session.pavel` is typed in TypeScript.

## Security notes

- Each challenge is random, single-use, expires after `nonceTtlMs`, and is tied to your `origin`, so an answer can't be reused or forwarded from another site.
- Use a strong session secret, and set `cookie: { secure: true }` in production so the session cookie is only sent over HTTPS.
- Revocation is not checked: PAVEL enforces an ID's validity dates, but does not yet consult issuers' revocation lists.

## License

[Apache-2.0](../../LICENSE)
