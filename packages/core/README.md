# `@justinswork/pavel-core`

The framework-independent verifier behind PAVEL. It builds the requests a phone's wallet answers, and verifies the wallet's signed answer: who issued the ID, whether it was altered, whether it's in date, whether it was made for your site, and finally whether the user meets the age.

Most sites don't need this package directly: [`@justinswork/pavel`](../middleware) wraps it for Express, including the session handling. Use core when you want PAVEL in another framework (Fastify, Next.js, Hono, and so on) or a custom flow.

```bash
npm install @justinswork/pavel-core
```

> PAVEL is not yet published to npm. Until it is, use the packages from this repository (see the [main README](../../README.md#run-it-locally)).

## Using it directly

An age check is two server calls with the browser in between: **build** a request and send it to the browser, then **verify** the answer the browser posts back. Each protocol has its own pair of functions, and each needs a few values kept on the server between the two calls (in the user's session, for example):

| Protocol | Build | Verify | Keep between calls |
|---|---|---|---|
| `openid4vp-v1-unsigned` (Chrome on Android) | `buildAgeRequest` | `verifyPresentation` | the nonce |
| `org-iso-mdoc` (Safari) | `buildIsoMdocAgeRequest` | `verifyIsoMdocPresentation` | `ephemeralPrivateKeyJwk`, `encryptionInfoBase64Url` |
| `openid4vp-v1-signed` (Google Wallet) | `buildGoogleAgeRequest` | `verifyGooglePresentation` | the nonce, `encryptionPrivateKeyJwk` |

You can offer several protocols in one challenge, and the browser and wallet pick one they support. The [`@justinswork/pavel-client`](../client) SDK accepts a response of the form `{ requests: [{ protocol, data }, …] }`.

Here is the Chrome/Android flow:

```ts
import { randomBytes } from 'node:crypto';
import { buildAgeRequest, createOwfMdocBackend, verifyPresentation } from '@justinswork/pavel-core';

const origin = 'https://shop.example';
const backend = createOwfMdocBackend({ trustAnchors }); // root certificates (PEM) of the issuers you accept

// 1. Build the request, and keep the nonce for this user.
const nonce = randomBytes(16).toString('base64url');
const data = buildAgeRequest({ minAge: 21, nonce, origin });
// send { requests: [{ protocol: 'openid4vp-v1-unsigned', data }] } to the browser

// 2. Verify the answer the browser posts back.
const result = await verifyPresentation(vpToken, { nonce, expectedOrigin: origin, minAge: 21 }, backend);
if (result.outcome === 'verified') {
  // record that this user is over 21
}
```

The Safari and Google Wallet pairs work the same way, but their answers are encrypted, so you keep the private key the build step returns and pass it to the verify step.

### What you're responsible for

Core verifies; it doesn't manage state. When you use it directly, do what the middleware does for you:

- **Make the nonce random and single-use.** Generate a fresh one per check, and discard it after one verify attempt, whether or not the answer verifies.
- **Expire challenges.** The middleware's default is 5 minutes.
- **Keep private keys on the server.** Never send `ephemeralPrivateKeyJwk` or `encryptionPrivateKeyJwk` to the browser.
- **Use the exact origin.** Pass your site's origin with no trailing slash; it's signed into every answer.
- **Protect the session.** Give the user a new session ID after a successful check, so an attacker can't plant a session ahead of time.

The middleware's [`pavel.ts`](../middleware/src/pavel.ts) is a short, complete reference for all of the above.

## Checks and outcomes

Every verify function runs the same checks in order and stops at the first one that fails:

| # | Check | Outcome if it fails |
|---|---|---|
| 1 | The answer decodes as a supported ID | `malformed` |
| 2 | The issuer's certificate traces back to one of your trust anchors | `untrusted_issuer` |
| 3 | The issuer's signature is valid, and the shared value matches what the issuer signed | `malformed` |
| 4 | The ID is within its validity dates | `expired` |
| 5 | The phone's signature proves the answer was made for this site and this challenge | `replay` |
| 6 | The ID contains the requested age field | `predicate_unavailable` |
| 7 | That field is true | `predicate_false` |

If every check passes, the outcome is `verified`. For the Safari protocol (`org-iso-mdoc`), the site's origin is also part of the encryption, so an answer made for a different site fails to decrypt and is reported as `malformed` rather than `replay`. The result is `{ outcome, predicate? }`, where `predicate` is the field that was evaluated, e.g. `age_over_21`.

## Design notes

- **Minimal by construction.** The request builders accept only a minimum age and always ask for exactly one field (`age_over_NN`). There's no way to request a name, birthdate, or anything else through this API, and tests assert it.
- **Fails closed.** A check only passes on positive evidence that it passed. If the underlying library skips a check or reports a failure PAVEL doesn't recognize, the answer is rejected, not accepted.
- **Strict certificate paths.** Every certificate that issues another must be a certificate authority allowed to sign certificates, and every certificate in the path, trust anchor included, must be in date.
- **Supported ID types:** mobile driver's licenses (`org.iso.18013.5.1.mDL`) and Google Wallet ID Passes (`com.google.wallet.idcard.1`). Google documents only `age_over_18` for ID Passes, so a 21+ check against one may return `predicate_unavailable`.
- **Built on** the OpenWallet Foundation's [`@owf/mdoc`](https://github.com/openwallet-foundation-labs/mdoc-ts) for decoding and signature checks.

## Reader certificates (real IDs)

To accept real IDs, Google Wallet and Apple Wallet require signed requests from a registered site (see the [middleware README](../middleware/README.md#accepting-real-ids)). Core provides the helpers:

- `readerFromPem(privateKeyPem, [certPem, …])` turns the key and certificates a platform issues you into a reader identity, used by both `buildGoogleAgeRequest` and `buildIsoMdocAgeRequest`.
- `createGoogleReader()` makes a self-signed reader certificate for Google's sandbox.

## Debug logging

Off by default. These environment variables log each stage of a verification, to help diagnose real-device problems. They log only the document type, check results, and public issuer certificates, never personal data:

| Variable | Logs |
|---|---|
| `PAVEL_DEBUG_ISO=1` | each stage of Safari (`org-iso-mdoc`) verification |
| `PAVEL_DEBUG_GOOGLE=1` | each stage of Google Wallet verification |
| `PAVEL_DEBUG_ISO_CERTS=1` | the issuer certificate chain a wallet presented, as PEM, so you can add it to your trust anchors |

## Develop

```bash
corepack pnpm --filter @justinswork/pavel-core test
corepack pnpm --filter @justinswork/pavel-core typecheck
```

## License

[Apache-2.0](../../LICENSE)
