# `@justinswork/pavel-client`

The browser half of PAVEL. One call runs the whole age check against the [`@justinswork/pavel`](../middleware) endpoints: it fetches a challenge from your server, opens the phone's wallet through the [Digital Credentials API][dc-api], sends the wallet's answer back to your server for verification, and gives you a simple result. No personal data ever reaches your page.

```bash
npm install @justinswork/pavel-client
```

> PAVEL is not yet published to npm. Until it is, use the packages from this repository (see the [main README](../../README.md#run-it-locally)).

## Usage

The usual pattern: try the protected action, and if the server answers that an age check is needed, run it and try again.

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

The page doesn't decide whether an age check is needed; the server does, based on its own rules and whether the user has already verified.

Without a bundler, the IIFE build attaches `window.pavelClient`:

```html
<script src="/pavel-client.js"></script>
<script>
  const { ok, reason } = await window.pavelClient.requestAgeProof({ minAge: 21 });
</script>
```

(The build currently writes this file as `dist/zk-age.js`; serve it under whatever name you like.)

## Browsers and wallets

When the server offers several protocols, as `@justinswork/pavel` does, the client passes all of them to the browser, which picks the one it and the user's wallet support:

| Browser | Protocol |
|---|---|
| Chrome on Android | `openid4vp-v1-unsigned`, or `openid4vp-v1-signed` for Google Wallet real IDs |
| Safari on iPhone / iPad | `org-iso-mdoc` |

Encrypted answers (`org-iso-mdoc` and `openid4vp-v1-signed`) are forwarded to the server as-is; only the server can decrypt them.

## Result

`requestAgeProof` never throws. It resolves to `{ ok: true }` once the server has verified the answer and recorded it, or to `{ ok: false, reason }`:

| `reason` | Meaning |
|---|---|
| `unsupported` | This browser doesn't support the Digital Credentials API. |
| `declined` | The user closed the wallet prompt. |
| `request_failed` | The challenge couldn't be fetched from the server. |
| `verification_failed` | The verify call failed or returned an unknown result. |
| `predicate_false` | The ID is valid, but the user is under the required age. |
| `predicate_unavailable` | The ID doesn't include the requested age field. |
| `untrusted_issuer` | The ID wasn't issued by anyone the server trusts. |
| `expired` | The ID is outside its validity dates. |
| `replay` | The answer wasn't made for this site and this challenge. |
| `malformed` | The answer couldn't be read, or its signature is invalid. |

The last six come straight from the server's verification result.

## Options

`minAge` is the only option most callers set:

| Option | Default | Description |
|---|---|---|
| `minAge` | required | The age to prove, e.g. `21` asks for `age_over_21`. |
| `request` | none | A challenge fetched earlier with `fetchAgeRequest`. See [Timing](#timing). |
| `requestPath` | `/pavel/request` | Where your server issues challenges. |
| `verifyPath` | `/pavel/verify` | Where your server verifies answers. |
| `signal` | none | An `AbortSignal` to cancel the check. |
| `onDiagnostic` | none | A callback that receives the raw wallet response, wallet errors, and the verify result. Useful for debugging on real devices. |
| `fetch` | global `fetch` | A replacement `fetch`, for tests or non-browser hosts. |
| `protocol` | `openid4vp-v1-unsigned` | Only used if the server returns a single request instead of a list. |
| `credentialId` | `age_check` | The request ID the answer is read under (OpenID4VP only). |

## Timing

Browsers only open the wallet in direct response to a user action, such as a click. Chrome allows a few seconds of other work between the click and the wallet call, so the simple usage above normally works. On slow connections, fetch the challenge before the click and pass it in, so opening the wallet is the first thing the click does:

```js
import { fetchAgeRequest, requestAgeProof } from '@justinswork/pavel-client';

// Ahead of time, e.g. when the checkout page loads:
const request = await fetchAgeRequest({ minAge: 21 });

// In the click handler, the wallet opens immediately:
button.addEventListener('click', async () => {
  const result = await requestAgeProof({ minAge: 21, request });
});
```

A challenge is single-use and expires (after 5 minutes by default), so fetch it close to when it will be used. `fetchAgeRequest` throws on a network or server error; `requestAgeProof` never throws.

## Feature detection

`isDigitalCredentialsSupported()` tells you whether the browser supports the API, if you want to adjust your UI before starting. `requestAgeProof` also checks, and returns `unsupported` instead of throwing.

## Build

```bash
corepack pnpm --filter @justinswork/pavel-client build
```

Writes `dist/zk-age.js` (IIFE, attaches `window.pavelClient`) and `dist/pavel-client.mjs` (ES module).

## License

[Apache-2.0](../../LICENSE)

[dc-api]: https://developer.mozilla.org/en-US/docs/Web/API/Digital_Credentials_API
