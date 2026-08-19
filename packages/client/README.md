# @justinswork/pavel-client (`zk-age.js`)

The browser half of PAVEL. One call runs the whole age-verification ceremony
against the [`@justinswork/pavel`](../middleware) endpoints — fetch the challenge,
invoke the OS wallet through the [Digital Credentials API][dc-api], post the
presentation back — and hands you a boolean-shaped result. No PII ever touches
your page.

```js
import { requestAgeProof } from '@justinswork/pavel-client';

const result = await requestAgeProof({ minAge: 21 });
if (result.ok) {
  location.reload(); // the server has recorded the eligibility fact
} else {
  showFallback(result.reason); // 'unsupported' | 'declined' | 'predicate_false' | …
}
```

Or as a plain script — the IIFE build attaches `window.pavelClient`:

```html
<script src="/zk-age.js"></script>
<script>
  const { ok, reason } = await window.pavelClient.requestAgeProof({ minAge: 21 });
</script>
```

## Result

`requestAgeProof` never throws. It resolves to:

- `{ ok: true }` — the ceremony verified and the server recorded the fact.
- `{ ok: false, reason }` — where `reason` is one of:

| reason | meaning |
|---|---|
| `unsupported` | this browser has no Digital Credentials API |
| `declined` | the user dismissed the wallet prompt |
| `request_failed` | couldn't fetch the authorization request |
| `verification_failed` | the verify call errored or returned an unknown outcome |
| `predicate_false` | credential present, but under the required age |
| `predicate_unavailable` | the issuer never signed this age predicate |
| `untrusted_issuer` | signer doesn't chain to a trusted IACA |
| `expired` | credential outside its validity window |
| `replay` | presentation not bound to this fresh challenge |
| `malformed` | undecodable / structurally invalid presentation |

The last six pass straight through from `pavel-core`'s verification outcomes.

## Options

`minAge` is the only one most callers set. The rest exist for custom mounts and
testing:

| option | default | notes |
|---|---|---|
| `minAge` | — | required; maps to the `age_over_<minAge>` predicate |
| `requestPath` | `/pavel/request` | where the challenge is minted |
| `verifyPath` | `/pavel/verify` | where the presentation is verified |
| `protocol` | `openid4vp` | DC API protocol string |
| `credentialId` | `age_check` | DCQL id the vp_token is read under |
| `fetch` | global `fetch` | injectable for tests / non-browser hosts |
| `signal` | — | `AbortSignal` to cancel the in-flight ceremony |
| `request` | — | a pre-fetched authorization request (from `fetchAgeRequest`) — see *Transient activation* below |

## Transient activation

`navigator.credentials.get()` requires **transient activation** — it must run
inside a live user gesture. Chrome keeps that activation alive for ~5s across
`await`s, so the one-call form above usually works. But to be robust (slow
networks, tunnels), fetch the request *before* the gesture and pass it in, so the
wallet call is the first async step in the handler:

```js
import { fetchAgeRequest, requestAgeProof } from '@justinswork/pavel-client';

// Ahead of the gesture (e.g. when the user shows checkout intent):
const request = await fetchAgeRequest({ minAge: 21 });

// Inside the click handler — get() runs first, activation intact:
button.addEventListener('click', async () => {
  const result = await requestAgeProof({ minAge: 21, request });
});
```

The minted nonce is single-use and TTL'd (default 5 min), so fetch it close to
the gesture. `fetchAgeRequest` throws on a network / non-2xx error; `requestAgeProof`
still never throws.

## Feature detection

`isDigitalCredentialsSupported()` is exported if you want to gate UI before
starting; `requestAgeProof` also checks internally and returns `unsupported`
rather than throwing.

## Build

```bash
pnpm --filter @justinswork/pavel-client build
```

Emits `dist/zk-age.js` (IIFE, `window.pavelClient`) and `dist/pavel-client.mjs`
(ESM).

## Limitation

v0 targets the `openid4vp` protocol. Safari currently speaks only
`org-iso-mdoc`, whose request payload differs; broadening the compatibility
matrix (and the server-side request builder) is tracked separately.

[dc-api]: https://developer.mozilla.org/en-US/docs/Web/API/Digital_Credentials_API
