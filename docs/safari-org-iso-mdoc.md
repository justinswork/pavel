# Safari support — ISO 18013-7 Annex C (`org-iso-mdoc`)

**Status:** implemented and validated end-to-end via the mock wallet; **not yet
confirmed against real Safari** (see Residuals). Chrome (`openid4vp`) is unaffected.

## Why this exists

Safari speaks only the `org-iso-mdoc` DC-API protocol (ISO 18013-7 Annex C); it
rejects our `openid4vp-v1-unsigned` request outright (`TypeError: "At least one
supported DigitalCredentialRequest must present"`, confirmed on a real iPad). So
cross-browser support means offering the ISO protocol too. Unlike OpenID4VP, this
transport **encrypts the response**.

## The wire format

```
EncryptionInfo    = ["dcapi", { nonce: bstr, recipientPublicKey: COSE_Key }]   (base64url)
DeviceRequest     = CBOR (base64url)                     ── request data = { deviceRequest, encryptionInfo }
SessionTranscript = [null, null, ["dcapi", SHA-256(CBOR([encryptionInfoB64, origin]))]]
EncryptedResponse = ["dcapi", { enc: bstr, cipherText: bstr }]   (base64url)
```

HPKE single-shot (RFC 9180), suite **DHKEM(P-256)/HKDF-SHA256/AES-128-GCM**, with
the CBOR SessionTranscript as the HPKE `info` and empty aad. The verifier generates
a reader ephemeral key, the wallet seals its DeviceResponse to it, the verifier
opens it and verifies the plaintext exactly as for OpenID4VP.

## Components

- **`pavel-core/hpke.ts`** — `hpkeSeal` / `hpkeOpen` (via `@hpke/core`). @owf/mdoc
  leaves HPKE to the caller.
- **`pavel-core/iso-mdoc.ts`** — `buildIsoMdocAgeRequest` (ephemeral key + nonce +
  EncryptionInfo + DeviceRequest), `verifyIsoMdocPresentation` (parse → HPKE-open →
  decode → verify), and `sealIsoMdocResponse` (holder/test side).
- **`pavel-core/verify-shared.ts`** — the assessment→`RawVerification` mapping,
  shared by the OpenID4VP and ISO paths (only decode + transcript differ).
- **`@justinswork/pavel` (middleware)** — `/pavel/request` offers **both** protocols
  and stashes the ISO ephemeral key + EncryptionInfo in the session; `/pavel/verify`
  routes by protocol.
- **`@justinswork/pavel-client`** — offers both protocols to the wallet, then routes
  the verify POST by the protocol the browser chose.
- **`pavel-mock-authority`** — `MockWallet.presentIso` HPKE-seals a real DeviceResponse,
  standing in for Safari's OS wallet so the whole path is testable offline.

## What's tested

- HPKE round-trip + info-binding + wrong-key (unit).
- Full ISO mint → present → HPKE-decrypt → verify: `verified`, `predicate_false`,
  `untrusted_issuer`, and `malformed` (wrong-origin fails to decrypt, and garbage).
- The ISO ceremony through the real middleware endpoints.

## Trying it on an iPad

Serve over HTTPS (`cloudflared`) with `ORIGIN` set to the tunnel URL, open in Safari,
and run a `21+` checkout. Safari will now **accept** the request (no more `TypeError`)
and open its wallet — the milestone this unblocks.

## Residuals (honest gaps)

1. **Real-Safari byte interop is unverified.** The CBOR structures follow the ISO
   spec and the Animo reference impl, and round-trip through our own encode/decode —
   but the first real-Safari run may reveal a mismatch (e.g. the COSE_Key `alg`
   field, or the response wrapper). The `onDiagnostic` → `/debug/log` path logs the
   raw wallet response so any mismatch is diagnosable, and `parseEncryptedResponse`
   is intentionally tolerant of wrapper shapes.
2. **iOS has no test-credential story.** There's no CMWallet-style sideload; a real
   Apple Wallet ID would verify structurally but return `untrusted_issuer` (its DMV
   root isn't one we trust). So a green `verified` *on the iPad* needs a trusted test
   credential in an iOS wallet — a separate problem from this code.

## References

- [WebKit — Safari 26 Digital Credentials API](https://webkit.org/blog/17333/webkit-features-in-safari-26-0/)
- ISO/IEC TS 18013-7:2025, Annex C · [Animo mdoc](https://github.com/animo/mdoc) (reference impl)
