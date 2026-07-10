# PAVEL — Glossary

Domain terms used across [ARCHITECTURE.md](ARCHITECTURE.md) and the codebase, roughly grouped. This space is acronym-heavy; when in doubt, start here.

## Protocols & APIs

- **DC API (Digital Credentials API)** — W3C browser API, `navigator.credentials.get({ digital: … })`, that lets a web page request a credential presentation from the OS wallet. Shipped in stable Chrome and Safari. This is PAVEL's browser entry point.
- **OpenID4VP (OpenID for Verifiable Presentations)** — the *protocol* carried over the DC API. Defines the Authorization Request (what the verifier asks) and the `vp_token` response. Protocol string: `openid4vp`.
- **org-iso-mdoc** — an alternative DC API protocol string that carries an ISO 18013-7 request/response directly (used by Safari today; Chrome supports it too). PAVEL normalizes it and `openid4vp` into the same internal intent.
- **DCQL (Digital Credentials Query Language)** — JSON query language inside the OpenID4VP request that declares which credential (`format`, `doctype_value`) and which claims (`path`) are requested.
- **Authorization Request** — the OpenID4VP message the verifier sends: `response_type`, `response_mode`, `nonce`, `dcql_query`, `client_metadata`.
- **`vp_token`** — the Verifiable Presentation token returned in the OpenID4VP response. For mdoc it is a base64url-encoded CBOR `DeviceResponse`.
- **response_mode `dc_api` / `dc_api.jwt`** — DC API response delivery; `.jwt` variant encrypts the response to the verifier's key.

## Credential format (ISO/IEC 18013)

- **ISO/IEC 18013-5** — standard defining the mDL data model and the mdoc credential format (originally for in-person NFC/QR).
- **ISO/IEC 18013-7** — extends 18013-5 to *online* / unattended presentation (the web case PAVEL uses).
- **mdoc** — the CBOR-encoded credential format defined by 18013-5. Generic container; an mDL is one profile of it.
- **mDL (mobile Driver's License)** — an mdoc with `docType = org.iso.18013.5.1.mDL`.
- **docType** — identifier for the credential type, e.g. `org.iso.18013.5.1.mDL`.
- **namespace** — grouping of attributes within a credential, e.g. `org.iso.18013.5.1` holds the standard mDL fields.
- **DeviceResponse** — top-level CBOR object returned by the wallet; contains a `documents` array.
- **IssuerSigned** — the part of a document signed by the issuer: the disclosed `nameSpaces` items plus `issuerAuth`.
- **IssuerSignedItem** — one disclosed attribute, a 4-tuple `{ digestID, random, elementIdentifier, elementValue }`. `random` is a per-item salt.
- **DeviceSigned / DeviceAuth** — the part signed by the *holder's device*, proving holder binding over the `SessionTranscript`.
- **MSO (Mobile Security Object)** — the issuer-signed metadata object. Contains `version`, `digestAlgorithm`, `docType`, `valueDigests`, `deviceKeyInfo`, `validityInfo`. Signed via `issuerAuth`.
- **valueDigests** — map in the MSO of salted SHA-256 hashes of *every* attribute, indexed by namespace and `digestID`. Basis of selective disclosure.
- **issuerAuth** — `COSE_Sign1` structure over the MSO; its header carries the document-signer certificate (`x5chain`).
- **deviceKeyInfo / deviceKey** — the device public key (usually P-256) the credential is bound to; used to verify `deviceAuth`.
- **validityInfo** — signed timestamps: `signed`, `validFrom`, `validUntil`.
- **age_over_NN** — discrete boolean attributes (`age_over_18`, `age_over_21`, …) in the mDL namespace. PAVEL requests the specific one matching `minAge`. Note: it's a *set of booleans*, not a range query.

## Cryptography

- **CBOR (Concise Binary Object Representation)** — the binary serialization (RFC 8949) used for mdoc.
- **COSE (CBOR Object Signing and Encryption)** — signing/encryption over CBOR (RFC 9052). `COSE_Sign1` = single-signer signature, used for both `issuerAuth` and `deviceAuth`.
- **Selective disclosure** — revealing only chosen attributes while the issuer's signature still covers them, via the salted-hash `valueDigests` commitment.
- **Holder binding** — cryptographic proof that the presenter controls the device the credential was issued to (via `deviceAuth`), defeating copied credentials.
- **SessionTranscript** — the data structure `deviceAuth` signs over, incorporating the verifier's **nonce** and the **origin**. Provides freshness (anti-replay) and audience binding (anti-relay/phishing).
- **nonce** — single-use, server-minted random challenge bound to the session; consumed on verify.
- **ZKP (Zero-Knowledge Proof)** — proof of a statement revealing nothing beyond its truth. PAVEL's stretch goal uses one to also hide the issuer signature (unlinkability).
- **Longfellow-ZK** — Google's open-source (Apache-2.0) ZK library for identity protocols; the basis of PAVEL's unlinkability stretch objective.

## Trust / PKI

- **Issuer / Issuing Authority** — the entity that signs credentials (e.g. a state DMV).
- **IACA (Issuing Authority Certificate Authority)** — the issuer's root CA. Verifiers trust an IACA; document-signer certs chain to it. PAVEL's trust anchor.
- **Document Signer (DS)** — the certificate/key that actually signs the MSO, issued under the IACA and carried in the `issuerAuth` `x5chain` header.
- **Trust anchor** — a configured IACA the verifier is willing to trust. Mock in dev, real authority in prod. PAVEL ships no implicit trust.
- **Relying Party (RP) / Verifier** — the party requesting and checking a presentation. PAVEL is a verifier toolkit. Accepting *real* consumer wallets requires RP registration (out of scope).

## PAVEL-specific

- **`requireAgeProof({ minAge })`** — the Express middleware that gates a route on the session's verified flag.
- **The ceremony** — the `GET /pavel/request` → `navigator.credentials.get()` → `POST /pavel/verify` round-trip that establishes the flag.
- **`pavel-core`** — framework-agnostic package: request building + verification pipeline.
- **`pavel-authority`** — test-only tool that plays mock IACA + issuer, minting mDLs for the emulator and exporting the trust anchor.
- **CMWallet** — Google's open-source sample wallet app used in the Android emulator to hold the mock mDL during testing.
- **Verification outcomes** — `verified` | `predicate_false` | `predicate_unavailable` | `untrusted_issuer` | `expired` | `replay` | `malformed`.
