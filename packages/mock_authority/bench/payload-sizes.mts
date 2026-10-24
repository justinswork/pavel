/**
 * Payload sizes for every message PAVEL exchanges, per protocol.
 *
 * Requests are what /pavel/request hands the browser (the DC-API `data`, JSON-serialized);
 * responses are what the wallet returns. Mock credentials carry only a handful of claims, so
 * real-wallet responses are larger (more digests in the MSO, longer certificate chains).
 *
 * Run: pnpm --filter @justinswork/pavel-mock-authority bench:payloads
 */
import {
  buildAgeRequest,
  buildGoogleAgeRequest,
  buildIsoMdocAgeRequest,
  createGoogleReader,
} from '@justinswork/pavel-core';
import { MockAuthority, MockWallet } from '../src/index';

const ORIGIN = 'https://shop.example';
const NONCE = 'bench-nonce-0123456789abcdef';
const SAMPLE_METADATA = 'c2FtcGxlLWd3LXJwLW1ldGFkYXRh';

const bytes = (s: string) => Buffer.byteLength(s, 'utf8');
const json = (v: unknown) => bytes(JSON.stringify(v));

const authority = await MockAuthority.create();
const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
const { reader } = await createGoogleReader({ commonName: 'PAVEL Bench Reader' });

const oid4vp = buildAgeRequest({ minAge: 21, nonce: NONCE, origin: ORIGIN });
const isoUnsigned = await buildIsoMdocAgeRequest({ minAge: 21 });
const isoSigned = await buildIsoMdocAgeRequest({ minAge: 21, reader, origin: ORIGIN });
const google = await buildGoogleAgeRequest({ minAge: 21, nonce: NONCE, origin: ORIGIN, reader, gwRpMetadataBytes: SAMPLE_METADATA });

const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });
const isoResponse = await wallet.presentIso({
  encryptionInfoBase64Url: isoUnsigned.encryptionInfoBase64Url,
  origin: ORIGIN,
  disclose: ['age_over_21'],
});
const { d: _d, ...encPub } = google.encryptionPrivateKeyJwk;
const googleResponse = await wallet.presentGoogle({ origin: ORIGIN, nonce: NONCE, encryptionPublicJwk: encPub, disclose: ['age_over_21'] });

const allThree = { requests: [
  { protocol: google.protocol, data: google.data },
  { protocol: 'openid4vp-v1-unsigned', data: oid4vp },
  { protocol: 'org-iso-mdoc', data: isoUnsigned.data },
] };

console.table([
  { message: 'Request: openid4vp-v1-unsigned (Chrome)', bytes: json(oid4vp) },
  { message: 'Request: org-iso-mdoc, unsigned (Safari)', bytes: json(isoUnsigned.data) },
  { message: 'Request: org-iso-mdoc, signed for Apple (1 cert)', bytes: json(isoSigned.data) },
  { message: 'Request: openid4vp-v1-signed (Google, 1 cert)', bytes: json(google.data) },
  { message: 'Request: full /pavel/request body (all three)', bytes: json(allThree) },
  { message: 'Response: openid4vp vp_token (base64url mdoc)', bytes: bytes(vpToken) },
  { message: 'Response: org-iso-mdoc HPKE-encrypted (base64url)', bytes: bytes(isoResponse) },
  { message: 'Response: Google JWE (compact)', bytes: bytes(googleResponse) },
]);
