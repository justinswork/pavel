/**
 * Reader authentication for org-iso-mdoc requests (what Apple Wallet requires for real IDs).
 *
 * We can't reach Apple's verifier, so the signatures are checked independently of the signing
 * code: the per-DocRequest readerAuth by @owf/mdoc's own Holder.verifyDeviceRequest, and the
 * second-edition readerAuthAll by rebuilding ReaderAuthenticationAll here and verifying the
 * ECDSA signature with Node's crypto against the reader certificate.
 */
import 'reflect-metadata';
import { X509Certificate, verify as nodeVerify } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import { Holder, SessionTranscript, cborDecode, cborEncode } from '@owf/mdoc';
import { buildIsoMdocAgeRequest } from '../src/iso-mdoc';
import { createGoogleReader } from '../src/google-reader';
import { mdocContext } from '../src/mdoc-context';

const ORIGIN = 'https://shop.example';

const fromB64url = (s: string) => new Uint8Array(Buffer.from(s, 'base64url'));

/** Independent #6.24(bstr) encoder (hand-written header, not cborEncode). */
function tag24(b: Uint8Array): Uint8Array {
  const n = b.length;
  const head = n < 24 ? [0x40 + n] : n < 256 ? [0x58, n] : [0x59, n >> 8, n & 0xff];
  return Uint8Array.from([0xd8, 0x18, ...head, ...b]);
}

async function signedRequest(origin = ORIGIN) {
  const { reader, certPem } = await createGoogleReader({ commonName: 'PAVEL Test ISO Reader' });
  const built = await buildIsoMdocAgeRequest({ minAge: 21, reader, origin });
  const bytes = fromB64url(built.data.deviceRequest);
  return { built, bytes, request: cborDecode(bytes) as Map<string, any>, reader, certPem };
}

const transcriptFor = (encryptionInfoBase64Url: string, origin: string) =>
  SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext);

/** Verify readerAuthAll[0] against an independently rebuilt ReaderAuthenticationAll. */
function verifyReaderAuthAll(request: Map<string, any>, transcript: SessionTranscript, certPem: string): boolean {
  const [protectedBytes, , payload, signature] = request.get('readerAuthAll')[0];
  expect(payload).toBeNull(); // detached
  const items = (request.get('docRequests') as Array<Map<string, any>>).map((d) => d.get('itemsRequest'));
  const authAll = cborEncode(['ReaderAuthenticationAll', cborDecode(transcript.encode()), items, null]);
  const sigStructure = cborEncode(['Signature1', protectedBytes, new Uint8Array(0), tag24(authAll)]);
  const key = new X509Certificate(certPem).publicKey;
  return nodeVerify('sha256', sigStructure, { key, dsaEncoding: 'ieee-p1363' }, signature);
}

describe('org-iso-mdoc reader authentication (signed requests)', () => {
  it('leaves the request unsigned (version 1.0) when no reader is configured', async () => {
    const built = await buildIsoMdocAgeRequest({ minAge: 21 });
    const request = cborDecode(fromB64url(built.data.deviceRequest)) as Map<string, any>;
    expect(request.get('version')).toBe('1.0');
    expect(request.has('readerAuthAll')).toBe(false);
    expect(request.get('docRequests')[0].has('readerAuth')).toBe(false);
  });

  it('builds a second-edition (1.1) request with readerAuthAll, per-doc readerAuth, and the cert in x5chain', async () => {
    const { request, reader } = await signedRequest();
    expect(request.get('version')).toBe('1.1');
    const all = request.get('readerAuthAll');
    expect(all).toHaveLength(1);
    const [protectedBytes, unprotected] = all[0];
    expect(cborDecode(protectedBytes)).toEqual(new Map([[1, -7]])); // alg ES256
    expect(Buffer.from(unprotected.get(33)).toString('base64')).toBe(reader.certChainB64[0]);
    expect(request.get('docRequests')[0].has('readerAuth')).toBe(true);
  });

  it('readerAuthAll verifies over ReaderAuthenticationAll for this origin + encryption info', async () => {
    const { built, request, certPem } = await signedRequest();
    const transcript = await transcriptFor(built.encryptionInfoBase64Url, ORIGIN);
    expect(verifyReaderAuthAll(request, transcript, certPem)).toBe(true);
  });

  it('readerAuthAll does NOT verify for a different origin', async () => {
    const { built, request, certPem } = await signedRequest();
    const wrong = await transcriptFor(built.encryptionInfoBase64Url, 'https://evil.example');
    expect(verifyReaderAuthAll(request, wrong, certPem)).toBe(false);
  });

  it('readerAuthAll does NOT verify if the requested items are swapped', async () => {
    const { built, request, certPem } = await signedRequest();
    // Splice in the items request from an unsigned 18+ request, keeping the old signature.
    const other = cborDecode(fromB64url((await buildIsoMdocAgeRequest({ minAge: 18 })).data.deviceRequest)) as Map<
      string,
      any
    >;
    request.get('docRequests')[0].set('itemsRequest', other.get('docRequests')[0].get('itemsRequest'));
    const transcript = await transcriptFor(built.encryptionInfoBase64Url, ORIGIN);
    expect(verifyReaderAuthAll(request, transcript, certPem)).toBe(false);
  });

  it('per-doc readerAuth verifies with @owf/mdoc, including chain trust in the reader cert', async () => {
    const { built, bytes, reader } = await signedRequest();
    const transcript = await transcriptFor(built.encryptionInfoBase64Url, ORIGIN);
    await expect(Holder.verifyDeviceRequest({ deviceRequest: bytes, sessionTranscript: transcript }, mdocContext))
      .resolves.toBeUndefined();
    const anchor = new Uint8Array(Buffer.from(reader.certChainB64[0]!, 'base64'));
    await expect(
      Holder.verifyDeviceRequest(
        { deviceRequest: bytes, sessionTranscript: transcript, trustedCertificates: [anchor] },
        mdocContext,
      ),
    ).resolves.toBeUndefined();
  });

  it('per-doc readerAuth is rejected by @owf/mdoc for a different origin', async () => {
    const { built, bytes } = await signedRequest();
    const wrong = await transcriptFor(built.encryptionInfoBase64Url, 'https://evil.example');
    await expect(
      Holder.verifyDeviceRequest({ deviceRequest: bytes, sessionTranscript: wrong }, mdocContext),
    ).rejects.toThrow();
  });

  it('requires an origin when signing', async () => {
    const { reader } = await createGoogleReader();
    await expect(buildIsoMdocAgeRequest({ minAge: 21, reader })).rejects.toThrow(/origin/);
  });
});
