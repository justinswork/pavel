/**
 * Reader authentication for ISO 18013-7 Annex C (org-iso-mdoc) requests — what Apple Wallet
 * requires before it will release a real ID to a website.
 *
 * Apple expects the ISO 18013-5 SECOND-edition request: the reader signs the whole request
 * into `readerAuthAll`, and the request's version becomes "1.1". For first-edition mdocs we
 * also sign each DocRequest's `readerAuth` with the same key.
 *
 *   ReaderAuthenticationAll = [ "ReaderAuthenticationAll", SessionTranscript,
 *                               [ ItemsRequestBytes, ... ], DeviceRequestInfoBytes / null ]
 *   ReaderAuthentication    = [ "ReaderAuthentication", SessionTranscript, ItemsRequestBytes ]
 *
 * Each is wrapped as #6.24(bstr) and signed as a COSE_Sign1 with a detached payload, ES256,
 * and the reader certificate chain in the unprotected x5chain header (label 33).
 *
 * @owf/mdoc 0.7.0 only models first-edition requests, so the second-edition map is assembled
 * here. The ItemsRequestBytes are reused verbatim from the request, so the signatures cover
 * exactly the bytes that are sent.
 */
import { webcrypto } from 'node:crypto';
import { cborDecode, cborEncode, type SessionTranscript } from '@owf/mdoc';

/** The reader's signing identity: an ES256 key and its certificate chain (leaf first). */
export interface IsoReaderIdentity {
  /** Reader private key as PKCS#8 PEM (P-256). */
  privateKeyPkcs8Pem: string;
  /** Reader certificate chain as base64 DER, leaf first. */
  certChainB64: string[];
}

const COSE_ALG_ES256 = -7;
const COSE_HEADER_ALG = 1;
const COSE_HEADER_X5CHAIN = 33;

/** Wrap already-encoded CBOR as #6.24(bstr .cbor ...). */
export function tag24(encoded: Uint8Array): Uint8Array {
  const bstr = cborEncode(encoded);
  const out = new Uint8Array(2 + bstr.length);
  out.set([0xd8, 0x18]);
  out.set(bstr, 2);
  return out;
}

function pemToDerBytes(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/g, '').replace(/-----END [^-]+-----/g, '').replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

async function importSigningKey(pkcs8Pem: string): Promise<webcrypto.CryptoKey> {
  return webcrypto.subtle.importKey('pkcs8', pemToDerBytes(pkcs8Pem), { name: 'ECDSA', namedCurve: 'P-256' }, false, [
    'sign',
  ]);
}

/** COSE_Sign1 (untagged) over a detached payload: [protected, unprotected, null, signature]. */
async function coseSign1Detached(
  key: webcrypto.CryptoKey,
  x5chain: Uint8Array | Uint8Array[],
  payload: Uint8Array,
): Promise<unknown[]> {
  const protectedBytes = cborEncode(new Map([[COSE_HEADER_ALG, COSE_ALG_ES256]]));
  const sigStructure = cborEncode(['Signature1', protectedBytes, new Uint8Array(0), payload]);
  // WebCrypto ECDSA returns the raw r||s form COSE expects.
  const signature = new Uint8Array(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, sigStructure));
  return [protectedBytes, new Map([[COSE_HEADER_X5CHAIN, x5chain]]), null, signature];
}

/**
 * Sign an encoded first-edition DeviceRequest for the given session transcript, returning the
 * second-edition (version "1.1") request with `readerAuthAll` plus per-DocRequest `readerAuth`.
 */
export async function signIsoDeviceRequest(params: {
  deviceRequest: Uint8Array;
  sessionTranscript: SessionTranscript;
  reader: IsoReaderIdentity;
}): Promise<Uint8Array> {
  const certs = params.reader.certChainB64.map((c) => new Uint8Array(Buffer.from(c, 'base64')));
  if (certs.length === 0) throw new Error('reader certificate chain is required');
  const x5chain = certs.length === 1 ? certs[0]! : certs;
  const key = await importSigningKey(params.reader.privateKeyPkcs8Pem);

  const request = cborDecode(params.deviceRequest) as Map<string, unknown>;
  const docRequests = request.get('docRequests') as Array<Map<string, unknown>>;
  const transcript = cborDecode(params.sessionTranscript.encode());

  // First edition: each DocRequest signed on its own.
  const signedDocRequests: Array<Map<string, unknown>> = [];
  for (const docRequest of docRequests) {
    const itemsRequest = docRequest.get('itemsRequest');
    const readerAuthentication = cborEncode(['ReaderAuthentication', transcript, itemsRequest]);
    signedDocRequests.push(
      new Map<string, unknown>([
        ['itemsRequest', itemsRequest],
        ['readerAuth', await coseSign1Detached(key, x5chain, tag24(readerAuthentication))],
      ]),
    );
  }

  // Second edition: the whole request signed once (no DeviceRequestInfo → null).
  const readerAuthenticationAll = cborEncode([
    'ReaderAuthenticationAll',
    transcript,
    docRequests.map((d) => d.get('itemsRequest')),
    null,
  ]);
  const readerAuthAll = await coseSign1Detached(key, x5chain, tag24(readerAuthenticationAll));

  return cborEncode(
    new Map<string, unknown>([
      ['version', '1.1'],
      ['docRequests', signedDocRequests],
      ['readerAuthAll', [readerAuthAll]],
    ]),
  );
}
