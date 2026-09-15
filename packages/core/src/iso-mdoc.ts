/**
 * ISO 18013-7 Annex C ("org-iso-mdoc") DC-API path — the protocol Safari speaks.
 *
 * Unlike OpenID4VP, this transport encrypts the response:
 *   - the verifier sends a CBOR DeviceRequest + an EncryptionInfo carrying a reader
 *     ephemeral public key + nonce;
 *   - the wallet HPKE-seals its DeviceResponse to that key (info = SessionTranscript);
 *   - the verifier HPKE-opens it and verifies the plaintext DeviceResponse.
 *
 *   EncryptionInfo   = ["dcapi", { nonce: bstr, recipientPublicKey: COSE_Key }]
 *   EncryptedResponse = ["dcapi", { enc: bstr, cipherText: bstr }]
 *
 * @owf/mdoc gives us only the transcript (forIsoMdocDcApi); the request assembly,
 * COSE_Key/EncryptionInfo encoding, and HPKE are ours (hpke.ts, verify-shared.ts).
 */
import { webcrypto } from 'node:crypto';
import {
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  ItemsRequest,
  SessionTranscript,
  cborDecode,
  cborEncode,
} from '@owf/mdoc';
import { MDL_DOCTYPE, MDL_NAMESPACE } from './backend';
import { mdocContext } from './mdoc-context';
import { hpkeOpen, hpkeSeal } from './hpke';
import { agePredicate, assertValidMinAge } from './request';
import { outcomeFor } from './pipeline';
import type { VerifyResult } from './types';
import { NOT_DECODED, pemToDer, verifyDecodedResponse } from './verify-shared';

const b64urlToBytes = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));
const bytesToB64url = (b: Uint8Array): string => Buffer.from(b).toString('base64url');

export interface IsoMdocRequestData {
  /** base64url CBOR DeviceRequest. */
  deviceRequest: string;
  /** base64url CBOR EncryptionInfo. */
  encryptionInfo: string;
}

export interface BuiltIsoMdocRequest {
  /** The `data` for the DC-API `org-iso-mdoc` request entry. */
  data: IsoMdocRequestData;
  /** Reader ephemeral private key (JWK) — keep server-side to decrypt the response. */
  ephemeralPrivateKeyJwk: Record<string, unknown>;
  /** The exact EncryptionInfo string — needed again to rebuild the transcript on verify. */
  encryptionInfoBase64Url: string;
}

/** COSE_Key (EC2, P-256, public) as a CBOR map for embedding in EncryptionInfo. */
function coseKeyEc2Public(jwk: Record<string, unknown>): Map<number, unknown> {
  return new Map<number, unknown>([
    [1, 2], // kty: EC2
    [-1, 1], // crv: P-256
    [-2, b64urlToBytes(jwk.x as string)], // x
    [-3, b64urlToBytes(jwk.y as string)], // y
  ]);
}

/**
 * Build the `org-iso-mdoc` request for an age predicate, generating the reader
 * ephemeral key + nonce and encoding the DeviceRequest and EncryptionInfo.
 */
export async function buildIsoMdocAgeRequest(params: {
  minAge: number;
  nonce?: Uint8Array;
}): Promise<BuiltIsoMdocRequest> {
  assertValidMinAge(params.minAge);
  const nonce = params.nonce ?? webcrypto.getRandomValues(new Uint8Array(16));

  const keyPair = (await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])) as webcrypto.CryptoKeyPair;
  const publicKeyJwk = (await webcrypto.subtle.exportKey('jwk', keyPair.publicKey)) as unknown as Record<
    string,
    unknown
  >;
  const ephemeralPrivateKeyJwk = (await webcrypto.subtle.exportKey('jwk', keyPair.privateKey)) as unknown as Record<
    string,
    unknown
  >;

  const encryptionInfoBytes = cborEncode([
    'dcapi',
    new Map<string, unknown>([
      ['nonce', nonce],
      ['recipientPublicKey', coseKeyEc2Public(publicKeyJwk)],
    ]),
  ]);
  const encryptionInfoBase64Url = bytesToB64url(encryptionInfoBytes);

  const deviceRequestBytes = DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({
          docType: MDL_DOCTYPE,
          namespaces: { [MDL_NAMESPACE]: { [agePredicate(params.minAge)]: false } },
        }),
      }),
    ],
  }).encode();

  return {
    data: { deviceRequest: bytesToB64url(deviceRequestBytes), encryptionInfo: encryptionInfoBase64Url },
    ephemeralPrivateKeyJwk,
    encryptionInfoBase64Url,
  };
}

/** Read a field from a decoded CBOR value that may be a Map or a plain object. */
function getField(container: unknown, ...keys: string[]): unknown {
  if (container instanceof Map) {
    for (const k of keys) if (container.has(k)) return container.get(k);
  } else if (container && typeof container === 'object') {
    const obj = container as Record<string, unknown>;
    for (const k of keys) if (k in obj) return obj[k];
  }
  return undefined;
}

/** Pull { enc, ciphertext } out of whatever shape the wallet's response arrives in. */
export function parseEncryptedResponse(data: unknown): { enc: Uint8Array; ciphertext: Uint8Array } {
  let bytes: Uint8Array | undefined;
  if (typeof data === 'string') {
    bytes = b64urlToBytes(data);
  } else if (data && typeof data === 'object') {
    const inner = getField(data, 'response', 'Response', 'data', 'vp_token');
    if (typeof inner === 'string') bytes = b64urlToBytes(inner);
  }
  if (!bytes) throw new Error('unrecognized encrypted response shape');

  const decoded = cborDecode(bytes) as unknown;
  // EncryptedResponse = ["dcapi", { enc, cipherText }] — tolerate a bare params map too.
  const paramsMap = Array.isArray(decoded) && decoded.length >= 2 ? decoded[1] : decoded;
  const enc = getField(paramsMap, 'enc');
  const ciphertext = getField(paramsMap, 'cipherText', 'ciphertext', 'cipher_text');
  if (!(enc instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) {
    throw new Error('missing enc/cipherText in encrypted response');
  }
  return { enc, ciphertext };
}

/** Dev aid: log the DeviceResponse's issuer cert chain (x5chain) as PEM. */
function logIssuerChainPem(response: DeviceResponse): void {
  try {
    const chain = response.documents?.[0]?.issuerSigned.issuerAuth.x5chain ?? [];
    for (const der of chain) {
      const b64 = (Buffer.from(der).toString('base64').match(/.{1,64}/g) ?? []).join('\n');
      console.log(`[pavel iso issuer cert]\n-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`);
    }
  } catch {
    /* dev aid only */
  }
}

/** Read a key that may be a number or string, from a decoded Map or plain object. */
function readKey(container: unknown, key: number | string): unknown {
  if (container instanceof Map) {
    if (container.has(key)) return container.get(key);
    return container.get(String(key));
  }
  if (container && typeof container === 'object') {
    const obj = container as Record<string, unknown>;
    return obj[key as keyof typeof obj] ?? obj[String(key)];
  }
  return undefined;
}

/** Recover the reader's public key (as a JWK) from an EncryptionInfo's COSE_Key. */
function recipientPublicKeyFromEncryptionInfo(encryptionInfoBase64Url: string): Record<string, unknown> {
  const decoded = cborDecode(b64urlToBytes(encryptionInfoBase64Url)) as unknown;
  const paramsMap = Array.isArray(decoded) && decoded.length >= 2 ? decoded[1] : decoded;
  const coseKey = readKey(paramsMap, 'recipientPublicKey');
  const x = readKey(coseKey, -2);
  const y = readKey(coseKey, -3);
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array)) {
    throw new Error('EncryptionInfo missing recipient public key coordinates');
  }
  return { kty: 'EC', crv: 'P-256', x: bytesToB64url(x), y: bytesToB64url(y) };
}

/**
 * Holder/test counterpart of the verify path: HPKE-seal a raw DeviceResponse to the
 * reader key in EncryptionInfo and wrap it as an EncryptedResponse (base64url). Used
 * by the mock wallet to exercise the whole ISO round-trip without a real device.
 */
export async function sealIsoMdocResponse(params: {
  deviceResponseBytes: Uint8Array;
  encryptionInfoBase64Url: string;
  origin: string;
}): Promise<string> {
  const transcript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: params.encryptionInfoBase64Url, origin: params.origin },
    mdocContext,
  );
  const { enc, ciphertext } = await hpkeSeal({
    recipientPublicKeyJwk: recipientPublicKeyFromEncryptionInfo(params.encryptionInfoBase64Url),
    info: transcript.encode(),
    plaintext: params.deviceResponseBytes,
  });
  const envelope = cborEncode([
    'dcapi',
    new Map<string, unknown>([
      ['enc', enc],
      ['cipherText', ciphertext],
    ]),
  ]);
  return bytesToB64url(envelope);
}

/**
 * Verify an ISO 18013-7 Annex C encrypted presentation end to end: rebuild the
 * transcript, HPKE-open the response, decode, and run the shared verifier.
 */
export async function verifyIsoMdocPresentation(params: {
  encryptedResponse: unknown;
  ephemeralPrivateKeyJwk: Record<string, unknown>;
  encryptionInfoBase64Url: string;
  expectedOrigin: string;
  minAge: number;
  trustAnchors: string[];
}): Promise<VerifyResult> {
  const transcript = await SessionTranscript.forIsoMdocDcApi(
    { encryptionInfoBase64Url: params.encryptionInfoBase64Url, origin: params.expectedOrigin },
    mdocContext,
  );

  let response: DeviceResponse;
  try {
    const { enc, ciphertext } = parseEncryptedResponse(params.encryptedResponse);
    const plaintext = await hpkeOpen({
      recipientPrivateKeyJwk: params.ephemeralPrivateKeyJwk,
      enc,
      info: transcript.encode(),
      ciphertext,
    });
    response = DeviceResponse.decode(plaintext);
  } catch {
    // Couldn't decrypt or decode → treat as malformed (never reveals more).
    return outcomeFor({ ...NOT_DECODED }, params.minAge);
  }

  // Dev aid: with PAVEL_DEBUG_ISO_CERTS set, print the presented issuer cert chain as
  // PEM so a tester can pin an otherwise-untrusted wallet's root (e.g. Multipaz).
  if (typeof process !== 'undefined' && process.env?.PAVEL_DEBUG_ISO_CERTS) {
    logIssuerChainPem(response);
  }

  const raw = await verifyDecodedResponse({
    response,
    sessionTranscript: transcript,
    trustedIssuance: params.trustAnchors.map(pemToDer),
  });
  return outcomeFor(raw, params.minAge);
}
