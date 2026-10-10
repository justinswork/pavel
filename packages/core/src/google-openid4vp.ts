/**
 * Google Wallet "real ID" path — signed + encrypted OpenID4VP 1.0 over the DC-API.
 *
 * Unlike the plain Chrome path (openid4vp-v1-unsigned) and the Safari path
 * (org-iso-mdoc), production Google Wallet only releases a real credential to a
 * REGISTERED reader whose request is signed (JAR) and whose response is encrypted:
 *
 *   request  protocol = "openid4vp-v1-signed"
 *            data     = { request: <JAR JWT> }
 *     JWT header  = { alg: ES256, typ: oauth-authz-req+jwt, kid, x5c: [readerCertDER…] }
 *     JWT payload = OpenID4VP params + client_metadata{ jwks, vp_formats_supported,
 *                   gw_rp_metadata_bytes }, response_mode = "dc_api.jwt"
 *   response = JWE (ECDH-ES / A128GCM) wrapping { vp_token }
 *
 * This module builds + signs the request and generates the response-encryption key.
 * Verification (JWE open → decode → verify) lives in verifyGooglePresentation (next).
 *
 * Sandbox vs production differ by exactly two inputs: the reader cert (self-signed
 * for sandbox → Google-signed for prod) and gwRpMetadataBytes (sample → issued).
 * Everything here is identical across both, so the same code promotes to real IDs.
 */
import { createHash } from 'node:crypto';
import {
  SignJWT,
  calculateJwkThumbprint,
  compactDecrypt,
  exportJWK,
  generateKeyPair,
  importJWK,
  importPKCS8,
} from 'jose';
import { DeviceResponse, SessionTranscript } from '@owf/mdoc';
import { MDL_DOCTYPE, MDL_NAMESPACE } from './backend';
import { mdocContext } from './mdoc-context';
import { agePredicate, assertValidMinAge } from './request';
import { outcomeFor } from './pipeline';
import type { VerifyResult } from './types';
import { NOT_DECODED, pemToDer, verifyDecodedResponse } from './verify-shared';

/** The registered reader's signing identity (what goes in the JAR + x5c). */
export interface GoogleReaderIdentity {
  /** Reader private key as PKCS#8 PEM (ES256 / P-256) — signs the JAR JWT. */
  privateKeyPkcs8Pem: string;
  /** Reader certificate chain as base64 DER (RFC 7515 x5c order: leaf first). */
  certChainB64: string[];
  /** Optional JWT header `kid`. */
  kid?: string;
}

export interface BuildGoogleRequestParams {
  minAge: number;
  /** Server-minted, single-use nonce. */
  nonce: string;
  /** The registered RP origin, e.g. https://shop.example (goes in expected_origins). */
  origin: string;
  reader: GoogleReaderIdentity;
  /** base64url RP metadata from Google (sandbox sample string or production value). */
  gwRpMetadataBytes: string;
  /**
   * Reuse a fixed response-encryption key (JWK) instead of generating one. Handy for
   * tests; in production a fresh key per request is fine (keep the private half server-side).
   */
  encryptionPrivateKeyJwk?: Record<string, unknown>;
  /**
   * client_metadata.vp_formats_supported. Defaults to a minimal mso_mdoc entry.
   * CONFIRM the exact shape Google expects against the sandbox before go-live.
   */
  vpFormatsSupported?: Record<string, unknown>;
}

export interface BuiltGoogleRequest {
  protocol: 'openid4vp-v1-signed';
  /** The DC-API request `data`: the signed JAR JWT under `request`. */
  data: { request: string };
  /** Keep server-side — needed to decrypt the JWE response. */
  encryptionPrivateKeyJwk: Record<string, unknown>;
  /** Raw SHA-256 JWK thumbprint of the encryption key — bound into the transcript on verify. */
  encryptionJwkThumbprint: Uint8Array;
  nonce: string;
}

const b64urlToBytes = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, 'base64url'));

/** client_id per Google: "x509_hash:<base64url( SHA-256(leaf cert DER) )>". */
function x509HashClientId(leafCertB64: string): string {
  const der = Buffer.from(leafCertB64, 'base64');
  const fp = createHash('sha256').update(der).digest();
  return `x509_hash:${fp.toString('base64url')}`;
}

/**
 * Build and sign the Google Wallet OpenID4VP request for an age predicate, generating
 * the response-encryption key and binding everything the verify step will need.
 */
export async function buildGoogleAgeRequest(params: BuildGoogleRequestParams): Promise<BuiltGoogleRequest> {
  assertValidMinAge(params.minAge);
  if (!params.nonce) throw new Error('nonce is required');
  if (!params.origin) throw new Error('origin is required');
  const leafCertB64 = params.reader?.certChainB64?.[0];
  if (!leafCertB64) throw new Error('reader certificate chain is required');

  // Response-encryption key: reuse the supplied one or mint a fresh P-256 ECDH key.
  let encPrivJwk: Record<string, unknown>;
  let encPubJwk: Record<string, unknown>;
  if (params.encryptionPrivateKeyJwk) {
    encPrivJwk = params.encryptionPrivateKeyJwk;
    const { d: _d, ...pub } = encPrivJwk as Record<string, unknown>;
    encPubJwk = pub;
  } else {
    const { publicKey, privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    encPrivJwk = (await exportJWK(privateKey)) as Record<string, unknown>;
    encPubJwk = (await exportJWK(publicKey)) as Record<string, unknown>;
  }
  // Thumbprint over the public JWK; the handover carries the raw digest bytes.
  const thumbB64url = await calculateJwkThumbprint(encPubJwk as Parameters<typeof calculateJwkThumbprint>[0], 'sha256');
  const encryptionJwkThumbprint = b64urlToBytes(thumbB64url);

  const encKid = 'enc-1';
  const signingKey = await importPKCS8(params.reader.privateKeyPkcs8Pem, 'ES256');

  const payload = {
    response_type: 'vp_token',
    response_mode: 'dc_api.jwt',
    client_id: x509HashClientId(leafCertB64),
    nonce: params.nonce,
    expected_origins: [params.origin],
    dcql_query: {
      credentials: [
        {
          id: 'age_check',
          format: 'mso_mdoc',
          meta: { doctype_value: MDL_DOCTYPE },
          claims: [{ path: [MDL_NAMESPACE, agePredicate(params.minAge)], intent_to_retain: false }],
        },
      ],
    },
    client_metadata: {
      jwks: { keys: [{ ...encPubJwk, use: 'enc', alg: 'ECDH-ES', kid: encKid }] },
      vp_formats_supported: params.vpFormatsSupported ?? { mso_mdoc: {} },
      gw_rp_metadata_bytes: params.gwRpMetadataBytes,
    },
  };

  const request = await new SignJWT(payload)
    .setProtectedHeader({
      alg: 'ES256',
      typ: 'oauth-authz-req+jwt',
      kid: params.reader.kid ?? '1',
      x5c: params.reader.certChainB64,
    })
    .sign(signingKey);

  // NOTE: `data` wraps the JWT as { request } for signed (JAR) requests — confirm
  // against the Google sandbox, which is the authority on the exact wrapper.
  return {
    protocol: 'openid4vp-v1-signed',
    data: { request },
    encryptionPrivateKeyJwk: encPrivJwk,
    encryptionJwkThumbprint,
    nonce: params.nonce,
  };
}

/** Read a field from a Map or plain object. */
function getField(container: unknown, ...keys: string[]): unknown {
  if (container instanceof Map) {
    for (const k of keys) if (container.has(k)) return container.get(k);
  } else if (container && typeof container === 'object') {
    const obj = container as Record<string, unknown>;
    for (const k of keys) if (k in obj) return obj[k];
  }
  return undefined;
}

/** A compact JWE has exactly five base64url segments separated by dots. */
function looksLikeCompactJwe(s: string): boolean {
  return s.split('.').length === 5;
}

/** Pull the compact-JWE string out of whatever wrapper the response arrives in. */
function extractJweCompact(data: unknown): string {
  if (typeof data === 'string') {
    if (!looksLikeCompactJwe(data)) throw new Error('response is not a compact JWE');
    return data;
  }
  const inner = getField(data, 'response', 'Response', 'data', 'vp_token');
  if (typeof inner === 'string' && looksLikeCompactJwe(inner)) return inner;
  throw new Error('no compact JWE found in response');
}

/**
 * Extract the base64url mdoc from a decrypted `vp_token`. Per DCQL it's keyed by the
 * credential id (we use "age_check") → array of presentations; tolerate a bare string
 * or array too.
 */
function extractMdocFromVpToken(vpToken: unknown): string {
  if (typeof vpToken === 'string') return vpToken;
  if (Array.isArray(vpToken)) {
    const first = vpToken[0];
    if (typeof first === 'string') return first;
  }
  if (vpToken && typeof vpToken === 'object') {
    const first = Object.values(vpToken as Record<string, unknown>)[0];
    if (typeof first === 'string') return first;
    if (Array.isArray(first) && typeof first[0] === 'string') return first[0];
  }
  throw new Error('no mdoc presentation in vp_token');
}

/**
 * Verify a Google Wallet signed/encrypted OpenID4VP presentation end to end: derive the
 * encryption-key thumbprint, rebuild the DC-API transcript (origin + nonce + thumbprint),
 * JWE-decrypt the response, decode the vp_token, and run the shared verifier.
 */
export async function verifyGooglePresentation(params: {
  /** The wallet's encrypted response: a compact JWE string, or a wrapper holding one. */
  encryptedResponse: unknown;
  /** The encryption private key returned by buildGoogleAgeRequest (kept server-side). */
  encryptionPrivateKeyJwk: Record<string, unknown>;
  /** The registered RP origin the presentation must be bound to. */
  expectedOrigin: string;
  /** The nonce minted for this ceremony. */
  nonce: string;
  minAge: number;
  /** Trusted IACA roots (PEM). */
  trustAnchors: string[];
}): Promise<VerifyResult> {
  // The transcript binds the SAME encryption-key thumbprint the request advertised.
  const { d: _d, ...pubJwk } = params.encryptionPrivateKeyJwk;
  const thumbB64url = await calculateJwkThumbprint(pubJwk as Parameters<typeof calculateJwkThumbprint>[0], 'sha256');
  const sessionTranscript = await SessionTranscript.forOid4VpDcApi(
    { origin: params.expectedOrigin, nonce: params.nonce, jwkThumbprint: b64urlToBytes(thumbB64url) },
    mdocContext,
  );

  const debug = typeof process !== 'undefined' && !!process.env?.PAVEL_DEBUG_GOOGLE;

  let response: DeviceResponse;
  try {
    const jwe = extractJweCompact(params.encryptedResponse);
    if (debug) console.log(`[pavel google] jwe compact length=${jwe.length}`);
    const key = await importJWK(params.encryptionPrivateKeyJwk, 'ECDH-ES');
    const { plaintext } = await compactDecrypt(jwe, key);
    if (debug) console.log(`[pavel google] jwe decrypted: plaintext=${plaintext.length}B`);
    const payload = JSON.parse(new TextDecoder().decode(plaintext)) as unknown;
    const mdocB64url = extractMdocFromVpToken(getField(payload, 'vp_token'));
    response = DeviceResponse.fromEncodedForOid4Vp(mdocB64url);
    if (debug) console.log(`[pavel google] decoded docType=${response.documents?.[0]?.docType}`);
  } catch (err) {
    // Couldn't decrypt or decode → malformed (never reveals more).
    if (debug) console.log(`[pavel google] decrypt/decode FAILED: ${(err as Error)?.message ?? err}`);
    return outcomeFor({ ...NOT_DECODED }, params.minAge);
  }

  // Dev aid: with PAVEL_DEBUG_ISO_CERTS set, print the presented issuer cert chain as PEM
  // so a tester can pin an otherwise-untrusted sandbox issuer.
  if (typeof process !== 'undefined' && process.env?.PAVEL_DEBUG_ISO_CERTS) {
    try {
      const chain = response.documents?.[0]?.issuerSigned.issuerAuth.x5chain ?? [];
      for (const der of chain) {
        const b64 = (Buffer.from(der).toString('base64').match(/.{1,64}/g) ?? []).join('\n');
        console.log(`[pavel google issuer cert]\n-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`);
      }
    } catch {
      /* dev aid only */
    }
  }

  const raw = await verifyDecodedResponse({
    response,
    sessionTranscript,
    trustedIssuance: params.trustAnchors.map(pemToDer),
  });
  if (debug) {
    const { ageClaims, ...flags } = raw;
    console.log(`[pavel google] verify flags: ${JSON.stringify(flags)} ageClaims=${JSON.stringify(ageClaims)}`);
  }
  return outcomeFor(raw, params.minAge);
}
