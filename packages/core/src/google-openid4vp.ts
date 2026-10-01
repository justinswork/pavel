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
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, importPKCS8 } from 'jose';
import { MDL_DOCTYPE, MDL_NAMESPACE } from './backend';
import { agePredicate, assertValidMinAge } from './request';

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
