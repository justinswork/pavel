/**
 * Chunk 1 of the Google Wallet "real ID" path: the signed (JAR) request builder.
 *
 * We can't exercise a real wallet offline, but we CAN prove the request is well-formed
 * and genuinely signed: generate a throwaway P-256 reader cert, build the request, then
 * decode + signature-verify the JAR JWT and assert every field Google requires.
 */
import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import * as x509 from '@peculiar/x509';
import { decodeJwt, decodeProtectedHeader, importX509, jwtVerify } from 'jose';
import { buildGoogleAgeRequest } from '../src/google-openid4vp';
import { MDL_DOCTYPE, MDL_NAMESPACE } from '../src/backend';

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

const ORIGIN = 'https://shop.example';
const SAMPLE_METADATA = 'c2FtcGxlLWd3LXJwLW1ldGFkYXRh'; // stand-in sandbox gw_rp_metadata_bytes

/** Mint a throwaway self-signed P-256 reader cert + its PKCS#8 PEM. */
async function makeReader() {
  const keys = (await webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])) as webcrypto.CryptoKeyPair;
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: 'CN=PAVEL Test Reader',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 86_400_000),
    keys,
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
  });
  const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const pem = `-----BEGIN PRIVATE KEY-----\n${(Buffer.from(pkcs8).toString('base64').match(/.{1,64}/g) ?? []).join('\n')}\n-----END PRIVATE KEY-----`;
  const certB64 = Buffer.from(new Uint8Array(cert.rawData)).toString('base64');
  return { privateKeyPkcs8Pem: pem, certChainB64: [certB64], certPem: cert.toString('pem') };
}

describe('buildGoogleAgeRequest (signed JAR request)', () => {
  it('produces a signed JWT with the Google-required header and claims', async () => {
    const reader = await makeReader();
    const built = await buildGoogleAgeRequest({
      minAge: 21,
      nonce: 'nonce-abc',
      origin: ORIGIN,
      reader,
      gwRpMetadataBytes: SAMPLE_METADATA,
    });

    expect(built.protocol).toBe('openid4vp-v1-signed');
    const jwt = built.data.request;

    // Header: JAR type + x5c carrying the reader cert.
    const header = decodeProtectedHeader(jwt);
    expect(header.alg).toBe('ES256');
    expect(header.typ).toBe('oauth-authz-req+jwt');
    expect(header.x5c).toEqual(reader.certChainB64);

    // Signature actually verifies under the cert's public key.
    const pub = await importX509(reader.certPem, 'ES256');
    await expect(jwtVerify(jwt, pub)).resolves.toBeDefined();

    // Payload: every field Google needs.
    const p = decodeJwt(jwt) as Record<string, any>;
    expect(p.response_type).toBe('vp_token');
    expect(p.response_mode).toBe('dc_api.jwt');
    expect(p.client_id).toMatch(/^x509_hash:/);
    expect(p.nonce).toBe('nonce-abc');
    expect(p.expected_origins).toEqual([ORIGIN]);
    expect(p.dcql_query.credentials[0].meta.doctype_value).toBe(MDL_DOCTYPE);
    expect(p.dcql_query.credentials[0].claims[0].path).toEqual([MDL_NAMESPACE, 'age_over_21']);
    expect(p.client_metadata.gw_rp_metadata_bytes).toBe(SAMPLE_METADATA);
    const encKey = p.client_metadata.jwks.keys[0];
    expect(encKey.use).toBe('enc');
    expect(encKey.crv).toBe('P-256');
    expect(encKey.d).toBeUndefined(); // only the PUBLIC half is published
  });

  it('keeps the encryption private key server-side with a 32-byte thumbprint', async () => {
    const reader = await makeReader();
    const built = await buildGoogleAgeRequest({
      minAge: 18,
      nonce: 'n2',
      origin: ORIGIN,
      reader,
      gwRpMetadataBytes: SAMPLE_METADATA,
    });
    expect(built.encryptionPrivateKeyJwk.d).toBeTypeOf('string'); // private component present
    expect(built.encryptionJwkThumbprint).toHaveLength(32); // raw SHA-256 digest
  });

  it('rejects an invalid minAge', async () => {
    const reader = await makeReader();
    await expect(
      buildGoogleAgeRequest({ minAge: 0, nonce: 'n', origin: ORIGIN, reader, gwRpMetadataBytes: SAMPLE_METADATA }),
    ).rejects.toThrow();
  });
});
