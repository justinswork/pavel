/**
 * Chunk 3: the sandbox reader cert + config seam. Proves createGoogleReader yields a
 * cert/key that drop straight into buildGoogleAgeRequest, and that the optional Google
 * reader-auth extension lands in the cert when requested.
 */
import 'reflect-metadata';
import { describe, it, expect } from 'vitest';
import * as x509 from '@peculiar/x509';
import { importX509, jwtVerify } from 'jose';
import { createGoogleReader, readerFromPem, GOOGLE_READER_EXTENSION_OID } from '../src/google-reader';
import { buildGoogleAgeRequest } from '../src/google-openid4vp';

const ORIGIN = 'https://shop.example';

describe('createGoogleReader (sandbox reader cert + seam)', () => {
  it('produces PEMs and a single-cert x5c chain', async () => {
    const { reader, privateKeyPkcs8Pem, certPem } = await createGoogleReader();
    expect(privateKeyPkcs8Pem).toContain('BEGIN PRIVATE KEY');
    expect(certPem).toContain('BEGIN CERTIFICATE');
    expect(reader.certChainB64).toHaveLength(1);
    expect(reader.certChainB64[0]).not.toContain('-----'); // bare base64 DER for x5c
  });

  it('is a drop-in for buildGoogleAgeRequest — the signed JWT verifies under the cert', async () => {
    const { reader, certPem } = await createGoogleReader();
    const built = await buildGoogleAgeRequest({
      minAge: 21,
      nonce: 'n',
      origin: ORIGIN,
      reader,
      gwRpMetadataBytes: 'c2FtcGxl',
    });
    const pub = await importX509(certPem, 'ES256');
    await expect(jwtVerify(built.data.request, pub)).resolves.toBeDefined();
  });

  it('embeds the Google reader-auth extension when supplied', async () => {
    const extValue = Buffer.from('placeholder-ext-value').toString('base64');
    const { certPem } = await createGoogleReader({ googleExtensionDerBase64: extValue });
    const cert = new x509.X509Certificate(certPem);
    expect(cert.extensions.some((e) => e.type === GOOGLE_READER_EXTENSION_OID)).toBe(true);
  });

  it('readerFromPem round-trips a cert PEM into bare base64 DER', async () => {
    const { certPem } = await createGoogleReader();
    const reader = readerFromPem('-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----', [certPem]);
    expect(reader.certChainB64[0]).toBe(
      certPem.replace(/-----BEGIN CERTIFICATE-----/g, '').replace(/-----END CERTIFICATE-----/g, '').replace(/\s+/g, ''),
    );
  });
});
