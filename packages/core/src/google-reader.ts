/**
 * Reader identity + config seam for the Google Wallet "real ID" path.
 *
 * The verify/build code (google-openid4vp.ts) is identical in sandbox and production;
 * only two inputs change — the reader certificate and gw_rp_metadata_bytes. This module
 * is that seam: generate a self-signed reader cert for the sandbox, load a Google-signed
 * one for production, and carry both (plus the metadata + origin) in one config object.
 */
import 'reflect-metadata'; // @peculiar/x509's tsyringe dependency needs this first
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import type { GoogleReaderIdentity } from './google-openid4vp';

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
const P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;

/** Google's custom reader-auth certificate extension OID. */
export const GOOGLE_READER_EXTENSION_OID = '1.3.6.1.4.1.11129.10.1';

/** Everything the Google path needs, bundled so sandbox→prod is a config swap. */
export interface GoogleVerifierConfig {
  /** The registered RP origin (goes in expected_origins), e.g. https://shop.example. */
  origin: string;
  /** The reader signing identity (sandbox self-signed, or Google-signed for production). */
  reader: GoogleReaderIdentity;
  /**
   * base64url RP metadata from Google — the SANDBOX SAMPLE string during testing, the
   * issued PRODUCTION string after registration. Deliberately not hard-coded: fetch the
   * current sandbox value from Google's sandbox docs so it can't silently go stale.
   */
  gwRpMetadataBytes: string;
}

function toPkcs8Pem(der: Uint8Array): string {
  const b64 = (Buffer.from(der).toString('base64').match(/.{1,64}/g) ?? []).join('\n');
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----`;
}

/** A certificate PEM's body IS the base64 DER that JOSE x5c wants. */
export function certPemToX5c(certPem: string): string {
  return certPem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
}

/** Build a reader identity from stored PEMs (private key + cert chain, leaf first). */
export function readerFromPem(privateKeyPkcs8Pem: string, certChainPem: string[]): GoogleReaderIdentity {
  return { privateKeyPkcs8Pem, certChainB64: certChainPem.map(certPemToX5c) };
}

export interface CreateReaderOptions {
  commonName?: string;
  validityDays?: number;
  /**
   * Include Google's reader-auth extension (OID 1.3.6.1.4.1.11129.10.1) with these DER
   * bytes (base64). On the INDIVIDUAL registration path Google signs your cert via CSR and
   * supplies this extension itself, so a self-signed sandbox cert normally omits it — leave
   * undefined unless the sandbox is found to require it.
   */
  googleExtensionDerBase64?: string;
}

/**
 * Generate a self-signed P-256 reader cert for SANDBOX use, returning the reader identity
 * plus PEMs to persist (reuse the same cert across restarts rather than regenerating).
 */
export async function createGoogleReader(
  options: CreateReaderOptions = {},
): Promise<{ reader: GoogleReaderIdentity; privateKeyPkcs8Pem: string; certPem: string }> {
  const keys = (await webcrypto.subtle.generateKey(P256, true, ['sign', 'verify'])) as webcrypto.CryptoKeyPair;

  const extensions: x509.Extension[] = [
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
  ];
  if (options.googleExtensionDerBase64) {
    extensions.push(
      new x509.Extension(
        GOOGLE_READER_EXTENSION_OID,
        false,
        Buffer.from(options.googleExtensionDerBase64, 'base64'),
      ),
    );
  }

  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${options.commonName ?? 'PAVEL Reader (sandbox)'}`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + (options.validityDays ?? 365) * 86_400_000),
    keys,
    signingAlgorithm: ES256,
    extensions,
  });

  const pkcs8 = new Uint8Array(await webcrypto.subtle.exportKey('pkcs8', keys.privateKey));
  const privateKeyPkcs8Pem = toPkcs8Pem(pkcs8);
  const certPem = cert.toString('pem');
  return { reader: readerFromPem(privateKeyPkcs8Pem, [certPem]), privateKeyPkcs8Pem, certPem };
}
