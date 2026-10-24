/**
 * Certificate-path hardening in mdocContext.x509.verifyCertificateChain: issuing certificates
 * must be CAs allowed to sign certificates, and every certificate in the path (trust anchor
 * included) must be inside its validity period.
 */
import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import * as x509 from '@peculiar/x509';
import { mdocContext } from '../src/mdoc-context';

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

const ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;
const DAY = 86_400_000;
const genKeys = () =>
  webcrypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']) as Promise<webcrypto.CryptoKeyPair>;
const der = (c: x509.X509Certificate) => new Uint8Array(c.rawData);

async function root(name: string, opts: { from?: number; to?: number } = {}) {
  const keys = await genKeys();
  const cert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name,
    notBefore: new Date(Date.now() + (opts.from ?? -DAY)),
    notAfter: new Date(Date.now() + (opts.to ?? 365 * DAY)),
    keys,
    signingAlgorithm: ALG,
    extensions: [
      new x509.BasicConstraintsExtension(true, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
    ],
  });
  return { keys, cert };
}

async function issued(subject: string, issuer: { keys: webcrypto.CryptoKeyPair; cert: x509.X509Certificate }, opts: { to?: number } = {}) {
  const keys = await genKeys();
  const cert = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject,
    issuer: issuer.cert.subject,
    notBefore: new Date(Date.now() - DAY),
    notAfter: new Date(Date.now() + (opts.to ?? 365 * DAY)),
    publicKey: keys.publicKey,
    signingKey: issuer.keys.privateKey,
    signingAlgorithm: ALG,
    extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)], // NOT a CA
  });
  return { keys, cert };
}

const verify = (x5chain: Uint8Array[], trustedCertificates: Uint8Array[]) =>
  Promise.resolve(mdocContext.x509.verifyCertificateChain({ x5chain, trustedCertificates }));

describe('verifyCertificateChain hardening', () => {
  it('accepts a document signer issued by a trusted CA root', async () => {
    const iaca = await root('CN=Test IACA, C=US');
    const ds = await issued('CN=Test DS, C=US', iaca);
    await expect(verify([der(ds.cert)], [der(iaca.cert)])).resolves.toBeDefined();
  });

  it('still accepts a pinned leaf certificate used as its own trust anchor', async () => {
    const iaca = await root('CN=Test IACA, C=US');
    const ds = await issued('CN=Pinned DS, C=US', iaca);
    await expect(verify([der(ds.cert)], [der(ds.cert)])).resolves.toBeDefined();
  });

  it('rejects a chain where a non-CA certificate issues another certificate', async () => {
    const iaca = await root('CN=Test IACA, C=US');
    const leaf = await issued('CN=Not A CA, C=US', iaca);
    const forged = await issued('CN=Forged DS, C=US', leaf);
    await expect(verify([der(forged.cert), der(leaf.cert)], [der(iaca.cert)])).rejects.toThrow(/not a CA/);
  });

  it('rejects an expired trust anchor', async () => {
    const expired = await root('CN=Expired IACA, C=US', { from: -400 * DAY, to: -DAY });
    const ds = await issued('CN=Test DS, C=US', expired);
    await expect(verify([der(ds.cert)], [der(expired.cert)])).rejects.toThrow(/validity period/);
  });

  it('rejects an expired document signer', async () => {
    const iaca = await root('CN=Test IACA, C=US');
    const ds = await issued('CN=Old DS, C=US', iaca, { to: -DAY });
    await expect(verify([der(ds.cert)], [der(iaca.cert)])).rejects.toThrow(/validity period/);
  });
});
