/**
 * End-to-end Google Wallet "real ID" path (signed/encrypted OpenID4VP) through the real
 * pavel-core verify path: build the signed request, have the mock wallet JWE-encrypt a real
 * DeviceResponse bound to the reader's encryption-key thumbprint, then decrypt + verify.
 * The mock wallet stands in for Google Wallet's OS wallet — no device needed.
 */
import 'reflect-metadata';
import { webcrypto } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import * as x509 from '@peculiar/x509';
import { MockAuthority, MockWallet, type IssueMdlOptions } from '../src/index';
import { buildGoogleAgeRequest, verifyGooglePresentation } from '@justinswork/pavel-core';

const ORIGIN = 'https://shop.example';
const METADATA = 'c2FtcGxlLWd3LXJwLW1ldGFkYXRh';

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
  return { privateKeyPkcs8Pem: pem, certChainB64: [Buffer.from(new Uint8Array(cert.rawData)).toString('base64')] };
}

const publicOf = (jwk: Record<string, unknown>) => {
  const { d: _d, ...pub } = jwk;
  return pub;
};

async function ceremony(
  authority: MockAuthority,
  opts: { issue?: IssueMdlOptions; disclose?: string[]; presentOrigin?: string } = {},
) {
  const wallet = new MockWallet(await authority.issueMdl(opts.issue ?? { ageOver: [18, 21] }));
  const reader = await makeReader();
  const built = await buildGoogleAgeRequest({ minAge: 21, nonce: 'nonce-1', origin: ORIGIN, reader, gwRpMetadataBytes: METADATA });
  const encryptedResponse = await wallet.presentGoogle({
    origin: opts.presentOrigin ?? ORIGIN,
    nonce: 'nonce-1',
    jwkThumbprint: built.encryptionJwkThumbprint,
    encryptionPublicJwk: publicOf(built.encryptionPrivateKeyJwk),
    disclose: opts.disclose ?? ['age_over_21'],
  });
  return { built, encryptedResponse };
}

const verify = (
  authority: MockAuthority,
  built: Awaited<ReturnType<typeof ceremony>>['built'],
  encryptedResponse: unknown,
  expectedOrigin = ORIGIN,
) =>
  verifyGooglePresentation({
    encryptedResponse,
    encryptionPrivateKeyJwk: built.encryptionPrivateKeyJwk,
    expectedOrigin,
    nonce: 'nonce-1',
    minAge: 21,
    trustAnchors: [authority.trustAnchor],
  });

describe('Google Wallet (signed/encrypted OpenID4VP) end-to-end', () => {
  it('verified for a valid over-21 presentation', async () => {
    const authority = await MockAuthority.create();
    const { built, encryptedResponse } = await ceremony(authority);
    expect(await verify(authority, built, encryptedResponse)).toEqual({ outcome: 'verified', predicate: 'age_over_21' });
  });

  it('predicate_false when the credential is signed under 21', async () => {
    const authority = await MockAuthority.create();
    const { built, encryptedResponse } = await ceremony(authority, {
      issue: { ageOver: [18], claims: { age_over_21: false } },
    });
    expect((await verify(authority, built, encryptedResponse)).outcome).toBe('predicate_false');
  });

  it('untrusted_issuer for a credential from a different authority', async () => {
    const evil = await MockAuthority.create();
    const good = await MockAuthority.create();
    const { built, encryptedResponse } = await ceremony(evil);
    expect((await verify(good, built, encryptedResponse)).outcome).toBe('untrusted_issuer');
  });

  it('replay when verified against a different origin (deviceAuth binding)', async () => {
    // Origin is bound into the transcript (deviceAuth), not the JWE, so a wrong origin
    // decrypts fine but fails device binding → replay.
    const authority = await MockAuthority.create();
    const { built, encryptedResponse } = await ceremony(authority);
    expect((await verify(authority, built, encryptedResponse, 'https://evil.example')).outcome).toBe('replay');
  });

  it('malformed for a garbage response', async () => {
    const authority = await MockAuthority.create();
    const { built } = await ceremony(authority);
    expect((await verify(authority, built, 'not-a-jwe')).outcome).toBe('malformed');
  });
});
