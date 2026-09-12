/**
 * End-to-end ISO 18013-7 Annex C (org-iso-mdoc / Safari) round-trip through the real
 * pavel-core path: build the request, HPKE-encrypt a real DeviceResponse from the mock
 * wallet, then HPKE-decrypt + verify. No device needed — the mock wallet stands in for
 * Safari's OS wallet.
 */
import { describe, it, expect } from 'vitest';
import { MockAuthority, MockWallet, type IssueMdlOptions } from '../src/index';
import { buildIsoMdocAgeRequest, verifyIsoMdocPresentation } from '@justinswork/pavel-core';

const ORIGIN = 'https://shop.example';

async function ceremony(
  authority: MockAuthority,
  opts: { issue?: IssueMdlOptions; disclose?: string[]; presentOrigin?: string } = {},
) {
  const wallet = new MockWallet(await authority.issueMdl(opts.issue ?? { ageOver: [18, 21] }));
  const req = await buildIsoMdocAgeRequest({ minAge: 21 });
  const encryptedResponse = await wallet.presentIso({
    encryptionInfoBase64Url: req.encryptionInfoBase64Url,
    origin: opts.presentOrigin ?? ORIGIN,
    disclose: opts.disclose ?? ['age_over_21'],
  });
  return { req, encryptedResponse };
}

function verify(
  authority: MockAuthority,
  req: Awaited<ReturnType<typeof ceremony>>['req'],
  encryptedResponse: unknown,
  expectedOrigin = ORIGIN,
) {
  return verifyIsoMdocPresentation({
    encryptedResponse,
    ephemeralPrivateKeyJwk: req.ephemeralPrivateKeyJwk,
    encryptionInfoBase64Url: req.encryptionInfoBase64Url,
    expectedOrigin,
    minAge: 21,
    trustAnchors: [authority.trustAnchor],
  });
}

describe('ISO 18013-7 (org-iso-mdoc) end-to-end', () => {
  it('verified for a valid over-21 presentation', async () => {
    const authority = await MockAuthority.create();
    const { req, encryptedResponse } = await ceremony(authority);
    expect(await verify(authority, req, encryptedResponse)).toEqual({
      outcome: 'verified',
      predicate: 'age_over_21',
    });
  });

  it('predicate_false when the credential is signed under 21', async () => {
    const authority = await MockAuthority.create();
    const { req, encryptedResponse } = await ceremony(authority, {
      issue: { ageOver: [18], claims: { age_over_21: false } },
    });
    const result = await verify(authority, req, encryptedResponse);
    expect(result.outcome).toBe('predicate_false');
  });

  it('untrusted_issuer for a credential from a different authority', async () => {
    const evil = await MockAuthority.create();
    const good = await MockAuthority.create();
    const { req, encryptedResponse } = await ceremony(evil);
    // Verify against the good anchor; decrypt still succeeds (right ephemeral key).
    const result = await verifyIsoMdocPresentation({
      encryptedResponse,
      ephemeralPrivateKeyJwk: req.ephemeralPrivateKeyJwk,
      encryptionInfoBase64Url: req.encryptionInfoBase64Url,
      expectedOrigin: ORIGIN,
      minAge: 21,
      trustAnchors: [good.trustAnchor],
    });
    expect(result.outcome).toBe('untrusted_issuer');
  });

  it('malformed when verified against a different origin (HPKE info binding)', async () => {
    // ISO binds origin into the HPKE info (the transcript), so a wrong origin fails to
    // decrypt — surfacing as malformed rather than replay.
    const authority = await MockAuthority.create();
    const { req, encryptedResponse } = await ceremony(authority);
    const result = await verify(authority, req, encryptedResponse, 'https://evil.example');
    expect(result.outcome).toBe('malformed');
  });

  it('malformed for a garbage response', async () => {
    const authority = await MockAuthority.create();
    const { req } = await ceremony(authority);
    const result = await verify(authority, req, 'not-a-valid-encrypted-response');
    expect(result.outcome).toBe('malformed');
  });
});
