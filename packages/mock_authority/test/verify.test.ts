/**
 * End-to-end: mint (MockAuthority) → present (MockWallet) → verify through the
 * real pavel-core @owf/mdoc backend. This exercises real CBOR/COSE/PKI and the
 * outcome mapping together. It lives here because mock_authority already depends
 * on pavel-core (no dependency cycle).
 */
import { describe, it, expect } from 'vitest';
import { MockAuthority, MockWallet } from '../src/index';
import { createOwfMdocBackend, verifyPresentation } from '@justinswork/pavel-core';

const ORIGIN = 'https://shop.example';
const NONCE = 'server-minted-nonce-abc';
const YEAR_MS = 365 * 24 * 3600 * 1000;

async function present(
  wallet: MockWallet,
  disclose: string[] = ['age_over_21'],
): Promise<string> {
  return wallet.present({ nonce: NONCE, origin: ORIGIN, disclose });
}

describe('pavel-core @owf/mdoc backend verifies mock_authority presentations', () => {
  it('verified for a valid over-21 presentation', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const backend = createOwfMdocBackend({ trustAnchors: [authority.trustAnchor] });

    const result = await verifyPresentation(
      await present(wallet),
      { nonce: NONCE, expectedOrigin: ORIGIN, minAge: 21 },
      backend,
    );
    expect(result).toEqual({ outcome: 'verified', predicate: 'age_over_21' });
  });

  it('untrusted_issuer for a credential from a different authority', async () => {
    const evil = await MockAuthority.create();
    const good = await MockAuthority.create();
    const wallet = new MockWallet(await evil.issueMdl());
    const backend = createOwfMdocBackend({ trustAnchors: [good.trustAnchor] });

    const result = await verifyPresentation(
      await present(wallet),
      { nonce: NONCE, expectedOrigin: ORIGIN, minAge: 21 },
      backend,
    );
    expect(result.outcome).toBe('untrusted_issuer');
  });

  it('replay for a presentation checked against a different origin', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl());
    const backend = createOwfMdocBackend({ trustAnchors: [authority.trustAnchor] });

    const result = await verifyPresentation(
      await present(wallet),
      { nonce: NONCE, expectedOrigin: 'https://evil.example', minAge: 21 },
      backend,
    );
    expect(result.outcome).toBe('replay');
  });

  it('expired for a credential outside its validity window', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(
      await authority.issueMdl({
        validFrom: new Date(Date.now() - 2 * YEAR_MS),
        validUntil: new Date(Date.now() - YEAR_MS),
      }),
    );
    const backend = createOwfMdocBackend({ trustAnchors: [authority.trustAnchor] });

    const result = await verifyPresentation(
      await present(wallet),
      { nonce: NONCE, expectedOrigin: ORIGIN, minAge: 21 },
      backend,
    );
    expect(result.outcome).toBe('expired');
  });
});
