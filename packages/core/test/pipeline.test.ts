import { describe, it, expect } from 'vitest';
import { outcomeFor, verifyPresentation } from '../src/pipeline';
import { MDL_DOCTYPE, type RawVerification, type MdocBackend } from '../src/backend';
import type { VerifyContext } from '../src/types';

/** A RawVerification where every check passed and the predicate is true. */
function validRaw(overrides: Partial<RawVerification> = {}): RawVerification {
  return {
    decoded: true,
    docType: MDL_DOCTYPE,
    issuerTrusted: true,
    authentic: true,
    withinValidity: true,
    deviceBound: true,
    ageClaims: { age_over_21: true },
    ...overrides,
  };
}

describe('outcomeFor — predicate outcomes', () => {
  it('verified when every check passes and the predicate is true', () => {
    expect(outcomeFor(validRaw(), 21)).toEqual({ outcome: 'verified', predicate: 'age_over_21' });
  });

  it('predicate_unavailable when the requested age_over_NN is absent', () => {
    expect(outcomeFor(validRaw({ ageClaims: { age_over_18: true } }), 21)).toEqual({
      outcome: 'predicate_unavailable',
      predicate: 'age_over_21',
    });
  });

  it('predicate_false when the predicate is present but false', () => {
    expect(outcomeFor(validRaw({ ageClaims: { age_over_21: false } }), 21)).toEqual({
      outcome: 'predicate_false',
      predicate: 'age_over_21',
    });
  });
});

describe('outcomeFor — each failed check maps to its outcome', () => {
  it('malformed when the token did not decode', () => {
    expect(outcomeFor(validRaw({ decoded: false }), 21).outcome).toBe('malformed');
  });

  it('malformed when the docType is not an mDL', () => {
    expect(outcomeFor(validRaw({ docType: 'org.iso.23220.photoID' }), 21).outcome).toBe('malformed');
  });

  it('untrusted_issuer when the issuer does not chain to a trusted IACA', () => {
    expect(outcomeFor(validRaw({ issuerTrusted: false }), 21).outcome).toBe('untrusted_issuer');
  });

  it('malformed when the credential is not authentic (bad signature / digest)', () => {
    expect(outcomeFor(validRaw({ authentic: false }), 21).outcome).toBe('malformed');
  });

  it('expired when outside the validity window', () => {
    expect(outcomeFor(validRaw({ withinValidity: false }), 21).outcome).toBe('expired');
  });

  it('replay when deviceAuth binding fails', () => {
    expect(outcomeFor(validRaw({ deviceBound: false }), 21).outcome).toBe('replay');
  });
});

describe('outcomeFor — precedence (first failing check wins)', () => {
  it('reports untrusted_issuer before expired', () => {
    expect(outcomeFor(validRaw({ issuerTrusted: false, withinValidity: false }), 21).outcome).toBe(
      'untrusted_issuer',
    );
  });

  it('reports replay before the predicate check', () => {
    expect(outcomeFor(validRaw({ deviceBound: false, ageClaims: { age_over_21: false } }), 21).outcome).toBe(
      'replay',
    );
  });
});

describe('verifyPresentation — delegates to the backend and maps its result', () => {
  const ctx: VerifyContext = { nonce: 'n', expectedOrigin: 'https://shop.example', minAge: 21 };

  it('awaits the backend and returns the mapped outcome', async () => {
    const backend: MdocBackend = { verify: async () => validRaw() };
    await expect(verifyPresentation('tok', ctx, backend)).resolves.toEqual({
      outcome: 'verified',
      predicate: 'age_over_21',
    });
  });

  it('passes the token and context through to the backend', async () => {
    let seen: unknown;
    const backend: MdocBackend = {
      verify: async (vpToken, c) => {
        seen = { vpToken, c };
        return validRaw({ deviceBound: false });
      },
    };
    const result = await verifyPresentation('the-token', ctx, backend);
    expect(seen).toEqual({ vpToken: 'the-token', c: ctx });
    expect(result.outcome).toBe('replay');
  });
});
