import { describe, it, expect } from 'vitest';
import { verifyPresentation } from '../src/pipeline';
import { MDL_DOCTYPE, type MdocBackend, type DecodedDocument } from '../src/backend';
import type { VerifyContext } from '../src/types';

const NOW = 1_700_000_000_000; // fixed "current time" for deterministic validity checks

const ctx: VerifyContext = {
  nonce: 'server-nonce',
  expectedOrigin: 'https://shop.example',
  minAge: 21,
  now: NOW,
};

/** A decoded document that passes every pure check by default. */
function validDoc(overrides: Partial<DecodedDocument> = {}): DecodedDocument {
  return {
    docType: MDL_DOCTYPE,
    validity: { validFrom: NOW - 1000, validUntil: NOW + 1000, signed: NOW - 1000 },
    ageClaims: { age_over_21: true },
    ...overrides,
  };
}

/**
 * A fake backend whose every crypto check passes, decoding to `doc`. Override any
 * method to force a specific failure — this is how we TDD the pipeline's control
 * flow without real CBOR/COSE.
 */
function fakeBackend(overrides: Partial<MdocBackend> = {}, doc: DecodedDocument = validDoc()): MdocBackend {
  return {
    decode: () => doc,
    chainsToTrustedIaca: () => true,
    issuerAuthValid: () => true,
    deviceAuthValid: () => true,
    sessionTranscriptBinds: () => true,
    digestsMatch: () => true,
    ...overrides,
  };
}

describe('verifyPresentation — predicate outcomes', () => {
  it('accepts a fully valid presentation with the predicate true', () => {
    expect(verifyPresentation('tok', ctx, fakeBackend())).toEqual({
      outcome: 'verified',
      predicate: 'age_over_21',
    });
  });

  it('predicate_unavailable when the requested age_over_NN is absent', () => {
    const backend = fakeBackend({}, validDoc({ ageClaims: { age_over_18: true } }));
    expect(verifyPresentation('tok', ctx, backend)).toEqual({
      outcome: 'predicate_unavailable',
      predicate: 'age_over_21',
    });
  });

  it('predicate_false when the predicate is present but false', () => {
    const backend = fakeBackend({}, validDoc({ ageClaims: { age_over_21: false } }));
    expect(verifyPresentation('tok', ctx, backend)).toEqual({
      outcome: 'predicate_false',
      predicate: 'age_over_21',
    });
  });
});
