/**
 * THE SWAP POINT.
 *
 * In the real system this file is `@justinswork/pavel-core`'s verification
 * pipeline: decode the CBOR DeviceResponse, validate the IACA chain, verify the
 * issuerAuth COSE_Sign1 over the MSO, check validityInfo, verify the deviceAuth
 * holder binding, confirm the SessionTranscript binds our nonce + origin,
 * recompute valueDigests, and finally read the age_over_NN predicate.
 *
 * The MOCK below performs the *same logical checks* on a plaintext JSON token
 * instead of real crypto, and returns the same outcome enum. Replace ONLY this
 * module to go live — the middleware and demo never change.
 */

import type { VerificationOutcome } from './types.js';

/** The single trusted mock issuer. Real code would check an IACA cert chain. */
const TRUSTED_ISSUER = 'mock-iaca';

/** Shape of the plaintext token the mock wallet (zk-age.js) fabricates. */
interface MockPresentation {
  /** Echoes the server nonce — stands in for SessionTranscript freshness binding. */
  nonce: string;
  /** Echoes location.origin — stands in for audience binding. */
  origin: string;
  doctype: string;
  /** Stands in for the IACA/document-signer trust chain. */
  issuer: string;
  /** Disclosed boolean predicates, e.g. { age_over_21: true }. */
  claims: Record<string, boolean>;
  /** Optional signed validity window; if absent, treated as always-valid. */
  validUntil?: number;
}

export interface VerifyContext {
  /** The single-use nonce the server minted for THIS ceremony. */
  nonce: string;
  /** The origin the middleware was configured with. */
  expectedOrigin: string;
  /** The predicate to require, i.e. age_over_<minAge>. */
  minAge: number;
  /** Current time (ms). Injectable for deterministic tests. */
  now?: number;
}

export interface VerifyResult {
  outcome: VerificationOutcome;
  /** The predicate element that was evaluated, e.g. "age_over_21". */
  predicate?: string;
}

function base64urlDecode(input: string): string {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return Buffer.from(b64, 'base64').toString('utf8');
}

/**
 * Verify a (mock) presentation against the ceremony context, failing closed.
 * Mirrors the ordered verification pipeline.
 */
export function verifyPresentation(vpToken: string, ctx: VerifyContext): VerifyResult {
  const now = ctx.now ?? Date.now();

  // 1. Structural — decode the token.
  let doc: MockPresentation;
  try {
    doc = JSON.parse(base64urlDecode(vpToken)) as MockPresentation;
  } catch {
    return { outcome: 'malformed' };
  }
  if (
    !doc ||
    typeof doc.nonce !== 'string' ||
    typeof doc.origin !== 'string' ||
    typeof doc.issuer !== 'string' ||
    typeof doc.claims !== 'object' ||
    doc.claims === null ||
    doc.doctype !== 'org.iso.18013.5.1.mDL'
  ) {
    return { outcome: 'malformed' };
  }

  // 2. Issuer trust — real code chains the document-signer cert to a trusted IACA.
  if (doc.issuer !== TRUSTED_ISSUER) {
    return { outcome: 'untrusted_issuer' };
  }

  // 4. Credential validity window (validityInfo).
  if (typeof doc.validUntil === 'number' && doc.validUntil < now) {
    return { outcome: 'expired' };
  }

  // 6. Freshness & audience binding — the token must carry OUR nonce and origin.
  //    (Steps 3 & 5 — issuer/device COSE signatures — have no mock analogue.)
  if (doc.nonce !== ctx.nonce || doc.origin !== ctx.expectedOrigin) {
    return { outcome: 'replay' };
  }

  // 8. Predicate — the requested age_over_NN element must be present and true.
  const predicate = `age_over_${ctx.minAge}`;
  if (!(predicate in doc.claims)) {
    return { outcome: 'predicate_unavailable' };
  }
  if (doc.claims[predicate] !== true) {
    return { outcome: 'predicate_false', predicate };
  }

  return { outcome: 'verified', predicate };
}
