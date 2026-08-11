/**
 * The verification pipeline: map a backend's RawVerification to a public outcome.
 *
 * When several checks fail at once (the backend runs them all), the order below
 * is the outcome PRECEDENCE: structural → issuer trust → authenticity → validity
 * → device binding → predicate. This is asserted by tests.
 */
import type { MdocBackend, RawVerification } from './backend';
import { MDL_DOCTYPE } from './backend';
import { agePredicate } from './request';
import type { VerifyContext, VerifyResult } from './types';

/** Map a neutral verification result to a public outcome. Pure. */
export function outcomeFor(raw: RawVerification, minAge: number): VerifyResult {
  if (!raw.decoded || raw.docType !== MDL_DOCTYPE) return { outcome: 'malformed' };
  if (!raw.issuerTrusted) return { outcome: 'untrusted_issuer' };
  if (!raw.authentic) return { outcome: 'malformed' };
  if (!raw.withinValidity) return { outcome: 'expired' };
  if (!raw.deviceBound) return { outcome: 'replay' };

  const predicate = agePredicate(minAge);
  if (!(predicate in raw.ageClaims)) return { outcome: 'predicate_unavailable', predicate };
  if (raw.ageClaims[predicate] !== true) return { outcome: 'predicate_false', predicate };
  return { outcome: 'verified', predicate };
}

/** Verify a presentation end-to-end through the given backend. */
export async function verifyPresentation(
  vpToken: string,
  ctx: VerifyContext,
  backend: MdocBackend,
): Promise<VerifyResult> {
  const raw = await backend.verify(vpToken, ctx);
  return outcomeFor(raw, ctx.minAge);
}
