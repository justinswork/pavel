/**
 * The verification pipeline.
 *
 * Decodes the presentation and reads the requested age predicate. Authenticity,
 * validity and binding checks are layered in on top as the suite grows.
 *
 * Crypto lives entirely behind `MdocBackend`; this function is the control flow
 * and outcome selection only.
 */

import type { MdocBackend, DecodedDocument } from './backend';
import { agePredicate } from './request';
import type { VerifyContext, VerifyResult } from './types';

export function verifyPresentation(
  vpToken: string,
  ctx: VerifyContext,
  backend: MdocBackend,
): VerifyResult {
  // Structural — decode the presentation.
  let doc: DecodedDocument;
  try {
    doc = backend.decode(vpToken);
  } catch {
    return { outcome: 'malformed' };
  }

  // Predicate — the requested age_over_NN element must be present and true.
  const predicate = agePredicate(ctx.minAge);
  if (!(predicate in doc.ageClaims)) {
    return { outcome: 'predicate_unavailable', predicate };
  }
  if (doc.ageClaims[predicate] !== true) {
    return { outcome: 'predicate_false', predicate };
  }

  return { outcome: 'verified', predicate };
}
