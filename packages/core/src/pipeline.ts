/**
 * The verification pipeline.
 *
 * Runs the ordered checks and FAILS CLOSED on the first failure. The ordering is
 * significant and is asserted by tests: e.g. an untrusted issuer that is also
 * expired reports `untrusted_issuer`, because the trust chain is checked first.
 *
 * Crypto lives entirely behind `MdocBackend`; this function is the control flow
 * and outcome selection only.
 */

import type { MdocBackend, DecodedDocument } from './backend';
import { MDL_DOCTYPE } from './backend';
import { agePredicate } from './request';
import type { VerifyContext, VerifyResult } from './types';

export function verifyPresentation(
  vpToken: string,
  ctx: VerifyContext,
  backend: MdocBackend,
): VerifyResult {
  const now = ctx.now ?? Date.now();

  // 1. Structural — decode; must be a document of the expected docType.
  let doc: DecodedDocument;
  try {
    doc = backend.decode(vpToken);
  } catch {
    return { outcome: 'malformed' };
  }
  if (doc.docType !== MDL_DOCTYPE) {
    return { outcome: 'malformed' };
  }

  // 2. Issuer trust chain — document-signer cert chains to a trusted IACA.
  if (!backend.chainsToTrustedIaca(doc)) {
    return { outcome: 'untrusted_issuer' };
  }

  // 3. Issuer signature — issuerAuth COSE_Sign1 over the MSO. A bad signature
  //    means a forged/tampered credential → malformed.
  if (!backend.issuerAuthValid(doc)) {
    return { outcome: 'malformed' };
  }

  // 4. Credential validity window — signed / validFrom / validUntil.
  if (now < doc.validity.validFrom || now > doc.validity.validUntil) {
    return { outcome: 'expired' };
  }

  // 5. Holder binding — deviceAuth under the MSO deviceKey. Failure means a
  //    copied credential presented from another device → malformed.
  if (!backend.deviceAuthValid(doc)) {
    return { outcome: 'malformed' };
  }

  // 6. Freshness & audience binding — SessionTranscript carries our nonce +
  //    origin. Failure is a replay or cross-site relay.
  if (!backend.sessionTranscriptBinds(doc, ctx.nonce, ctx.expectedOrigin)) {
    return { outcome: 'replay' };
  }

  // 7. Digest integrity — every disclosed item matches the MSO valueDigests.
  if (!backend.digestsMatch(doc)) {
    return { outcome: 'malformed' };
  }

  // 8. Predicate — the requested age_over_NN element is present and true.
  const predicate = agePredicate(ctx.minAge);
  if (!(predicate in doc.ageClaims)) {
    return { outcome: 'predicate_unavailable', predicate };
  }
  if (doc.ageClaims[predicate] !== true) {
    return { outcome: 'predicate_false', predicate };
  }

  return { outcome: 'verified', predicate };
}
