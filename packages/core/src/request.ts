/** Builds the OpenID4VP + DCQL Authorization Request for a single age predicate. */

import type { AuthorizationRequest, BuildAgeRequestParams } from './types';
import { MDL_DOCTYPE, MDL_NAMESPACE } from './backend';

/** Assert a minAge is a usable integer predicate index; throws otherwise. */
export function assertValidMinAge(minAge: number): void {
  if (!Number.isInteger(minAge) || minAge < 1 || minAge > 120) {
    throw new RangeError(`minAge must be an integer in 1..120, got ${minAge}`);
  }
}

/** Map a minimum age to its ISO 18013-5 boolean element identifier. */
export function agePredicate(minAge: number): string {
  assertValidMinAge(minAge);
  return `age_over_${minAge}`;
}

/**
 * Build the Authorization Request. By construction it asks for exactly ONE
 * claim — the age predicate — so it is not possible to over-collect.
 */
export function buildAgeRequest(params: BuildAgeRequestParams): AuthorizationRequest {
  const { minAge, nonce, origin, responseMode = 'dc_api', clientName } = params;
  assertValidMinAge(minAge);

  return {
    response_type: 'vp_token',
    response_mode: responseMode,
    nonce,
    dcql_query: {
      credentials: [
        {
          id: 'age_check',
          format: 'mso_mdoc',
          meta: { doctype_value: MDL_DOCTYPE },
          claims: [{ path: [MDL_NAMESPACE, agePredicate(minAge)] }],
        },
      ],
    },
    client_metadata: {
      ...(clientName ? { client_name: clientName } : {}),
      // origin is carried here for the DC API handover / audience binding.
      expected_origin: origin,
    },
  };
}
