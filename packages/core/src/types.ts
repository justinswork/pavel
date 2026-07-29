/** Public types for @justinswork/pavel-core. */

/** The full set of verification outcomes. */
export type VerificationOutcome =
  | 'verified'
  | 'predicate_false'
  | 'predicate_unavailable'
  | 'untrusted_issuer'
  | 'expired'
  | 'replay'
  | 'malformed';

/** All outcomes, as a runtime-iterable tuple. */
export const VERIFICATION_OUTCOMES = [
  'verified',
  'predicate_false',
  'predicate_unavailable',
  'untrusted_issuer',
  'expired',
  'replay',
  'malformed',
] as const satisfies readonly VerificationOutcome[];

/** Inputs to build an age-predicate Authorization Request. */
export interface BuildAgeRequestParams {
  /** Maps to the age_over_<minAge> predicate. Integer, 1–120. */
  minAge: number;
  /** Server-minted, single-use, session-bound challenge. */
  nonce: string;
  /** Expected web origin, bound into the request. */
  origin: string;
  /** `dc_api` (default) or `dc_api.jwt` for an encrypted response. */
  responseMode?: 'dc_api' | 'dc_api.jwt';
  /** Verifier display name shown in the wallet consent prompt. */
  clientName?: string;
}

/** An OpenID4VP Authorization Request tailored for the DC API. */
export interface AuthorizationRequest {
  response_type: 'vp_token';
  response_mode: 'dc_api' | 'dc_api.jwt';
  nonce: string;
  dcql_query: {
    credentials: Array<{
      id: string;
      format: 'mso_mdoc';
      meta: { doctype_value: string };
      claims: Array<{ path: string[] }>;
    }>;
  };
  client_metadata: Record<string, unknown>;
}

/** The ceremony context a presentation is verified against. */
export interface VerifyContext {
  /** The single-use nonce the server minted for THIS ceremony. */
  nonce: string;
  /** The origin the verifier expects the presentation to be bound to. */
  expectedOrigin: string;
  /** The predicate to require, i.e. age_over_<minAge>. */
  minAge: number;
  /** Current time (ms since epoch). Injectable for deterministic tests. */
  now?: number;
}

/** The result of running the verification pipeline. */
export interface VerifyResult {
  outcome: VerificationOutcome;
  /** The predicate element evaluated, e.g. "age_over_21" (when reached). */
  predicate?: string;
}
