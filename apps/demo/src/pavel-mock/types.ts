/**
 * Shared types for the MOCK PAVEL gate.
 *
 * These deliberately mirror the shapes described in the repo's ARCHITECTURE
 * doc so that the real `@justinswork/pavel` packages can drop in behind the same
 * interface later. Only the credential cryptography (CBOR/COSE) is stubbed —
 * see verify.ts.
 */

/** The full set of verification outcomes. */
export type VerificationOutcome =
  | 'verified'
  | 'predicate_false'
  | 'predicate_unavailable'
  | 'untrusted_issuer'
  | 'expired'
  | 'replay'
  | 'malformed';

/** Options for the pavel() middleware factory. */
export interface PavelOptions {
  /** Expected web origin, bound into the request and checked on verify. */
  origin: string;
  /**
   * Trust anchors (IACA certs). Unused by the mock verifier, but kept in the
   * signature so integrator code doesn't change when real -core lands.
   */
  trustAnchors?: unknown[];
  /** Single-use nonce time-to-live, ms. Default 5 minutes. */
  nonceTtlMs?: number;
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
  /** Non-standard convenience field so the mock wallet can echo the origin back. */
  expected_origin: string;
}

/** What the server tracks in the session while a ceremony is in flight. */
export interface PendingRequest {
  nonce: string;
  minAge: number;
  expiresAt: number;
}

/** The durable result of a successful ceremony — a boolean fact, no PII. */
export interface PavelSessionState {
  verified: boolean;
  verifiedMinAge?: number;
  verifiedAt?: number;
}

/** Options for the requireAgeProof() gate. */
export interface RequireAgeProofOptions {
  /** The predicate to require, i.e. age_over_<minAge>. */
  minAge: number;
  /**
   * When true, a cached verification is NOT sufficient. The proof becomes
   * one-shot: it authorizes exactly this gated action and is consumed once the
   * action completes successfully, so the next gated request re-runs the
   * ceremony. Use for flows that must re-verify at every checkout regardless of
   * a recent prior verification. Defaults to false (verify once, cache for the
   * session — the default model).
   */
  forceReverify?: boolean;
}

// Augment express-session so req.session carries our fields with types.
declare module 'express-session' {
  interface SessionData {
    pavel?: PavelSessionState;
    pavelPending?: PendingRequest;
    cart?: Record<string, number>;
  }
}
