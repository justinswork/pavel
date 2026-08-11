/** Options and session types for the PAVEL Express middleware. */

export interface PavelOptions {
  /** Trusted IACA root certificates (PEM). Mock in dev, real issuer roots in prod. */
  trustAnchors: string[];
  /** Expected web origin, bound into the request and checked on verify. */
  origin: string;
  /** Single-use nonce time-to-live, ms. Default 5 minutes. */
  nonceTtlMs?: number;
  /** Verifier display name shown in the wallet consent prompt. */
  clientName?: string;
}

export interface RequireAgeProofOptions {
  /** The predicate to require, i.e. age_over_<minAge>. */
  minAge: number;
  /**
   * When true, a cached verification is not sufficient: the proof is one-shot,
   * consumed once the gated action succeeds, so the next request re-verifies.
   * Defaults to false (verify once, cache for the session).
   */
  forceReverify?: boolean;
}

/** The durable result of a ceremony — a boolean fact, no PII. */
export interface PavelSessionState {
  verified: boolean;
  verifiedMinAge?: number;
  verifiedAt?: number;
}

/** What the server tracks while a ceremony is in flight. */
export interface PendingRequest {
  nonce: string;
  minAge: number;
  expiresAt: number;
}

// Augment express-session so req.session carries our fields with types.
declare module 'express-session' {
  interface SessionData {
    pavel?: PavelSessionState;
    pavelPending?: PendingRequest;
  }
}
