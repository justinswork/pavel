/** Options and session types for the PAVEL Express middleware. */

import type { GoogleVerifierConfig, IsoReaderIdentity } from '@justinswork/pavel-core';

/** Apple Wallet "real ID" config: signs org-iso-mdoc requests with your Apple-issued certificate. */
export interface AppleVerifierConfig {
  /** The key and certificate chain from Apple Business (Verify with Wallet on the Web). */
  reader: IsoReaderIdentity;
}

export interface PavelOptions {
  /** Trusted IACA root certificates (PEM). Mock in dev, real issuer roots in prod. */
  trustAnchors: string[];
  /** Expected web origin, bound into the request and checked on verify. */
  origin: string;
  /** Single-use nonce time-to-live, ms. Default 5 minutes. */
  nonceTtlMs?: number;
  /** Verifier display name shown in the wallet consent prompt. */
  clientName?: string;
  /**
   * Optional Google Wallet "real ID" config (signed/encrypted OpenID4VP). When set, the
   * request also offers the `openid4vp-v1-signed` protocol. Needs a registered reader cert
   * + gw_rp_metadata_bytes (sandbox sample or production). Omit to keep the demo/test paths.
   */
  google?: GoogleVerifierConfig;
  /**
   * Optional Apple Wallet "real ID" config. When set, org-iso-mdoc requests are signed
   * (reader authentication), which Apple requires before releasing real IDs. Omit to keep
   * unsigned requests, which test wallets and Apple's developer profile accept.
   */
  apple?: AppleVerifierConfig;
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
  /** ISO 18013-7 (org-iso-mdoc) reader ephemeral private key, to decrypt the response. */
  isoEphemeralPrivateKeyJwk?: Record<string, unknown>;
  /** The ISO EncryptionInfo string, to rebuild the handover transcript on verify. */
  isoEncryptionInfoBase64Url?: string;
  /** Google Wallet response-encryption private key (JWK), to decrypt the JWE on verify. */
  googleEncryptionPrivateKeyJwk?: Record<string, unknown>;
}

// Augment express-session so req.session carries our fields with types.
declare module 'express-session' {
  interface SessionData {
    pavel?: PavelSessionState;
    pavelPending?: PendingRequest;
  }
}
