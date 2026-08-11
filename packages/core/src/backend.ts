/**
 * The verification backend seam.
 *
 * A backend does the crypto-heavy verification in one call and returns a neutral
 * RawVerification; verifyPresentation (pipeline.ts) maps that to the public
 * outcome enum. The real backend wraps @auth0/mdl (backend-auth0.ts); the mapping
 * is unit-tested against hand-built RawVerification values.
 */
import type { VerifyContext } from './types';

export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
export const MDL_NAMESPACE = 'org.iso.18013.5.1';

/** Backend-neutral result of verifying a presentation. */
export interface RawVerification {
  /** Did the token decode into a document? false → malformed. */
  decoded: boolean;
  /** docType of the decoded document, if any. */
  docType?: string;
  /** Document-signer cert chains to a trusted IACA. false → untrusted_issuer. */
  issuerTrusted: boolean;
  /** Issuer signature and disclosed-item digests verify. false → malformed. */
  authentic: boolean;
  /** MSO validity window covers verification time. false → expired. */
  withinValidity: boolean;
  /**
   * deviceAuth over the session transcript verifies. @auth0/mdl merges holder
   * binding and freshness/audience into this one verdict, so false → replay.
   */
  deviceBound: boolean;
  /** Disclosed age predicates in the mDL namespace, e.g. { age_over_21: true }. */
  ageClaims: Record<string, boolean>;
}

export interface MdocBackend {
  /** Verify a base64url vp_token against the ceremony context. */
  verify(vpToken: string, ctx: VerifyContext): Promise<RawVerification>;
}
