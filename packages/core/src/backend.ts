/**
 * The crypto seam.
 *
 * `MdocBackend` isolates every operation that needs real CBOR/COSE/PKI from the
 * pipeline's control flow. The pipeline (pipeline.ts) is pure and fully testable
 * against a fake backend today; the REAL backend — wrapping the mdoc library the
 * spike settles on (e.g. @auth0/mdl) — lands behind this same interface later,
 * and its own tests use golden `DeviceResponse` vectors from pavel-authority.
 *
 * NOTE: kept synchronous for now. If the chosen mdoc library is async-only, this
 * interface and verifyPresentation() become Promise-returning — a mechanical
 * change the spike will decide.
 */

export const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
export const MDL_NAMESPACE = 'org.iso.18013.5.1';

/** The subset of a decoded DeviceResponse the pipeline reads directly. */
export interface DecodedDocument {
  /** e.g. "org.iso.18013.5.1.mDL". */
  docType: string;
  /** MSO validityInfo timestamps (ms since epoch). */
  validity: { validFrom: number; validUntil: number; signed: number };
  /** Disclosed age predicates in the mDL namespace, e.g. { age_over_21: true }. */
  ageClaims: Record<string, boolean>;
  /** Opaque handle for the backend's own crypto checks (raw CBOR, COSE, etc.). */
  raw?: unknown;
}

export interface MdocBackend {
  /** Decode base64url → CBOR DeviceResponse. Throws on malformed input (step 1). */
  decode(vpToken: string): DecodedDocument;
  /** Document-signer cert chains to a trusted IACA, in validity period (step 2). */
  chainsToTrustedIaca(doc: DecodedDocument): boolean;
  /** issuerAuth COSE_Sign1 over the MSO verifies (step 3). */
  issuerAuthValid(doc: DecodedDocument): boolean;
  /** deviceAuth verifies under the MSO deviceKey — holder binding (step 5). */
  deviceAuthValid(doc: DecodedDocument): boolean;
  /** SessionTranscript binds OUR nonce + expected origin (step 6). */
  sessionTranscriptBinds(doc: DecodedDocument, nonce: string, origin: string): boolean;
  /** Each disclosed item's recomputed digest matches valueDigests (step 7). */
  digestsMatch(doc: DecodedDocument): boolean;
}
