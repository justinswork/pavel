/**
 * @justinswork/pavel-client — the browser SDK (zk-age.js).
 *
 * `requestAgeProof({ minAge })` runs the whole ceremony end to end:
 *   GET /pavel/request → navigator.credentials.get() → POST /pavel/verify
 * feature-detecting the Digital Credentials API and failing closed with a
 * machine-readable reason. minAge is the only knob a typical caller touches.
 */
import {
  isDigitalCredentialsSupported,
  isUserDismissal,
  presentViaWallet,
} from './dc-api';

export { isDigitalCredentialsSupported } from './dc-api';

/** Why a ceremony did not end in `verified`. Server outcomes pass through verbatim. */
export type PavelReason =
  | 'unsupported' // this browser has no Digital Credentials API
  | 'declined' // the user dismissed the wallet prompt
  | 'request_failed' // couldn't fetch the authorization request
  | 'verification_failed' // the verify call errored or returned an unknown outcome
  | 'predicate_false' // credential present, but under the required age
  | 'predicate_unavailable' // issuer never signed this age predicate
  | 'untrusted_issuer' // signer doesn't chain to a trusted IACA
  | 'expired' // credential outside its validity window
  | 'replay' // presentation not bound to this fresh challenge
  | 'malformed'; // undecodable / structurally invalid presentation

export type PavelResult = { ok: true } | { ok: false; reason: PavelReason };

export interface RequestAgeProofOptions {
  /** The minimum age to prove, mapping to the age_over_<minAge> predicate. */
  minAge: number;
  /** Endpoint that mints the challenge. Default '/pavel/request'. */
  requestPath?: string;
  /** Endpoint that verifies the presentation. Default '/pavel/verify'. */
  verifyPath?: string;
  /** DC API protocol string to request. Default 'openid4vp'. */
  protocol?: string;
  /** DCQL credential id to read the vp_token under. Default 'age_check'. */
  credentialId?: string;
  /** Injectable fetch (testing / non-browser hosts). Default global fetch. */
  fetch?: typeof fetch;
  /** Abort the in-flight ceremony. */
  signal?: AbortSignal;
  /**
   * A pre-fetched authorization request (from `fetchAgeRequest`). When provided,
   * `requestAgeProof` skips its own network fetch so `navigator.credentials.get()`
   * is the first async call in the user gesture — keeping transient activation
   * intact, which the Digital Credentials API requires. See the README.
   */
  request?: unknown;
}

export interface FetchAgeRequestOptions {
  /** The minimum age to prove, mapping to the age_over_<minAge> predicate. */
  minAge: number;
  /** Endpoint that mints the challenge. Default '/pavel/request'. */
  requestPath?: string;
  /** Injectable fetch (testing / non-browser hosts). Default global fetch. */
  fetch?: typeof fetch;
  /** Abort the fetch. */
  signal?: AbortSignal;
}

/** Server verify outcomes that map straight onto a PavelReason. */
const PASSTHROUGH_OUTCOMES = new Set<PavelReason>([
  'predicate_false',
  'predicate_unavailable',
  'untrusted_issuer',
  'expired',
  'replay',
  'malformed',
]);

function reasonForOutcome(outcome: unknown): PavelReason {
  return typeof outcome === 'string' && PASSTHROUGH_OUTCOMES.has(outcome as PavelReason)
    ? (outcome as PavelReason)
    : 'verification_failed';
}

/**
 * Fetch the authorization request the server mints for a ceremony.
 *
 * Call this AHEAD of the user gesture, then pass the result to `requestAgeProof`
 * as `request`, so the wallet call runs first in the gesture (see the README).
 * Throws on a non-2xx response or network error.
 */
export async function fetchAgeRequest(options: FetchAgeRequestOptions): Promise<unknown> {
  const { minAge, requestPath = '/pavel/request', signal } = options;
  const doFetch = options.fetch ?? globalThis.fetch;
  const res = await doFetch(`${requestPath}?minAge=${encodeURIComponent(minAge)}`, { signal });
  if (!res.ok) throw new Error(`pavel: age request failed (${res.status})`);
  return res.json();
}

/**
 * Run the age-verification ceremony. Resolves to `{ ok: true }` once the server
 * records the eligibility fact, or `{ ok: false, reason }` otherwise. Never throws.
 */
export async function requestAgeProof(options: RequestAgeProofOptions): Promise<PavelResult> {
  const {
    minAge,
    requestPath = '/pavel/request',
    verifyPath = '/pavel/verify',
    protocol = 'openid4vp',
    credentialId = 'age_check',
    signal,
  } = options;
  const doFetch = options.fetch ?? globalThis.fetch;

  if (!isDigitalCredentialsSupported()) return { ok: false, reason: 'unsupported' };

  // 1. The authorization request — reuse a pre-fetched one (gesture-safe), else
  //    fetch it now. Passing `request` keeps get() first in the user gesture.
  let authRequest = options.request;
  if (authRequest === undefined) {
    try {
      authRequest = await fetchAgeRequest({ minAge, requestPath, fetch: doFetch, signal });
    } catch {
      return { ok: false, reason: 'request_failed' };
    }
  }

  // 2. Hand it to the OS wallet and collect the vp_token.
  let vpToken: string | null;
  try {
    vpToken = await presentViaWallet(authRequest, { protocol, credentialId, signal });
  } catch (err) {
    return { ok: false, reason: isUserDismissal(err) ? 'declined' : 'verification_failed' };
  }
  if (vpToken == null) return { ok: false, reason: 'declined' };

  // 3. Post the presentation back for verification.
  try {
    const res = await doFetch(verifyPath, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ vp_token: vpToken }),
      signal,
    });
    const body = (await res.json().catch(() => ({}))) as { ok?: boolean; outcome?: unknown };
    if (body?.ok === true) return { ok: true };
    return { ok: false, reason: reasonForOutcome(body?.outcome) };
  } catch {
    return { ok: false, reason: 'verification_failed' };
  }
}
