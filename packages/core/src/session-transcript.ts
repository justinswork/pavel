/**
 * The DC-API (OpenID4VP-over-Digital-Credentials-API) SessionTranscript — the
 * single source of truth both the verifier and any presenter must agree on.
 *
 * @owf/mdoc builds this handover variant natively, so we delegate to it rather
 * than hand-assembling the CBOR. deviceAuth is signed over these bytes; the
 * verifier recomputes them from origin + nonce and a mismatch fails the binding
 * (anti-replay / anti-relay).
 *
 *   SessionTranscript      = [ null, null, OpenID4VPDCAPIHandover ]
 *   OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", SHA-256(HandoverInfo) ]
 *   HandoverInfo           = [ origin, nonce, jwkThumbprint | null ]
 *
 * NOTE: the exact byte layout for real-wallet interop is pinned in the
 * integration tier; the mechanism is proven.
 */
import { SessionTranscript } from '@owf/mdoc';
import { mdocContext } from './mdoc-context';

/** Build the DC-API SessionTranscript binding a presentation to origin + nonce. */
export function dcApiSessionTranscript(origin: string, nonce: string): Promise<SessionTranscript> {
  return SessionTranscript.forOid4VpDcApi({ origin, nonce }, mdocContext);
}
