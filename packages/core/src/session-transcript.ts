/**
 * The DC-API (OpenID4VP-over-Digital-Credentials-API) SessionTranscript — the
 * single source of truth both the verifier and any presenter must agree on.
 *
 * @auth0/mdl has no built-in helper for this handover variant, so we build the
 * bytes here. deviceAuth is signed over them; the verifier recomputes them and a
 * mismatch fails the binding (anti-replay / anti-relay).
 *
 *   SessionTranscript      = [ null, null, OpenID4VPDCAPIHandover ]   (Tagged-24)
 *   OpenID4VPDCAPIHandover = [ "OpenID4VPDCAPIHandover", SHA-256(HandoverInfo) ]
 *   HandoverInfo           = [ origin, nonce, jwkThumbprint | null ]
 *
 * NOTE: the exact byte layout for real-wallet interop is pinned in the
 * integration tier; the mechanism is proven.
 */
import { createHash } from 'node:crypto';
import { cborEncode, DataItem } from '@auth0/mdl/lib/cbor/index.js';

export function dcApiSessionTranscript(origin: string, nonce: string): Buffer {
  const handoverInfo = cborEncode([origin, nonce, null]);
  const hash = createHash('sha256').update(handoverInfo).digest();
  const handover = ['OpenID4VPDCAPIHandover', hash];
  return cborEncode(DataItem.fromData([null, null, handover]));
}
