/**
 * The production verification backend for OpenID4VP over the DC-API (Chrome).
 *
 * Decodes the base64url vp_token into a DeviceResponse, builds the OpenID4VP DC-API
 * SessionTranscript, and hands both to the shared verifier (verify-shared.ts). The
 * ISO 18013-7 path (iso-mdoc.ts, Safari) reuses that same shared core with a
 * different decode + transcript.
 */
import { DeviceResponse } from '@owf/mdoc';
import type { MdocBackend, RawVerification } from './backend';
import type { VerifyContext } from './types';
import { dcApiSessionTranscript } from './session-transcript';
import { NOT_DECODED, pemToDer, verifyDecodedResponse } from './verify-shared';

export interface OwfMdocBackendOptions {
  /** Trusted IACA root certificates (PEM). */
  trustAnchors: string[];
}

/** Create a verification backend backed by @owf/mdoc and the given trust anchors. */
export function createOwfMdocBackend(options: OwfMdocBackendOptions): MdocBackend {
  const trustedIssuance = options.trustAnchors.map(pemToDer);

  return {
    async verify(vpToken: string, ctx: VerifyContext): Promise<RawVerification> {
      let response: DeviceResponse;
      try {
        response = DeviceResponse.fromEncodedForOid4Vp(vpToken);
      } catch {
        return { ...NOT_DECODED };
      }
      const sessionTranscript = await dcApiSessionTranscript(ctx.expectedOrigin, ctx.nonce);
      return verifyDecodedResponse({ response, sessionTranscript, trustedIssuance });
    },
  };
}
