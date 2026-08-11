/**
 * The production verification backend: wraps @auth0/mdl's Verifier.
 *
 * Runs the full verification once and maps @auth0/mdl's assessment set onto the
 * neutral RawVerification. @auth0/mdl merges holder binding and freshness into a
 * single deviceAuth verdict, so a failure there surfaces as `replay`
 * (see pipeline.ts).
 */
import { Verifier, parse } from '@auth0/mdl';
import type { MdocBackend, RawVerification } from './backend';
import { MDL_NAMESPACE } from './backend';
import type { VerifyContext } from './types';
import { dcApiSessionTranscript } from './session-transcript';

export interface Auth0MdocBackendOptions {
  /** Trusted IACA root certificates (PEM). */
  trustAnchors: string[];
}

const NOT_DECODED: RawVerification = {
  decoded: false,
  issuerTrusted: false,
  authentic: false,
  withinValidity: false,
  deviceBound: false,
  ageClaims: {},
};

function base64urlToBytes(input: string): Uint8Array {
  const pad = input.length % 4 === 0 ? '' : '='.repeat(4 - (input.length % 4));
  const b64 = input.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

/** Pull the disclosed age_over_NN booleans out of a verified document. */
function extractAgeClaims(document: unknown): Record<string, boolean> {
  const getNs = (document as { getIssuerNameSpace?: (ns: string) => Record<string, unknown> })
    ?.getIssuerNameSpace;
  if (typeof getNs !== 'function') return {};
  let ns: Record<string, unknown>;
  try {
    ns = getNs.call(document, MDL_NAMESPACE) ?? {};
  } catch {
    return {};
  }
  const claims: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(ns)) {
    if (key.startsWith('age_over_') && typeof value === 'boolean') claims[key] = value;
  }
  return claims;
}

/** Create a verification backend backed by @auth0/mdl and the given trust anchors. */
export function createAuth0MdocBackend(options: Auth0MdocBackendOptions): MdocBackend {
  const trustAnchors = [...options.trustAnchors];

  return {
    async verify(vpToken: string, ctx: VerifyContext): Promise<RawVerification> {
      let bytes: Uint8Array;
      try {
        bytes = base64urlToBytes(vpToken);
      } catch {
        return { ...NOT_DECODED };
      }

      // Structural decode (independent of the crypto verdict) → docType.
      let docType: string | undefined;
      try {
        docType = (parse(bytes).documents[0] as { docType?: string } | undefined)?.docType;
      } catch {
        return { ...NOT_DECODED };
      }

      // Full verification, collecting failed assessment ids without rethrowing.
      const failed = new Set<string>();
      let verified: { documents: unknown[] } | undefined;
      let threw = false;
      try {
        verified = (await new Verifier(trustAnchors).verify(bytes, {
          encodedSessionTranscript: dcApiSessionTranscript(ctx.expectedOrigin, ctx.nonce),
          onCheck: (item: any, original: any) => {
            if (item.status === 'FAILED') failed.add(item.id);
            else original(item);
          },
        })) as unknown as { documents: unknown[] };
      } catch {
        threw = true;
      }

      const failedAny = (...ids: string[]) => ids.some((id) => failed.has(id));

      return {
        decoded: true,
        docType,
        issuerTrusted: !failedAny('ISSUER_CERTIFICATE_VALIDITY'),
        authentic:
          !failedAny('ISSUER_SIGNATURE_VALIDITY', 'ATTRIBUTE_DIGEST_MATCH') &&
          // A hard throw with nothing recorded means we couldn't authenticate it.
          !(threw && failed.size === 0),
        withinValidity: !failedAny('MSO_VALIDITY_AT_VERIFICATION_TIME'),
        deviceBound: !failedAny('DEVICE_SIGNATURE_VALIDITY'),
        ageClaims: verified ? extractAgeClaims(verified.documents[0]) : {},
      };
    },
  };
}
