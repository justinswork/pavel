/**
 * The production verification backend: wraps @owf/mdoc's Verifier.
 *
 * Runs the full verification once and maps @owf/mdoc's assessment set onto the
 * neutral RawVerification. Like @auth0/mdl before it, @owf/mdoc merges holder
 * binding and freshness into a single deviceAuth verdict, so a DEVICE_AUTH
 * failure surfaces as `replay` (see pipeline.ts).
 *
 * @owf reports each check through an `onCheck` callback with a stable `category`
 * plus a human-readable `check` string. We bucket by category, splitting the
 * ISSUER_AUTH category (which covers cert trust, issuer signature, and the MSO
 * validity window) by check text so the outcomes stay distinct.
 */
import { DeviceResponse, Verifier, type VerificationAssessment } from '@owf/mdoc';
import type { MdocBackend, RawVerification } from './backend';
import { MDL_NAMESPACE } from './backend';
import type { VerifyContext } from './types';
import { dcApiSessionTranscript } from './session-transcript';
import { mdocContext } from './mdoc-context';

export interface OwfMdocBackendOptions {
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

/** Strip the PEM armor and base64-decode a certificate to its DER bytes. */
function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

/** Pull the disclosed age_over_NN booleans out of a decoded document. */
function extractAgeClaims(response: DeviceResponse): Record<string, boolean> {
  const claims: Record<string, boolean> = {};
  let disclosed: Record<string, unknown> | undefined;
  try {
    disclosed = response.documents?.[0]?.issuerSigned.getPrettyClaims(MDL_NAMESPACE) as
      | Record<string, unknown>
      | undefined;
  } catch {
    return claims;
  }
  for (const [key, value] of Object.entries(disclosed ?? {})) {
    if (key.startsWith('age_over_') && typeof value === 'boolean') claims[key] = value;
  }
  return claims;
}

/** Create a verification backend backed by @owf/mdoc and the given trust anchors. */
export function createOwfMdocBackend(options: OwfMdocBackendOptions): MdocBackend {
  const trustedIssuance = options.trustAnchors.map(pemToDer);

  return {
    async verify(vpToken: string, ctx: VerifyContext): Promise<RawVerification> {
      // Structural decode (independent of the crypto verdict) → docType + claims.
      let response: DeviceResponse;
      try {
        response = DeviceResponse.fromEncodedForOid4Vp(vpToken);
      } catch {
        return { ...NOT_DECODED };
      }
      const docType = response.documents?.[0]?.docType;
      const ageClaims = extractAgeClaims(response);

      // Full verification, collecting failed assessments without rethrowing.
      const failed: VerificationAssessment[] = [];
      let threw = false;
      try {
        const sessionTranscript = await dcApiSessionTranscript(ctx.expectedOrigin, ctx.nonce);
        await Verifier.verifyDeviceResponse(
          {
            deviceResponse: response,
            sessionTranscript,
            trustedCertificates: [{ issuance: trustedIssuance }],
            disableStatusValidation: true,
            onCheck: (item) => {
              if (item.status === 'FAILED') failed.push(item);
            },
          },
          mdocContext,
        );
      } catch {
        threw = true;
      }

      const failedIn = (category: VerificationAssessment['category']) =>
        failed.some((f) => f.category === category);
      const issuerAuthFailed = (match: string) =>
        failed.some((f) => f.category === 'ISSUER_AUTH' && f.check.includes(match));

      return {
        decoded: true,
        docType,
        // Cert chain doesn't reach a trusted anchor, or the DS cert is invalid.
        issuerTrusted:
          !issuerAuthFailed('trusted issuance chain') &&
          !issuerAuthFailed('Issuer certificate must be valid') &&
          !issuerAuthFailed('Country name'),
        // Issuer signature or a disclosed-item digest failed — or it threw before
        // recording anything, which means we couldn't authenticate it.
        authentic:
          !issuerAuthFailed('signature is invalid') &&
          !failedIn('DATA_INTEGRITY') &&
          !failedIn('DOCUMENT_FORMAT') &&
          !(threw && failed.length === 0),
        // MSO validity window (or its consistency with the DS cert).
        withinValidity:
          !issuerAuthFailed('valid at the time of verification') &&
          !issuerAuthFailed('within the validity period'),
        // deviceAuth over the session transcript: holder binding + freshness.
        deviceBound: !failedIn('DEVICE_AUTH'),
        ageClaims,
      };
    },
  };
}
