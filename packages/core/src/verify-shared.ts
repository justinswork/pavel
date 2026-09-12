/**
 * Shared verification core, protocol-agnostic.
 *
 * Both transports — OpenID4VP over DC-API (backend-owf.ts) and ISO 18013-7 Annex C
 * (iso-mdoc.ts) — end up with a decoded DeviceResponse and a SessionTranscript, then
 * run the SAME @owf/mdoc verification and map its assessment set onto the neutral
 * RawVerification. Only the decode + transcript differ per transport; the mapping,
 * trust anchors, and age-claim extraction live here.
 */
import { DeviceResponse, SessionTranscript, Verifier, type VerificationAssessment } from '@owf/mdoc';
import type { RawVerification } from './backend';
import { MDL_NAMESPACE } from './backend';
import { mdocContext } from './mdoc-context';

/** RawVerification for a presentation that never decoded → outcome `malformed`. */
export const NOT_DECODED: RawVerification = {
  decoded: false,
  issuerTrusted: false,
  authentic: false,
  withinValidity: false,
  deviceBound: false,
  ageClaims: {},
};

/** Strip the PEM armor and base64-decode a certificate to its DER bytes. */
export function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

/** Pull the disclosed age_over_NN booleans out of a decoded document. */
export function extractAgeClaims(response: DeviceResponse): Record<string, boolean> {
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

/**
 * Verify an already-decoded DeviceResponse against a transcript + trust anchors,
 * mapping @owf/mdoc's assessments onto RawVerification. @owf reports each check via
 * an onCheck callback with a stable `category`; we bucket by category, splitting the
 * ISSUER_AUTH category (cert trust vs. signature vs. MSO validity) by check text.
 */
export async function verifyDecodedResponse(params: {
  response: DeviceResponse;
  sessionTranscript: SessionTranscript;
  trustedIssuance: Uint8Array[];
}): Promise<RawVerification> {
  const { response, sessionTranscript, trustedIssuance } = params;
  const docType = response.documents?.[0]?.docType;
  const ageClaims = extractAgeClaims(response);

  const failed: VerificationAssessment[] = [];
  let threw = false;
  try {
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
    issuerTrusted:
      !issuerAuthFailed('trusted issuance chain') &&
      !issuerAuthFailed('Issuer certificate must be valid') &&
      !issuerAuthFailed('Country name'),
    authentic:
      !issuerAuthFailed('signature is invalid') &&
      !failedIn('DATA_INTEGRITY') &&
      !failedIn('DOCUMENT_FORMAT') &&
      !(threw && failed.length === 0),
    withinValidity:
      !issuerAuthFailed('valid at the time of verification') &&
      !issuerAuthFailed('within the validity period'),
    deviceBound: !failedIn('DEVICE_AUTH'),
    ageClaims,
  };
}
