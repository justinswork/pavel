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
 * The ISSUER_AUTH checks @owf/mdoc reports (same text for PASSED and FAILED), keyed by
 * the verdict each one feeds. Matched by substring of the check text.
 */
const ISSUER_CHECKS = {
  trustChain: 'trusted issuance chain',
  certificateValid: 'Issuer certificate must be valid',
  countryName: 'Country name',
  signature: 'Issuer auth signature',
  msoValidNow: 'valid at the time of verification',
  msoSignedInCertValidity: 'within the validity period',
} as const;

type Assessment = Pick<VerificationAssessment, 'status' | 'category' | 'check'>;

/**
 * Turn @owf/mdoc's assessments into the security verdicts, FAIL-CLOSED: a verdict is true
 * only when the checks behind it were positively reported PASSED (and none FAILED). An
 * unrecognized FAILED issuer check counts against trust, so a reworded or new check in a
 * library update can never silently let a credential through.
 */
export function classifyAssessments(
  assessments: Assessment[],
  threw: boolean,
): Pick<RawVerification, 'issuerTrusted' | 'authentic' | 'withinValidity' | 'deviceBound'> {
  const failed = assessments.filter((a) => a.status === 'FAILED');
  const failedIn = (category: string) => failed.some((f) => f.category === category);
  const passedIn = (category: string) =>
    assessments.some((a) => a.status === 'PASSED' && a.category === category) && !failedIn(category);
  const issuerPassed = (match: string) =>
    assessments.some((a) => a.status === 'PASSED' && a.category === 'ISSUER_AUTH' && a.check.includes(match)) &&
    !failed.some((f) => f.category === 'ISSUER_AUTH' && f.check.includes(match));
  const known = Object.values(ISSUER_CHECKS);
  const unknownIssuerFailure = failed.some(
    (f) => f.category === 'ISSUER_AUTH' && !known.some((m) => f.check.includes(m)),
  );

  return {
    issuerTrusted:
      issuerPassed(ISSUER_CHECKS.trustChain) &&
      issuerPassed(ISSUER_CHECKS.certificateValid) &&
      issuerPassed(ISSUER_CHECKS.countryName) &&
      !unknownIssuerFailure,
    authentic:
      issuerPassed(ISSUER_CHECKS.signature) &&
      !failedIn('DATA_INTEGRITY') &&
      !failedIn('DOCUMENT_FORMAT') &&
      // A throw with no recorded failure is unexplained, so it can't count as authentic.
      !(threw && failed.length === 0),
    withinValidity:
      issuerPassed(ISSUER_CHECKS.msoValidNow) && issuerPassed(ISSUER_CHECKS.msoSignedInCertValidity),
    deviceBound: passedIn('DEVICE_AUTH'),
  };
}

/**
 * Verify an already-decoded DeviceResponse against a transcript + trust anchors,
 * mapping @owf/mdoc's assessments onto RawVerification via classifyAssessments.
 */
export async function verifyDecodedResponse(params: {
  response: DeviceResponse;
  sessionTranscript: SessionTranscript;
  trustedIssuance: Uint8Array[];
}): Promise<RawVerification> {
  const { response, sessionTranscript, trustedIssuance } = params;
  const docType = response.documents?.[0]?.docType;
  const ageClaims = extractAgeClaims(response);

  const assessments: Assessment[] = [];
  let threw = false;
  try {
    await Verifier.verifyDeviceResponse(
      {
        deviceResponse: response,
        sessionTranscript,
        trustedCertificates: [{ issuance: trustedIssuance }],
        disableStatusValidation: true,
        onCheck: (item) => {
          assessments.push(item);
        },
      },
      mdocContext,
    );
  } catch {
    threw = true;
  }

  return { decoded: true, docType, ...classifyAssessments(assessments, threw), ageClaims };
}
