import { describe, it, expect } from 'vitest';
import { DeviceResponse, Verifier, type VerificationAssessment } from '@owf/mdoc';
import { MockAuthority, MockWallet } from '../src/index';
import { dcApiSessionTranscript, mdocContext } from '@justinswork/pavel-core';

const ORIGIN = 'https://shop.example';
const NONCE = 'server-minted-nonce-abc';
const MDL_NAMESPACE = 'org.iso.18013.5.1';

function pemToDer(pem: string): Uint8Array {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  return new Uint8Array(Buffer.from(body, 'base64'));
}

/** Verify a vp_token, collecting all assessments instead of throwing on failure. */
async function verify(vpToken: string, trustAnchor: string, origin: string, nonce: string) {
  const assessments: VerificationAssessment[] = [];
  const sessionTranscript = await dcApiSessionTranscript(origin, nonce);
  let result: Awaited<ReturnType<typeof Verifier.verifyDeviceResponse>> | undefined;
  try {
    result = await Verifier.verifyDeviceResponse(
      {
        deviceResponse: DeviceResponse.fromEncodedForOid4Vp(vpToken),
        sessionTranscript,
        trustedCertificates: [{ issuance: [pemToDer(trustAnchor)] }],
        disableStatusValidation: true,
        onCheck: (item) => assessments.push(item),
      },
      mdocContext,
    );
  } catch {
    /* assessments already captured */
  }
  return { assessments, result };
}

const failed = (assessments: VerificationAssessment[]) =>
  assessments.filter((a) => a.status === 'FAILED');

describe('MockAuthority + MockWallet', () => {
  it('issues an mDL that presents and verifies against its own trust anchor', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    const { assessments, result } = await verify(vpToken, authority.trustAnchor, ORIGIN, NONCE);

    expect(failed(assessments)).toEqual([]);
    const disclosed = result?.[0]?.document.issuerSigned.getPrettyClaims(MDL_NAMESPACE) as
      | Record<string, unknown>
      | undefined;
    expect(disclosed?.age_over_21).toBe(true);
    expect(disclosed?.given_name).toBeUndefined(); // selective disclosure
  });

  it('rejects a credential from an untrusted authority', async () => {
    const evil = await MockAuthority.create();
    const good = await MockAuthority.create();
    const wallet = new MockWallet(await evil.issueMdl());
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    const { assessments } = await verify(vpToken, good.trustAnchor, ORIGIN, NONCE);
    expect(failed(assessments).some((a) => a.category === 'ISSUER_AUTH')).toBe(true);
  });

  it('rejects a presentation replayed under a different origin (deviceAuth binding)', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl());
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    // Verify against a different origin → recomputed transcript no longer matches.
    const { assessments } = await verify(vpToken, authority.trustAnchor, 'https://evil.example', NONCE);
    expect(failed(assessments).some((a) => a.category === 'DEVICE_AUTH')).toBe(true);
  });
});
