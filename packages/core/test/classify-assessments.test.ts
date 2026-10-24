/**
 * The verdict mapping must FAIL CLOSED: trust, authenticity, validity, and device binding
 * are only granted on positive PASSED evidence, so a reworded, missing, or unknown check
 * (e.g. after an @owf/mdoc upgrade) can never let a credential through.
 */
import { describe, it, expect } from 'vitest';
import { classifyAssessments } from '../src/verify-shared';

const ISSUER = [
  'Country name (C) must be present in the issuer certificate\'s subject distinguished name',
  'Issuer certificate must be valid',
  'Issuer auth signature is invalid',
  'The MSO signed date must be within the validity period of the certificate',
  'The MSO must be valid at the time of verification',
  'Unable to determine a trusted issuance chain for the provided trusted certificates and the signer of the issuer auth',
];

const passed = (category: string, check: string) => ({ status: 'PASSED', category, check }) as const;
const failed = (category: string, check: string) => ({ status: 'FAILED', category, check }) as const;

/** Everything @owf/mdoc reports for a valid, trusted presentation. */
const allPassed = () => [...ISSUER.map((c) => passed('ISSUER_AUTH', c)), passed('DEVICE_AUTH', 'Device signature must be valid')];

describe('classifyAssessments (fail-closed verdicts)', () => {
  it('grants every verdict when all checks are reported PASSED', () => {
    expect(classifyAssessments(allPassed() as any, false)).toEqual({
      issuerTrusted: true,
      authentic: true,
      withinValidity: true,
      deviceBound: true,
    });
  });

  it('denies trust when the chain check is never reported (no positive evidence)', () => {
    const items = allPassed().filter((a) => !a.check.includes('trusted issuance chain'));
    expect(classifyAssessments(items as any, false).issuerTrusted).toBe(false);
  });

  it('denies trust for a reworded chain failure the mapping does not recognize', () => {
    const items = [
      ...allPassed().filter((a) => !a.check.includes('trusted issuance chain')),
      failed('ISSUER_AUTH', 'Certificate chain is not anchored in a configured trust root'),
    ];
    expect(classifyAssessments(items as any, false).issuerTrusted).toBe(false);
  });

  it('denies trust for any unknown FAILED issuer check, even if the known ones passed', () => {
    const items = [...allPassed(), failed('ISSUER_AUTH', 'Some new check added in a future release')];
    expect(classifyAssessments(items as any, false).issuerTrusted).toBe(false);
  });

  it('denies authenticity when the signature check is missing', () => {
    const items = allPassed().filter((a) => !a.check.includes('Issuer auth signature'));
    expect(classifyAssessments(items as any, false).authentic).toBe(false);
  });

  it('denies authenticity for an unexplained throw with no recorded failure', () => {
    expect(classifyAssessments(allPassed() as any, true).authentic).toBe(false);
  });

  it('denies validity when the MSO validity check fails, leaving trust intact', () => {
    const items = [
      ...allPassed().filter((a) => !a.check.includes('valid at the time')),
      failed('ISSUER_AUTH', 'The MSO must be valid at the time of verification'),
    ];
    const v = classifyAssessments(items as any, true);
    expect(v.withinValidity).toBe(false);
    expect(v.issuerTrusted).toBe(true);
  });

  it('denies device binding without a PASSED device-auth check', () => {
    const items = allPassed().filter((a) => a.category !== 'DEVICE_AUTH');
    expect(classifyAssessments(items as any, false).deviceBound).toBe(false);
  });
});
