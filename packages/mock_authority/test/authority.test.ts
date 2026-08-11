import { describe, it, expect } from 'vitest';
import { Verifier } from '@auth0/mdl';
import { MockAuthority, MockWallet } from '../src/index';
import { dcApiSessionTranscript } from '@justinswork/pavel-core';

const ORIGIN = 'https://shop.example';
const NONCE = 'server-minted-nonce-abc';

/** Verify a vp_token, collecting all assessments instead of throwing on failure. */
async function verify(vpToken: Uint8Array, trustAnchor: string, st: Buffer) {
  const assessments: { status: string; category: string; id: string }[] = [];
  let mdoc: any;
  try {
    mdoc = await new Verifier([trustAnchor]).verify(vpToken, {
      encodedSessionTranscript: st,
      onCheck: (item: any, original: any) => {
        assessments.push({ status: item.status, category: item.category, id: item.id });
        if (item.status !== 'FAILED') original(item);
      },
    });
  } catch {
    /* assessments already captured */
  }
  return { assessments, mdoc };
}

describe('MockAuthority + MockWallet', () => {
  it('issues an mDL that presents and verifies against its own trust anchor', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    const st = dcApiSessionTranscript(ORIGIN, NONCE);
    const { assessments, mdoc } = await verify(vpToken, authority.trustAnchor, st);

    expect(assessments.filter((a) => a.status === 'FAILED')).toEqual([]);
    const disclosed = mdoc.documents[0].getIssuerNameSpace('org.iso.18013.5.1');
    expect(disclosed.age_over_21).toBe(true);
    expect(disclosed.given_name).toBeUndefined(); // selective disclosure
  });

  it('rejects a credential from an untrusted authority', async () => {
    const evil = await MockAuthority.create();
    const good = await MockAuthority.create();
    const wallet = new MockWallet(await evil.issueMdl());
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    const { assessments } = await verify(vpToken, good.trustAnchor, dcApiSessionTranscript(ORIGIN, NONCE));
    expect(assessments.some((a) => a.category === 'ISSUER_AUTH' && a.status === 'FAILED')).toBe(true);
  });

  it('rejects a presentation replayed under a different origin (deviceAuth binding)', async () => {
    const authority = await MockAuthority.create();
    const wallet = new MockWallet(await authority.issueMdl());
    const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });

    const wrongSt = dcApiSessionTranscript('https://evil.example', NONCE);
    const { assessments } = await verify(vpToken, authority.trustAnchor, wrongSt);
    expect(assessments.some((a) => a.id === 'DEVICE_SIGNATURE_VALIDITY' && a.status === 'FAILED')).toBe(true);
  });
});
