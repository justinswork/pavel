/**
 * End-to-end middleware test: an Express app with pavel() + requireAgeProof,
 * driven through the full ceremony by mock_authority (issuer + wallet) and
 * verified via pavel-core's real @owf/mdoc backend. No mocks in the crypto path.
 */
import { describe, it, expect } from 'vitest';
import express, { type Express } from 'express';
import session from 'express-session';
import request from 'supertest';
import { MockAuthority, MockWallet } from '@justinswork/pavel-mock-authority';
import { pavel, requireAgeProof } from '../src/index';

const ORIGIN = 'http://localhost';

function buildApp(trustAnchors: string[]): Express {
  const app = express();
  app.use(express.json());
  app.use(session({ secret: 'test-secret', resave: false, saveUninitialized: true }));
  app.use(pavel({ trustAnchors, origin: ORIGIN }));
  app.post('/gated', requireAgeProof({ minAge: 21 }), (_req, res) => {
    res.json({ ok: true, content: 'secret' });
  });
  return app;
}

/** Run the wallet side of the ceremony against a challenge, returning the vp_token. */
async function present(
  authority: MockAuthority,
  nonce: string,
  ageOver: number[] = [21],
): Promise<string> {
  const wallet = new MockWallet(await authority.issueMdl({ ageOver }));
  return wallet.present({ nonce, origin: ORIGIN, disclose: ['age_over_21'] });
}

describe('pavel middleware ceremony', () => {
  it('verifies a real presentation, then lets the gate through', async () => {
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor]));

    // Gate is closed before verification.
    await agent.post('/gated').expect(401);

    // Mint the challenge, present against it, verify.
    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    expect(reqRes.body.nonce).toBeTruthy();
    const vpToken = await present(authority, reqRes.body.nonce);

    await agent
      .post('/pavel/verify')
      .send({ vp_token: vpToken })
      .expect(200)
      .expect((res) => expect(res.body).toEqual({ ok: true, outcome: 'verified' }));

    // Gate now opens.
    await agent
      .post('/gated')
      .expect(200)
      .expect((res) => expect(res.body.content).toBe('secret'));
  });

  it('rejects a presentation from an untrusted authority and keeps the gate closed', async () => {
    const good = await MockAuthority.create();
    const evil = await MockAuthority.create();
    const agent = request.agent(buildApp([good.trustAnchor]));

    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    const vpToken = await present(evil, reqRes.body.nonce);

    await agent
      .post('/pavel/verify')
      .send({ vp_token: vpToken })
      .expect(400)
      .expect((res) => expect(res.body.outcome).toBe('untrusted_issuer'));

    await agent.post('/gated').expect(401);
  });

  it('rejects a replayed presentation bound to a stale challenge', async () => {
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor]));

    // Present against a challenge the server never issued.
    const vpToken = await present(authority, 'never-issued-nonce');
    // First mint a real (different) challenge so a pending request exists.
    await agent.get('/pavel/request?minAge=21').expect(200);

    await agent
      .post('/pavel/verify')
      .send({ vp_token: vpToken })
      .expect(400)
      .expect((res) => expect(res.body.outcome).toBe('replay'));
  });

  it('401s with a machine-readable hint when unverified', async () => {
    const authority = await MockAuthority.create();
    await request(buildApp([authority.trustAnchor]))
      .post('/gated')
      .expect(401)
      .expect((res) =>
        expect(res.body).toEqual({
          error: 'age_verification_required',
          requestUrl: '/pavel/request?minAge=21',
        }),
      );
  });
});
