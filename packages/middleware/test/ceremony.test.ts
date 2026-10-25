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
import { cborDecode } from '@owf/mdoc';
import { createGoogleReader, type GoogleVerifierConfig } from '@justinswork/pavel-core';
import { pavel, requireAgeProof, type AppleVerifierConfig } from '../src/index';

const ORIGIN = 'http://localhost';

function buildApp(
  trustAnchors: string[],
  origin: string = ORIGIN,
  google?: GoogleVerifierConfig,
  apple?: AppleVerifierConfig,
): Express {
  const app = express();
  app.use(express.json());
  app.use(session({ secret: 'test-secret', resave: false, saveUninitialized: true }));
  app.use(pavel({ trustAnchors, origin, google, apple }));
  app.post('/gated', requireAgeProof({ minAge: 21 }), (_req, res) => {
    res.json({ ok: true, content: 'secret' });
  });
  // One-shot gate; ?fail=1 makes the gated action itself fail (500).
  app.post('/one-shot', requireAgeProof({ minAge: 21, forceReverify: true }), (req, res) => {
    if (req.query.fail) {
      res.status(500).json({ ok: false });
      return;
    }
    res.json({ ok: true });
  });
  // App-owned session data, to check it survives session regeneration.
  app.post('/stash', (req, res) => {
    (req.session as unknown as Record<string, unknown>).stash = 'keep-me';
    res.json({ ok: true });
  });
  app.get('/stash', (req, res) => {
    res.json({ stash: (req.session as unknown as Record<string, unknown>).stash ?? null });
  });
  return app;
}

/** The session cookie (name=value) from a response's Set-Cookie header. */
function sessionCookie(res: { headers: Record<string, unknown> }): string | undefined {
  const cookies = (res.headers['set-cookie'] as string[] | undefined) ?? [];
  return cookies.find((c) => c.startsWith('connect.sid='))?.split(';')[0];
}

/** Run a full openid4vp ceremony on an agent and expect it verified. */
async function verifyOn(agent: ReturnType<typeof request.agent>, authority: MockAuthority) {
  const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
  const vpToken = await present(authority, oid4vpNonce(reqRes));
  return agent.post('/pavel/verify').send({ vp_token: vpToken }).expect(200);
}

/** Decode a JWT payload without a library (test-only). */
function jwtPayload(jwt: string): Record<string, any> {
  return JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));
}

type RequestBody = {
  body: { requests: Array<{ protocol: string; data: Record<string, unknown> }> };
};
const oid4vpNonce = (r: RequestBody): string =>
  (r.body.requests.find((x) => x.protocol === 'openid4vp-v1-unsigned')!.data as { nonce: string }).nonce;
const isoRequest = (r: RequestBody): { deviceRequest: string; encryptionInfo: string } =>
  r.body.requests.find((x) => x.protocol === 'org-iso-mdoc')!.data as {
    deviceRequest: string;
    encryptionInfo: string;
  };

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
    const nonce = oid4vpNonce(reqRes);
    expect(nonce).toBeTruthy();
    const vpToken = await present(authority, nonce);

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
    const vpToken = await present(evil, oid4vpNonce(reqRes));

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

  it('normalizes a trailing-slash origin so deviceAuth binding still matches', async () => {
    // A stray trailing slash on the configured origin must not break verification:
    // the wallet binds to the bare web origin, the middleware normalizes to match.
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor], `${ORIGIN}/`));

    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    const vpToken = await present(authority, oid4vpNonce(reqRes));

    await agent
      .post('/pavel/verify')
      .send({ vp_token: vpToken })
      .expect(200)
      .expect((res) => expect(res.body).toEqual({ ok: true, outcome: 'verified' }));
  });

  it('verifies an org-iso-mdoc (Safari) presentation through the endpoints', async () => {
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor]));

    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    const iso = isoRequest(reqRes);
    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const response = await wallet.presentIso({
      encryptionInfoBase64Url: iso.encryptionInfo,
      origin: ORIGIN,
      disclose: ['age_over_21'],
    });

    await agent
      .post('/pavel/verify')
      .send({ protocol: 'org-iso-mdoc', response })
      .expect(200)
      .expect((res) => expect(res.body).toEqual({ ok: true, outcome: 'verified' }));

    await agent
      .post('/gated')
      .expect(200)
      .expect((res) => expect(res.body.content).toBe('secret'));
  });

  it('verifies a Google Wallet (signed/encrypted OpenID4VP) presentation through the endpoints', async () => {
    const authority = await MockAuthority.create();
    const { reader } = await createGoogleReader();
    const google: GoogleVerifierConfig = { origin: ORIGIN, reader, gwRpMetadataBytes: 'c2FtcGxl' };
    const agent = request.agent(buildApp([authority.trustAnchor], ORIGIN, google));

    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    const entry = (reqRes.body.requests as Array<{ protocol: string; data: { request: string } }>).find(
      (x) => x.protocol === 'openid4vp-v1-signed',
    );
    expect(entry).toBeTruthy(); // the signed protocol is offered first
    const payload = jwtPayload(entry!.data.request);
    const encPubJwk = payload.client_metadata.jwks.keys[0];

    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const response = await wallet.presentGoogle({
      origin: ORIGIN,
      nonce: payload.nonce,
      encryptionPublicJwk: encPubJwk,
      disclose: ['age_over_21'],
    });

    await agent
      .post('/pavel/verify')
      .send({ protocol: 'openid4vp-v1-signed', response })
      .expect(200)
      .expect((res) => expect(res.body).toEqual({ ok: true, outcome: 'verified' }));

    await agent
      .post('/gated')
      .expect(200)
      .expect((res) => expect(res.body.content).toBe('secret'));
  });

  it('signs the org-iso-mdoc request when an Apple certificate is configured, and still verifies', async () => {
    const authority = await MockAuthority.create();
    const { reader } = await createGoogleReader({ commonName: 'PAVEL Test Apple Reader' });
    const agent = request.agent(buildApp([authority.trustAnchor], ORIGIN, undefined, { reader }));

    const reqRes = await agent.get('/pavel/request?minAge=21').expect(200);
    const iso = isoRequest(reqRes);
    const deviceRequest = cborDecode(new Uint8Array(Buffer.from(iso.deviceRequest, 'base64url'))) as Map<string, unknown>;
    expect(deviceRequest.get('version')).toBe('1.1');
    expect(deviceRequest.has('readerAuthAll')).toBe(true);

    const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
    const response = await wallet.presentIso({
      encryptionInfoBase64Url: iso.encryptionInfo,
      origin: ORIGIN,
      disclose: ['age_over_21'],
    });
    await agent
      .post('/pavel/verify')
      .send({ protocol: 'org-iso-mdoc', response })
      .expect(200)
      .expect((res) => expect(res.body).toEqual({ ok: true, outcome: 'verified' }));
  });

  it('issues a new session ID on verification, keeps app session data, and the old ID stays unverified', async () => {
    const authority = await MockAuthority.create();
    const app = buildApp([authority.trustAnchor]);
    const agent = request.agent(app);

    const before = sessionCookie(await agent.post('/stash').expect(200));
    expect(before).toBeTruthy();
    const after = sessionCookie(await verifyOn(agent, authority));
    expect(after).toBeTruthy();
    expect(after).not.toBe(before); // fresh session ID

    await agent.get('/stash').expect(200).expect((res) => expect(res.body.stash).toBe('keep-me'));
    await agent.post('/gated').expect(200);
    // Someone holding the pre-verification session ID (session fixation) gets nothing.
    await request(app).post('/gated').set('Cookie', before!).expect(401);
  });

  it('a forceReverify proof can be spent only once, even by concurrent requests', async () => {
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor]));
    await verifyOn(agent, authority);

    const results = await Promise.all([1, 2, 3].map(() => agent.post('/one-shot')));
    expect(results.map((r) => r.status).sort()).toEqual([200, 401, 401]);
    await agent.post('/one-shot').expect(401); // spent
  });

  it('a failed gated action does not spend the forceReverify proof', async () => {
    const authority = await MockAuthority.create();
    const agent = request.agent(buildApp([authority.trustAnchor]));
    await verifyOn(agent, authority);

    await agent.post('/one-shot?fail=1').expect(500);
    await agent.post('/one-shot').expect(200);
    await agent.post('/one-shot').expect(401);
  });

  it('401s with a machine-readable hint when unverified', async () => {
    const authority = await MockAuthority.create();
    await request(buildApp([authority.trustAnchor]))
      .post('/gated')
      .expect(401)
      .expect((res) =>
        expect(res.body).toEqual({
          error: 'age_verification_required',
          minAge: 21,
          requestUrl: '/pavel/request?minAge=21',
        }),
      );
  });
});
