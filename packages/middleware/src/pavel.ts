/**
 * The ceremony endpoints: GET /pavel/request (mint the challenge) and
 * POST /pavel/verify (verify the presentation via pavel-core's real backend).
 *
 * The nonce/session/origin plumbing is here; all credential crypto is delegated
 * to pavel-core.
 */
import { randomBytes } from 'node:crypto';
import { Router, type Request } from 'express';
import {
  buildAgeRequest,
  buildIsoMdocAgeRequest,
  buildGoogleAgeRequest,
  verifyPresentation,
  verifyIsoMdocPresentation,
  verifyGooglePresentation,
  createOwfMdocBackend,
} from '@justinswork/pavel-core';
import type { PavelOptions } from './types';

const DEFAULT_NONCE_TTL_MS = 5 * 60 * 1000;

/**
 * Swap the session for one with a new ID, carrying the app's own session data (e.g. a cart)
 * across. PAVEL's state is left behind: the caller writes the verified state afterwards.
 */
function regenerateSession(req: Request): Promise<void> {
  const carried: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(req.session)) {
    if (key !== 'cookie' && key !== 'pavel' && key !== 'pavelPending') carried[key] = value;
  }
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      Object.assign(req.session, carried);
      resolve();
    });
  });
}

function parseMinAge(raw: unknown): number | null {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 120) return null;
  return n;
}

/** Mount the ceremony endpoints. Use with `app.use(pavel({ ... }))`. */
export function pavel(options: PavelOptions): Router {
  const { trustAnchors, clientName, google, apple } = options;
  // A web origin has no trailing slash; a stray one changes the DC-API handover
  // bytes so deviceAuth never matches — every presentation would read as replay.
  const origin = options.origin.replace(/\/+$/, '');
  const nonceTtlMs = options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS;
  const backend = createOwfMdocBackend({ trustAnchors });
  const router = Router();

  // GET /pavel/request?minAge=NN — mint a single-use challenge. Offers BOTH DC-API
  // protocols so the browser picks: openid4vp (Chrome) or org-iso-mdoc (Safari).
  router.get('/pavel/request', async (req, res) => {
    const minAge = parseMinAge(req.query.minAge);
    if (minAge === null) {
      res.status(400).json({ error: 'invalid_min_age' });
      return;
    }
    const nonce = randomBytes(16).toString('base64url');
    const openid4vp = buildAgeRequest({ minAge, nonce, origin, clientName });
    // Signed for this origin when an Apple certificate is configured (needed for real IDs).
    const iso = await buildIsoMdocAgeRequest({ minAge, ...(apple ? { reader: apple.reader, origin } : {}) });

    const pending = {
      nonce,
      minAge,
      expiresAt: Date.now() + nonceTtlMs,
      isoEphemeralPrivateKeyJwk: iso.ephemeralPrivateKeyJwk,
      isoEncryptionInfoBase64Url: iso.encryptionInfoBase64Url,
    } as typeof req.session.pavelPending & object;

    // Google Wallet "real ID" (signed/encrypted) — offered FIRST when configured, since
    // Google Wallet processes the first request it recognizes. Other wallets (CMWallet,
    // Safari) match their own protocol entry regardless of order.
    const requests: Array<{ protocol: string; data: unknown }> = [];
    if (google) {
      const g = await buildGoogleAgeRequest({
        minAge,
        nonce,
        origin,
        reader: google.reader,
        gwRpMetadataBytes: google.gwRpMetadataBytes,
      });
      pending.googleEncryptionPrivateKeyJwk = g.encryptionPrivateKeyJwk;
      requests.push({ protocol: g.protocol, data: g.data });
    }
    requests.push({ protocol: 'openid4vp-v1-unsigned', data: openid4vp });
    requests.push({ protocol: 'org-iso-mdoc', data: iso.data });

    req.session.pavelPending = pending;
    res.json({ requests });
  });

  // POST /pavel/verify — verify a presentation, routing by protocol:
  //   { vp_token }             → OpenID4VP (Chrome)
  //   { protocol: 'org-iso-mdoc', response } → ISO 18013-7 encrypted (Safari)
  router.post('/pavel/verify', async (req, res) => {
    const pending = req.session.pavelPending;
    const body = (req.body ?? {}) as { protocol?: unknown; vp_token?: unknown; response?: unknown };

    if (!pending) {
      // No challenge in flight → nothing to bind to; treat as replay/stale.
      res.status(400).json({ ok: false, outcome: 'replay' });
      return;
    }
    if (pending.expiresAt < Date.now()) {
      delete req.session.pavelPending;
      res.status(400).json({ ok: false, outcome: 'expired' });
      return;
    }

    // Route by protocol. Google (openid4vp-v1-signed) and ISO (org-iso-mdoc) both carry
    // an encrypted `response`; the protocol string disambiguates. A bare `response` with
    // no protocol is treated as ISO (back-compat).
    const isGoogle = body.protocol === 'openid4vp-v1-signed';
    const isIso = !isGoogle && (body.protocol === 'org-iso-mdoc' || body.response !== undefined);

    let result: { outcome: string; predicate?: string };
    try {
      if (isGoogle) {
        if (!pending.googleEncryptionPrivateKeyJwk) {
          delete req.session.pavelPending;
          res.status(400).json({ ok: false, outcome: 'malformed' });
          return;
        }
        result = await verifyGooglePresentation({
          encryptedResponse: body.response,
          encryptionPrivateKeyJwk: pending.googleEncryptionPrivateKeyJwk,
          expectedOrigin: origin,
          nonce: pending.nonce,
          minAge: pending.minAge,
          trustAnchors,
        });
      } else if (isIso) {
        if (!pending.isoEphemeralPrivateKeyJwk || !pending.isoEncryptionInfoBase64Url) {
          delete req.session.pavelPending;
          res.status(400).json({ ok: false, outcome: 'malformed' });
          return;
        }
        result = await verifyIsoMdocPresentation({
          encryptedResponse: body.response,
          ephemeralPrivateKeyJwk: pending.isoEphemeralPrivateKeyJwk,
          encryptionInfoBase64Url: pending.isoEncryptionInfoBase64Url,
          expectedOrigin: origin,
          minAge: pending.minAge,
          trustAnchors,
        });
      } else {
        if (typeof body.vp_token !== 'string') {
          delete req.session.pavelPending;
          res.status(400).json({ ok: false, outcome: 'malformed' });
          return;
        }
        result = await verifyPresentation(
          body.vp_token,
          { nonce: pending.nonce, expectedOrigin: origin, minAge: pending.minAge },
          backend,
        );
      }
    } catch {
      delete req.session.pavelPending;
      res.status(500).json({ ok: false, outcome: 'malformed' });
      return;
    }

    // Consume the challenge regardless of outcome — single use.
    delete req.session.pavelPending;

    if (result.outcome === 'verified') {
      // The session gains privilege here, so give it a fresh ID (prevents session fixation).
      try {
        await regenerateSession(req);
      } catch {
        res.status(500).json({ ok: false, outcome: 'malformed' });
        return;
      }
      req.session.pavel = {
        verified: true,
        verifiedMinAge: pending.minAge,
        verifiedAt: Date.now(),
        proofId: randomBytes(16).toString('base64url'),
      };
      res.json({ ok: true, outcome: result.outcome });
      return;
    }
    res.status(400).json({ ok: false, outcome: result.outcome, predicate: result.predicate });
  });

  return router;
}
