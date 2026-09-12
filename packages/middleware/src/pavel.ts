/**
 * The ceremony endpoints: GET /pavel/request (mint the challenge) and
 * POST /pavel/verify (verify the presentation via pavel-core's real backend).
 *
 * The nonce/session/origin plumbing is here; all credential crypto is delegated
 * to pavel-core.
 */
import { randomBytes } from 'node:crypto';
import { Router } from 'express';
import {
  buildAgeRequest,
  buildIsoMdocAgeRequest,
  verifyPresentation,
  verifyIsoMdocPresentation,
  createOwfMdocBackend,
} from '@justinswork/pavel-core';
import type { PavelOptions } from './types';

const DEFAULT_NONCE_TTL_MS = 5 * 60 * 1000;

function parseMinAge(raw: unknown): number | null {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 120) return null;
  return n;
}

/** Mount the ceremony endpoints. Use with `app.use(pavel({ ... }))`. */
export function pavel(options: PavelOptions): Router {
  const { trustAnchors, clientName } = options;
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
    const iso = await buildIsoMdocAgeRequest({ minAge });

    req.session.pavelPending = {
      nonce,
      minAge,
      expiresAt: Date.now() + nonceTtlMs,
      isoEphemeralPrivateKeyJwk: iso.ephemeralPrivateKeyJwk,
      isoEncryptionInfoBase64Url: iso.encryptionInfoBase64Url,
    };

    res.json({
      requests: [
        { protocol: 'openid4vp-v1-unsigned', data: openid4vp },
        { protocol: 'org-iso-mdoc', data: iso.data },
      ],
    });
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

    const isIso = body.protocol === 'org-iso-mdoc' || body.response !== undefined;

    let result: { outcome: string; predicate?: string };
    try {
      if (isIso) {
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
      req.session.pavel = {
        verified: true,
        verifiedMinAge: pending.minAge,
        verifiedAt: Date.now(),
      };
      res.json({ ok: true, outcome: result.outcome });
      return;
    }
    res.status(400).json({ ok: false, outcome: result.outcome, predicate: result.predicate });
  });

  return router;
}
