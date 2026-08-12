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
  verifyPresentation,
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
  const { origin, trustAnchors, clientName } = options;
  const nonceTtlMs = options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS;
  const backend = createOwfMdocBackend({ trustAnchors });
  const router = Router();

  // GET /pavel/request?minAge=NN — mint a single-use nonce, return the request.
  router.get('/pavel/request', (req, res) => {
    const minAge = parseMinAge(req.query.minAge);
    if (minAge === null) {
      res.status(400).json({ error: 'invalid_min_age' });
      return;
    }
    const nonce = randomBytes(16).toString('base64url');
    req.session.pavelPending = { nonce, minAge, expiresAt: Date.now() + nonceTtlMs };
    res.json(buildAgeRequest({ minAge, nonce, origin, clientName }));
  });

  // POST /pavel/verify { vp_token } — verify, set the session flag on success.
  router.post('/pavel/verify', async (req, res) => {
    const pending = req.session.pavelPending;
    const vpToken: unknown = (req.body as { vp_token?: unknown } | undefined)?.vp_token;

    if (!pending) {
      // No nonce in flight → nothing to bind to; treat as replay/stale.
      res.status(400).json({ ok: false, outcome: 'replay' });
      return;
    }
    if (typeof vpToken !== 'string') {
      res.status(400).json({ ok: false, outcome: 'malformed' });
      return;
    }
    if (pending.expiresAt < Date.now()) {
      delete req.session.pavelPending;
      res.status(400).json({ ok: false, outcome: 'expired' });
      return;
    }

    let outcome: string;
    let predicate: string | undefined;
    try {
      const result = await verifyPresentation(
        vpToken,
        { nonce: pending.nonce, expectedOrigin: origin, minAge: pending.minAge },
        backend,
      );
      outcome = result.outcome;
      predicate = result.predicate;
    } catch {
      delete req.session.pavelPending;
      res.status(500).json({ ok: false, outcome: 'malformed' });
      return;
    }

    // Consume the nonce regardless of outcome — single use.
    delete req.session.pavelPending;

    if (outcome === 'verified') {
      req.session.pavel = {
        verified: true,
        verifiedMinAge: pending.minAge,
        verifiedAt: Date.now(),
      };
      res.json({ ok: true, outcome });
      return;
    }
    res.status(400).json({ ok: false, outcome, predicate });
  });

  return router;
}
