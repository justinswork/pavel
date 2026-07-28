/**
 * MOCK of `@justinswork/pavel` (the Express middleware package).
 *
 * Public surface:
 *   - `pavel(options)`            → router mounting GET /pavel/request + POST /pavel/verify
 *   - `requireAgeProof({minAge})` → gate that checks the session flag
 *
 * The nonce/session/origin plumbing here is REAL. Only the credential crypto is
 * mocked, and that lives entirely in ./verify.ts.
 */

import { randomBytes } from 'node:crypto';
import { Router, type RequestHandler } from 'express';
import type { AuthorizationRequest, PavelOptions, RequireAgeProofOptions } from './types.js';
import { verifyPresentation } from './verify.js';

const DEFAULT_NONCE_TTL_MS = 5 * 60 * 1000;

function parseMinAge(raw: unknown): number | null {
  const n = Number(raw);
  if (!Number.isInteger(n) || n < 1 || n > 120) return null;
  return n;
}

/** Build the OpenID4VP Authorization Request for a single age predicate. */
function buildAuthorizationRequest(
  minAge: number,
  nonce: string,
  origin: string,
): AuthorizationRequest {
  return {
    response_type: 'vp_token',
    response_mode: 'dc_api',
    nonce,
    dcql_query: {
      credentials: [
        {
          id: 'age_check',
          format: 'mso_mdoc',
          meta: { doctype_value: 'org.iso.18013.5.1.mDL' },
          claims: [{ path: ['org.iso.18013.5.1', `age_over_${minAge}`] }],
        },
      ],
    },
    client_metadata: { client_name: 'PAVEL Demo Store' },
    expected_origin: origin,
  };
}

/**
 * The ceremony endpoints. Mount with `app.use(pavel({ ... }))`.
 */
export function pavel(options: PavelOptions): Router {
  const { origin } = options;
  const nonceTtlMs = options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS;
  const router = Router();

  // GET /pavel/request?minAge=NN — mint a single-use nonce and return the request.
  router.get('/pavel/request', (req, res) => {
    const minAge = parseMinAge(req.query.minAge);
    if (minAge === null) {
      res.status(400).json({ error: 'invalid_min_age' });
      return;
    }
    const nonce = randomBytes(16).toString('base64url');
    req.session.pavelPending = { nonce, minAge, expiresAt: Date.now() + nonceTtlMs };
    res.json(buildAuthorizationRequest(minAge, nonce, origin));
  });

  // POST /pavel/verify { vp_token } — run the pipeline, set the session flag.
  router.post('/pavel/verify', (req, res) => {
    const pending = req.session.pavelPending;
    const vpToken: unknown = req.body?.vp_token;

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

    const result = verifyPresentation(vpToken, {
      nonce: pending.nonce,
      expectedOrigin: origin,
      minAge: pending.minAge,
    });

    // Consume the nonce regardless of outcome — single use.
    delete req.session.pavelPending;

    if (result.outcome === 'verified') {
      // Carry over the user's cart; regenerate() starts a fresh, empty session.
      const cart = req.session.cart;
      // Session fixation mitigation: rotate the session id.
      req.session.regenerate((err) => {
        if (err) {
          res.status(500).json({ ok: false, outcome: 'malformed' });
          return;
        }
        req.session.cart = cart;
        req.session.pavel = {
          verified: true,
          verifiedMinAge: pending.minAge,
          verifiedAt: Date.now(),
        };
        res.json({ ok: true, outcome: result.outcome });
      });
      return;
    }

    res.status(400).json({ ok: false, outcome: result.outcome, predicate: result.predicate });
  });

  return router;
}

/**
 * Gate a route on the session's verified flag.
 * On failure responds 401 with a machine-readable hint the SDK acts on.
 *
 * With `forceReverify: true` the cached flag is treated as one-shot — see
 * RequireAgeProofOptions — so every gated action requires a fresh ceremony.
 */
export function requireAgeProof({
  minAge,
  forceReverify = false,
}: RequireAgeProofOptions): RequestHandler {
  return (req, res, next) => {
    const state = req.session.pavel;
    const satisfied = Boolean(state?.verified && (state.verifiedMinAge ?? 0) >= minAge);
    if (!satisfied) {
      res.status(401).json({
        error: 'age_verification_required',
        requestUrl: `/pavel/request?minAge=${minAge}`,
      });
      return;
    }
    if (forceReverify) {
      // Consume the proof once the gated action succeeds (status < 400), so the
      // next gated request must re-verify. Failures don't burn the verification.
      res.on('finish', () => {
        if (res.statusCode < 400 && req.session.pavel?.verified) {
          req.session.pavel = { verified: false };
          req.session.save(() => {});
        }
      });
    }
    next();
  };
}
