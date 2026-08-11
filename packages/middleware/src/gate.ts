/**
 * requireAgeProof — gate a route on the session's verified flag.
 *
 * On failure responds 401 with a machine-readable hint the client SDK acts on.
 */
import type { RequestHandler } from 'express';
import type { RequireAgeProofOptions } from './types';

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
      // One-shot: consume the proof once the gated action succeeds (status < 400),
      // so the next gated request must re-verify. Failures don't burn it.
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
