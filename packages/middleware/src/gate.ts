/**
 * requireAgeProof — gate a route on the session's verified flag.
 *
 * On failure responds 401 with a machine-readable hint the client SDK acts on.
 */
import type { RequestHandler, Response } from 'express';
import type { RequireAgeProofOptions } from './types';

/**
 * One-shot proofs (forceReverify) that are claimed or already spent, by proofId. A gate
 * claims a proof synchronously before running the action, so concurrent requests carrying
 * the same session can't all pass before the first one finishes. This is per process: a
 * multi-instance deployment needs a shared store for the same guarantee.
 */
const claimedProofs = new Map<string, number>();
const CLAIM_TTL_MS = 24 * 60 * 60 * 1000;

function pruneClaims(now: number): void {
  for (const [id, claimedAt] of claimedProofs) if (now - claimedAt > CLAIM_TTL_MS) claimedProofs.delete(id);
}

function deny(res: Response, minAge: number): void {
  res.status(401).json({
    error: 'age_verification_required',
    requestUrl: `/pavel/request?minAge=${minAge}`,
  });
}

export function requireAgeProof({
  minAge,
  forceReverify = false,
}: RequireAgeProofOptions): RequestHandler {
  return (req, res, next) => {
    const state = req.session.pavel;
    const satisfied = Boolean(state?.verified && (state.verifiedMinAge ?? 0) >= minAge);
    if (!satisfied) return deny(res, minAge);

    if (forceReverify) {
      const proofId = state?.proofId;
      const now = Date.now();
      pruneClaims(now);
      if (!proofId || claimedProofs.has(proofId)) return deny(res, minAge);
      claimedProofs.set(proofId, now);

      // On success the proof is spent: clear it from the session (it also stays claimed, so a
      // request holding a stale copy of the session can't reuse it). On failure, release the
      // claim so the user can retry without re-verifying.
      res.on('finish', () => {
        if (res.statusCode < 400) {
          if (req.session.pavel?.proofId === proofId) {
            req.session.pavel = { verified: false };
            req.session.save(() => {});
          }
        } else {
          claimedProofs.delete(proofId);
        }
      });
    }
    next();
  };
}
