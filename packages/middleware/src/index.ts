/** @justinswork/pavel — Express middleware for the PAVEL age-verification ceremony. */

export { pavel } from './pavel';
export { requireAgeProof } from './gate';
export type {
  PavelOptions,
  RequireAgeProofOptions,
  PavelSessionState,
  PendingRequest,
} from './types';
