/**
 * Golden-vector integration tests for the REAL mdoc backend.
 *
 * These are the highest-confidence correctness tests: a real CBOR `DeviceResponse`
 * per scenario, verified end-to-end through the actual CBOR/COSE/PKI backend (no
 * fakes). They are `todo` until two things exist:
 *
 *   1. The mdoc-library spike settles the backend implementation.
 *   2. pavel-authority can mint the fixtures below into test/fixtures/ — see
 *      test/fixtures/README.md.
 *
 * Fill each in by loading the fixture and asserting the pipeline outcome, exactly
 * as pipeline.test.ts does with the fake backend.
 */

import { describe, it } from 'vitest';

describe('real mdoc backend · golden vectors', () => {
  it.todo('verifies a valid authority-issued DeviceResponse → verified');
  it.todo('rejects a tampered issuerAuth signature → malformed');
  it.todo('rejects a flipped disclosed elementValue (digest mismatch) → malformed');
  it.todo('rejects a credential outside its validity window → expired');
  it.todo('rejects a presentation bound to a different origin → replay');
  it.todo('rejects a presentation bound to a stale/other nonce → replay');
  it.todo('rejects a document signer that does not chain to a trusted IACA → untrusted_issuer');
  it.todo('reports predicate_false when age_over_21 is signed false');
  it.todo('reports predicate_unavailable when age_over_21 was never issued');
});
