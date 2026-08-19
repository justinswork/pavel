/**
 * Golden-vector integration tests for the REAL mdoc backend.
 *
 * The highest-confidence correctness tests: one committed, base64url `DeviceResponse`
 * per scenario (test/fixtures/*.json), verified end-to-end through the actual
 * CBOR/COSE/PKI backend — no fakes. Fixtures are minted by pavel-mock-authority;
 * regenerate with `pnpm --filter @justinswork/pavel-mock-authority gen:fixtures`.
 * See test/fixtures/README.md.
 */
import { describe, it, expect } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import {
  createOwfMdocBackend,
  verifyPresentation,
  type VerifyContext,
  type VerifyResult,
} from '../src/index';

interface Fixture {
  vpToken: string;
  context: VerifyContext;
  expected: VerifyResult;
}

const FIXTURES_DIR = fileURLToPath(new URL('./fixtures/', import.meta.url));
const trustAnchor = readFileSync(path.join(FIXTURES_DIR, 'trust-anchor.pem'), 'utf8');
const backend = createOwfMdocBackend({ trustAnchors: [trustAnchor] });

const fixtureFiles = readdirSync(FIXTURES_DIR)
  .filter((f) => f.endsWith('.json'))
  .sort();

describe('real mdoc backend · golden vectors', () => {
  it('has a fixture for every outcome the pipeline can report', () => {
    // Guards against a fixture silently disappearing and taking its coverage with it.
    expect(fixtureFiles.length).toBe(9);
  });

  for (const file of fixtureFiles) {
    const fixture = JSON.parse(readFileSync(path.join(FIXTURES_DIR, file), 'utf8')) as Fixture;
    it(`${file} → ${fixture.expected.outcome}`, async () => {
      const result = await verifyPresentation(fixture.vpToken, fixture.context, backend);
      expect(result).toEqual(fixture.expected);
    });
  }
});
