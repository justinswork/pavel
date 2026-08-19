/**
 * Golden-vector fixture generator.
 *
 * Mints one DeviceResponse per verification outcome, mutating the encoded bytes
 * where a tamper case calls for it, then SELF-CHECKS each against the real
 * pavel-core backend before writing it out. The committed fixtures are therefore
 * guaranteed to produce their stated outcome; regenerating replaces them wholesale
 * (fresh keys/salts each run — see test/fixtures/README.md).
 *
 * Run: pnpm --filter @justinswork/pavel-mock-authority gen:fixtures
 */
import { fileURLToPath } from 'node:url';
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { MockAuthority, MockWallet } from '../src/index';
import { createOwfMdocBackend, verifyPresentation, type VerifyResult } from '@justinswork/pavel-core';

const OUT_DIR = fileURLToPath(new URL('../../core/test/fixtures/', import.meta.url));
const ORIGIN = 'https://shop.example';
const NONCE = 'golden-nonce-01';
const YEAR_MS = 365 * 24 * 3600 * 1000;
const CENTURY_DAYS = 365 * 100;
const farFuture = () => new Date(Date.now() + 100 * YEAR_MS);

const b64urlToBytes = (s: string) =>
  new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
const bytesToB64url = (b: Uint8Array) =>
  Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

/** Find the first occurrence of a byte subsequence, or -1. */
function indexOfSeq(haystack: Uint8Array, needle: number[]): number {
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

/** Flip a byte inside the first 64-byte bstr (0x58 0x40 …) — the issuerAuth signature. */
function tamperIssuerAuthSignature(token: string): string {
  const bytes = b64urlToBytes(token);
  const at = indexOfSeq(bytes, [0x58, 0x40]);
  if (at === -1) throw new Error('could not locate a 64-byte bstr (issuerAuth signature)');
  bytes[at + 2] ^= 0xff; // first byte of the signature
  return bytesToB64url(bytes);
}

/** Flip the leading letter of the disclosed family_name value "Doe" → digest mismatch. */
function flipDisclosedFamilyName(token: string): string {
  const bytes = b64urlToBytes(token);
  const at = indexOfSeq(bytes, [0x63, 0x44, 0x6f, 0x65]); // CBOR tstr(3) "Doe"
  if (at === -1) throw new Error('could not locate the disclosed "Doe" value');
  bytes[at + 1] = 0x58; // 'D' → 'X'
  return bytesToB64url(bytes);
}

interface Vector {
  file: string;
  vpToken: string;
  context: { nonce: string; expectedOrigin: string; minAge: number };
  expected: VerifyResult;
}

const ctx = (over: Partial<Vector['context']> = {}): Vector['context'] => ({
  nonce: NONCE,
  expectedOrigin: ORIGIN,
  minAge: 21,
  ...over,
});

async function build(): Promise<{ trustAnchor: string; vectors: Vector[] }> {
  const good = await MockAuthority.create({ validityDays: CENTURY_DAYS });
  const evil = await MockAuthority.create({ validityDays: CENTURY_DAYS });
  const present = (w: MockWallet, disclose: string[]) => w.present({ nonce: NONCE, origin: ORIGIN, disclose });

  // A valid over-21 credential, disclosing only the predicate.
  const validToken = await present(
    new MockWallet(await good.issueMdl({ ageOver: [18, 21], validUntil: farFuture() })),
    ['age_over_21'],
  );
  // The same, also disclosing family_name so we can corrupt that value's digest.
  const flipToken = await present(
    new MockWallet(await good.issueMdl({ ageOver: [18, 21], validUntil: farFuture() })),
    ['age_over_21', 'family_name'],
  );

  const vectors: Vector[] = [
    { file: 'valid.json', vpToken: validToken, context: ctx(), expected: { outcome: 'verified', predicate: 'age_over_21' } },
    { file: 'tampered-issuerauth.json', vpToken: tamperIssuerAuthSignature(validToken), context: ctx(), expected: { outcome: 'malformed' } },
    { file: 'flipped-value.json', vpToken: flipDisclosedFamilyName(flipToken), context: ctx(), expected: { outcome: 'malformed' } },
    {
      file: 'expired.json',
      vpToken: await present(
        new MockWallet(
          await good.issueMdl({
            ageOver: [18, 21],
            validFrom: new Date(Date.now() - 2 * YEAR_MS),
            validUntil: new Date(Date.now() - YEAR_MS),
          }),
        ),
        ['age_over_21'],
      ),
      context: ctx(),
      expected: { outcome: 'expired' },
    },
    { file: 'wrong-origin.json', vpToken: validToken, context: ctx({ expectedOrigin: 'https://evil.example' }), expected: { outcome: 'replay' } },
    { file: 'stale-nonce.json', vpToken: validToken, context: ctx({ nonce: 'a-different-nonce-99' }), expected: { outcome: 'replay' } },
    {
      file: 'untrusted-issuer.json',
      vpToken: await present(new MockWallet(await evil.issueMdl({ ageOver: [18, 21] })), ['age_over_21']),
      context: ctx(),
      expected: { outcome: 'untrusted_issuer' },
    },
    {
      file: 'predicate-false.json',
      vpToken: await present(new MockWallet(await good.issueMdl({ ageOver: [18], claims: { age_over_21: false } })), ['age_over_21']),
      context: ctx(),
      expected: { outcome: 'predicate_false', predicate: 'age_over_21' },
    },
    {
      file: 'predicate-absent.json',
      vpToken: await present(new MockWallet(await good.issueMdl({ ageOver: [18] })), ['age_over_18']),
      context: ctx(),
      expected: { outcome: 'predicate_unavailable', predicate: 'age_over_21' },
    },
  ];

  return { trustAnchor: good.trustAnchor, vectors };
}

async function main() {
  const { trustAnchor, vectors } = await build();
  const backend = createOwfMdocBackend({ trustAnchors: [trustAnchor] });

  mkdirSync(OUT_DIR, { recursive: true });
  writeFileSync(path.join(OUT_DIR, 'trust-anchor.pem'), trustAnchor.trimEnd() + '\n');

  for (const { file, vpToken, context, expected } of vectors) {
    // Self-check: the fixture must actually produce its stated outcome.
    const actual = await verifyPresentation(vpToken, context, backend);
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      throw new Error(`${file}: expected ${JSON.stringify(expected)} but backend returned ${JSON.stringify(actual)}`);
    }
    writeFileSync(path.join(OUT_DIR, file), JSON.stringify({ vpToken, context, expected }, null, 2) + '\n');
    console.log(`✓ ${file.padEnd(26)} → ${expected.outcome}`);
  }
  console.log(`\nWrote ${vectors.length} vectors + trust-anchor.pem to ${OUT_DIR}`);
}

main().catch((err) => {
  console.error('\nFIXTURE GENERATION FAILED:', err?.stack ?? err);
  process.exit(1);
});
