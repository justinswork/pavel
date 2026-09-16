/**
 * PAVEL verify-path performance baseline (tinybench).
 *
 * Measures the SERVER-SIDE verification work PAVEL owns — decode + crypto verify —
 * for both DC-API transports:
 *   - openid4vp  (Chrome): decode vp_token -> transcript -> verify
 *   - org-iso-mdoc (Safari): + HPKE open + ISO transcript
 * plus request-build cost (the ISO path does a P-256 ephemeral keygen per request).
 *
 * Wallet UI, browser, network, and the cross-device QR round-trip are OUT OF SCOPE —
 * none of that is PAVEL's code. Inputs are minted + presented ONCE via the mock
 * authority, then the measured operation is looped, so numbers reflect crypto/CBOR
 * cost only and are fully offline + deterministic.
 *
 * The "verify (crypto)" stage is Verifier.verifyDeviceResponse as one unit: @owf/mdoc
 * runs issuer COSE_Sign1, the X.509 chain, deviceAuth, and digest checks together, so
 * they can't be split at the public API — decode/transcript/HPKE, which can, are broken
 * out separately.
 *
 * Run: pnpm --filter @justinswork/pavel-mock-authority bench
 */
import os from 'node:os';
import { Bench } from 'tinybench';
import {
  DeviceResponse,
  SessionTranscript,
  Verifier,
} from '@owf/mdoc';
import {
  buildAgeRequest,
  buildIsoMdocAgeRequest,
  createOwfMdocBackend,
  dcApiSessionTranscript,
  hpkeOpen,
  mdocContext,
  parseEncryptedResponse,
  verifyIsoMdocPresentation,
  verifyPresentation,
} from '@justinswork/pavel-core';
import { MockAuthority, MockWallet } from '../src/index';

const ORIGIN = 'https://shop.example';
const NONCE = 'bench-nonce-0123456789abcdef';
const MIN_AGE = 21;
const MDL_NAMESPACE = 'org.iso.18013.5.1';

/** Strip PEM armor to DER (inlined so the bench stays on the public API surface). */
const pemToDer = (pem: string): Uint8Array =>
  new Uint8Array(Buffer.from(pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64'));

// ---- Setup (untimed): one trusted authority, one untrusted, minted + presented once.
const authority = await MockAuthority.create();
const other = await MockAuthority.create();
const trustAnchor = authority.trustAnchor;
const trustedIssuance = [pemToDer(trustAnchor)];

const wallet = new MockWallet(await authority.issueMdl({ ageOver: [18, 21] }));
const walletOther = new MockWallet(await other.issueMdl({ ageOver: [18, 21] }));

// openid4vp presentations (Chrome path).
const vpToken = await wallet.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });
const vpTokenUntrusted = await walletOther.present({ nonce: NONCE, origin: ORIGIN, disclose: ['age_over_21'] });
const backend = createOwfMdocBackend({ trustAnchors: [trustAnchor] });
const oid4vpCtx = { nonce: NONCE, expectedOrigin: ORIGIN, minAge: MIN_AGE };

// org-iso-mdoc presentation (Safari path).
const isoReq = await buildIsoMdocAgeRequest({ minAge: MIN_AGE });
const isoEncrypted = await wallet.presentIso({
  encryptionInfoBase64Url: isoReq.encryptionInfoBase64Url,
  origin: ORIGIN,
  disclose: ['age_over_21'],
});

// Precomputed intermediates so each stage times only its own work.
const oid4vpTranscript = await dcApiSessionTranscript(ORIGIN, NONCE);
const oid4vpDecoded = DeviceResponse.fromEncodedForOid4Vp(vpToken);
const isoTranscript = await SessionTranscript.forIsoMdocDcApi(
  { encryptionInfoBase64Url: isoReq.encryptionInfoBase64Url, origin: ORIGIN },
  mdocContext,
);
const isoParsed = parseEncryptedResponse(isoEncrypted);
const isoPlaintext = await hpkeOpen({
  recipientPrivateKeyJwk: isoReq.ephemeralPrivateKeyJwk,
  enc: isoParsed.enc,
  info: isoTranscript.encode(),
  ciphertext: isoParsed.ciphertext,
});
const isoDecoded = DeviceResponse.decode(isoPlaintext);

/** The bundled crypto verify (COSE + X.509 chain + deviceAuth + digests). */
const cryptoVerify = (response: DeviceResponse, transcript: SessionTranscript) =>
  Verifier.verifyDeviceResponse(
    {
      deviceResponse: response,
      sessionTranscript: transcript,
      trustedCertificates: [{ issuance: trustedIssuance }],
      disableStatusValidation: true,
      onCheck: () => {},
    },
    mdocContext,
  );

// Sanity: confirm the fixtures verify as expected before benchmarking them.
{
  const ok = await verifyPresentation(vpToken, oid4vpCtx, backend);
  const iso = await verifyIsoMdocPresentation({
    encryptedResponse: isoEncrypted,
    ephemeralPrivateKeyJwk: isoReq.ephemeralPrivateKeyJwk,
    encryptionInfoBase64Url: isoReq.encryptionInfoBase64Url,
    expectedOrigin: ORIGIN,
    minAge: MIN_AGE,
    trustAnchors: [trustAnchor],
  });
  if (ok.outcome !== 'verified' || iso.outcome !== 'verified') {
    throw new Error(`fixtures not verifying: oid4vp=${ok.outcome} iso=${iso.outcome}`);
  }
}

const bench = new Bench({ time: 2000, warmupTime: 400 });

bench
  // ---- Request build
  .add('build: openid4vp request', () => buildAgeRequest({ minAge: MIN_AGE, nonce: NONCE, origin: ORIGIN }))
  .add('build: org-iso-mdoc request (P-256 keygen)', async () => {
    await buildIsoMdocAgeRequest({ minAge: MIN_AGE });
  })
  // ---- openid4vp verify: total + stages
  .add('oid4vp: TOTAL verify (verified)', async () => {
    await verifyPresentation(vpToken, oid4vpCtx, backend);
  })
  .add('oid4vp: TOTAL verify (untrusted_issuer)', async () => {
    await verifyPresentation(vpTokenUntrusted, oid4vpCtx, backend);
  })
  .add('oid4vp: decode vp_token', () => {
    DeviceResponse.fromEncodedForOid4Vp(vpToken);
  })
  .add('oid4vp: build transcript', async () => {
    await dcApiSessionTranscript(ORIGIN, NONCE);
  })
  .add('oid4vp: verify (crypto)', async () => {
    await cryptoVerify(oid4vpDecoded, oid4vpTranscript);
  })
  .add('oid4vp: extract age claims', () => {
    oid4vpDecoded.documents?.[0]?.issuerSigned.getPrettyClaims(MDL_NAMESPACE);
  })
  // ---- org-iso-mdoc verify: total + stages
  .add('iso: TOTAL verify (verified)', async () => {
    await verifyIsoMdocPresentation({
      encryptedResponse: isoEncrypted,
      ephemeralPrivateKeyJwk: isoReq.ephemeralPrivateKeyJwk,
      encryptionInfoBase64Url: isoReq.encryptionInfoBase64Url,
      expectedOrigin: ORIGIN,
      minAge: MIN_AGE,
      trustAnchors: [trustAnchor],
    });
  })
  .add('iso: build transcript', async () => {
    await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url: isoReq.encryptionInfoBase64Url, origin: ORIGIN },
      mdocContext,
    );
  })
  .add('iso: HPKE open', async () => {
    const p = parseEncryptedResponse(isoEncrypted);
    await hpkeOpen({
      recipientPrivateKeyJwk: isoReq.ephemeralPrivateKeyJwk,
      enc: p.enc,
      info: isoTranscript.encode(),
      ciphertext: p.ciphertext,
    });
  })
  .add('iso: decode DeviceResponse', () => {
    DeviceResponse.decode(isoPlaintext);
  })
  .add('iso: verify (crypto)', async () => {
    await cryptoVerify(isoDecoded, isoTranscript);
  });

await bench.run();

// ---- Report
const pct = (samples: number[], p: number): number => {
  const a = [...samples].sort((x, y) => x - y);
  return a[Math.min(a.length - 1, Math.ceil((p / 100) * a.length) - 1)] ?? NaN;
};
const ms = (n: number) => n.toFixed(3);

const cpu = os.cpus()[0]?.model?.replace(/\s+/g, ' ').trim() ?? 'unknown';
console.log('\nPAVEL verify-path baseline');
console.log(`  node ${process.version} · ${os.type()} ${os.release()} ${os.arch()} · ${cpu} (${os.cpus().length} cores)`);
console.log(`  tinybench: ${bench.opts.warmupTime}ms warmup + ${bench.opts.time}ms measured per task\n`);

const rows = bench.tasks.map((t) => {
  const r = t.result!;
  const samples = r.latency.samples;
  return {
    task: t.name,
    'mean (ms)': ms(r.latency.mean),
    'p50 (ms)': ms(r.latency.p50),
    'p95 (ms)': ms(pct(samples, 95)),
    'p99 (ms)': ms(r.latency.p99),
    'ops/s': Math.round(r.throughput.mean).toLocaleString('en-US'),
    n: samples.length,
  };
});
console.table(rows);
