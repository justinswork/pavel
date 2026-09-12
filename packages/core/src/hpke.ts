/**
 * HPKE (RFC 9180) single-shot encryption for the ISO 18013-7 Annex C DC-API path.
 *
 * ISO 18013-7 fixes one suite: DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM,
 * with the CBOR SessionTranscript as the HPKE `info` and an empty aad. The wallet
 * seals the DeviceResponse to the reader's ephemeral public key; the verifier opens
 * it with the matching private key. @owf/mdoc leaves HPKE to the caller, so we own it.
 */
import { Aes128Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from '@hpke/core';

/** The one suite ISO 18013-7 Annex C permits. */
function isoSuite(): CipherSuite {
  return new CipherSuite({
    kem: new DhkemP256HkdfSha256(),
    kdf: new HkdfSha256(),
    aead: new Aes128Gcm(),
  });
}

const toBytes = (b: ArrayBuffer): Uint8Array => new Uint8Array(b);
/** @hpke/core takes ArrayBuffers; hand it a standalone buffer for any Uint8Array view. */
const toBuf = (u: Uint8Array): ArrayBuffer =>
  u.byteOffset === 0 && u.byteLength === u.buffer.byteLength
    ? (u.buffer as ArrayBuffer)
    : (u.slice().buffer as ArrayBuffer);

// The recipient key is imported by @hpke/core, which owns the WebCrypto key usages;
// the JWK type there is DOM's JsonWebKey, absent from this package's lib — cast at the edge.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Jwk = any;

export interface HpkeSealResult {
  /** Encapsulated key — a 65-byte uncompressed P-256 point. */
  enc: Uint8Array;
  ciphertext: Uint8Array;
}

/** Seal plaintext to the recipient's public key (JWK), binding it to `info`. */
export async function hpkeSeal(params: {
  recipientPublicKeyJwk: Record<string, unknown>;
  info: Uint8Array;
  plaintext: Uint8Array;
}): Promise<HpkeSealResult> {
  const suite = isoSuite();
  const recipientPublicKey = await suite.kem.importKey('jwk', params.recipientPublicKeyJwk as Jwk, true);
  const sender = await suite.createSenderContext({ recipientPublicKey, info: toBuf(params.info) });
  const ciphertext = toBytes(await sender.seal(toBuf(params.plaintext)));
  return { enc: toBytes(sender.enc), ciphertext };
}

/** Open an HPKE ciphertext with the recipient's private key (JWK), binding it to `info`. */
export async function hpkeOpen(params: {
  recipientPrivateKeyJwk: Record<string, unknown>;
  enc: Uint8Array;
  info: Uint8Array;
  ciphertext: Uint8Array;
}): Promise<Uint8Array> {
  const suite = isoSuite();
  const recipientKey = await suite.kem.importKey('jwk', params.recipientPrivateKeyJwk as Jwk, false);
  const recipient = await suite.createRecipientContext({
    recipientKey,
    enc: toBuf(params.enc),
    info: toBuf(params.info),
  });
  return toBytes(await recipient.open(toBuf(params.ciphertext)));
}
