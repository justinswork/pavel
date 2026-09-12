import { describe, it, expect } from 'vitest';
import { webcrypto } from 'node:crypto';
import { hpkeSeal, hpkeOpen } from '../src/hpke';

const enc = new TextEncoder();
const dec = new TextDecoder();

async function genKeyPairJwk() {
  const kp = (await webcrypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveBits',
  ])) as webcrypto.CryptoKeyPair;
  return {
    publicKeyJwk: (await webcrypto.subtle.exportKey('jwk', kp.publicKey)) as unknown as Record<string, unknown>,
    privateKeyJwk: (await webcrypto.subtle.exportKey('jwk', kp.privateKey)) as unknown as Record<string, unknown>,
  };
}

describe('hpke', () => {
  it('seals and opens a round trip bound to info', async () => {
    const { publicKeyJwk, privateKeyJwk } = await genKeyPairJwk();
    const info = enc.encode('session-transcript-bytes');
    const { enc: encapsulated, ciphertext } = await hpkeSeal({
      recipientPublicKeyJwk: publicKeyJwk,
      info,
      plaintext: enc.encode('the DeviceResponse'),
    });
    const opened = await hpkeOpen({ recipientPrivateKeyJwk: privateKeyJwk, enc: encapsulated, info, ciphertext });
    expect(dec.decode(opened)).toBe('the DeviceResponse');
    expect(encapsulated.length).toBe(65); // uncompressed P-256 point
  });

  it('fails to open when info differs (transcript binding)', async () => {
    const { publicKeyJwk, privateKeyJwk } = await genKeyPairJwk();
    const { enc: encapsulated, ciphertext } = await hpkeSeal({
      recipientPublicKeyJwk: publicKeyJwk,
      info: enc.encode('transcript-A'),
      plaintext: enc.encode('x'),
    });
    await expect(
      hpkeOpen({ recipientPrivateKeyJwk: privateKeyJwk, enc: encapsulated, info: enc.encode('transcript-B'), ciphertext }),
    ).rejects.toBeDefined();
  });

  it('fails to open with a different recipient key', async () => {
    const a = await genKeyPairJwk();
    const b = await genKeyPairJwk();
    const info = enc.encode('t');
    const { enc: encapsulated, ciphertext } = await hpkeSeal({
      recipientPublicKeyJwk: a.publicKeyJwk,
      info,
      plaintext: enc.encode('x'),
    });
    await expect(
      hpkeOpen({ recipientPrivateKeyJwk: b.privateKeyJwk, enc: encapsulated, info, ciphertext }),
    ).rejects.toBeDefined();
  });
});
