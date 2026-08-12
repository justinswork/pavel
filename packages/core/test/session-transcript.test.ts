import { describe, it, expect } from 'vitest';
import { dcApiSessionTranscript } from '../src/session-transcript';

const bytes = async (origin: string, nonce: string) =>
  Buffer.from((await dcApiSessionTranscript(origin, nonce)).encode());

describe('dcApiSessionTranscript', () => {
  it('is deterministic for the same origin + nonce', async () => {
    const a = await bytes('https://shop.example', 'nonce-abc');
    const b = await bytes('https://shop.example', 'nonce-abc');
    expect(a.equals(b)).toBe(true);
  });

  it('differs when the origin differs (audience binding)', async () => {
    const a = await bytes('https://shop.example', 'nonce-abc');
    const b = await bytes('https://evil.example', 'nonce-abc');
    expect(a.equals(b)).toBe(false);
  });

  it('differs when the nonce differs (freshness)', async () => {
    const a = await bytes('https://shop.example', 'nonce-abc');
    const b = await bytes('https://shop.example', 'nonce-xyz');
    expect(a.equals(b)).toBe(false);
  });
});
