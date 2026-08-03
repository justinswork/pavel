import { describe, it, expect } from 'vitest';
import { dcApiSessionTranscript } from '../src/session-transcript';

describe('dcApiSessionTranscript', () => {
  it('is deterministic for the same origin + nonce', () => {
    const a = dcApiSessionTranscript('https://shop.example', 'nonce-abc');
    const b = dcApiSessionTranscript('https://shop.example', 'nonce-abc');
    expect(a.equals(b)).toBe(true);
  });

  it('differs when the origin differs (audience binding)', () => {
    const a = dcApiSessionTranscript('https://shop.example', 'nonce-abc');
    const b = dcApiSessionTranscript('https://evil.example', 'nonce-abc');
    expect(a.equals(b)).toBe(false);
  });

  it('differs when the nonce differs (freshness)', () => {
    const a = dcApiSessionTranscript('https://shop.example', 'nonce-abc');
    const b = dcApiSessionTranscript('https://shop.example', 'nonce-xyz');
    expect(a.equals(b)).toBe(false);
  });
});
