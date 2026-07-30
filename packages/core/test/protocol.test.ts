import { describe, it, expect } from 'vitest';
import { normalizeProtocol, isSupportedProtocol, SUPPORTED_PROTOCOLS } from '../src/protocol';

describe('normalizeProtocol', () => {
  it('passes canonical protocol strings through', () => {
    expect(normalizeProtocol('openid4vp')).toBe('openid4vp');
    expect(normalizeProtocol('org-iso-mdoc')).toBe('org-iso-mdoc');
  });

  it('folds known aliases and casing onto a canonical value', () => {
    expect(normalizeProtocol('org.iso.mdoc')).toBe('org-iso-mdoc');
    expect(normalizeProtocol('OpenID4VP')).toBe('openid4vp');
  });

  it('throws on an unrecognized protocol', () => {
    expect(() => normalizeProtocol('siopv2')).toThrow(/unsupported protocol/);
  });
});

describe('isSupportedProtocol', () => {
  it('is true for every supported protocol', () => {
    for (const p of SUPPORTED_PROTOCOLS) expect(isSupportedProtocol(p)).toBe(true);
  });

  it('is false for anything else', () => {
    expect(isSupportedProtocol('nonsense')).toBe(false);
  });
});
