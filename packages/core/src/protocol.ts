/**
 * Protocol normalization.
 *
 * Safari speaks `org-iso-mdoc`; Chrome speaks both `openid4vp` and `org-iso-mdoc`.
 * pavel-client may emit either; -core normalizes both into one canonical value so
 * the rest of the pipeline is protocol-agnostic.
 */

export const SUPPORTED_PROTOCOLS = ['openid4vp', 'org-iso-mdoc'] as const;
export type Protocol = (typeof SUPPORTED_PROTOCOLS)[number];

/** Known spellings that map onto a canonical protocol string. */
const ALIASES: Record<string, Protocol> = {
  openid4vp: 'openid4vp',
  'org-iso-mdoc': 'org-iso-mdoc',
  'org.iso.mdoc': 'org-iso-mdoc',
};

export function isSupportedProtocol(input: string): boolean {
  return input.toLowerCase() in ALIASES;
}

/** Normalize a wallet/response protocol string, or throw if unrecognized. */
export function normalizeProtocol(input: string): Protocol {
  const canonical = ALIASES[input.toLowerCase()];
  if (!canonical) {
    throw new Error(`unsupported protocol: ${input}`);
  }
  return canonical;
}
