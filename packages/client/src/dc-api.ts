/**
 * The Digital Credentials API glue.
 *
 * The DC API (`navigator.credentials.get({ digital: … })`) is still emerging and
 * absent from TypeScript's DOM lib, so we declare the minimal surface we use.
 * This module wraps the authorization request in the DC API envelope, invokes the
 * OS wallet, and pulls the vp_token out of whatever shape the response arrives in.
 */

/** One protocol-tagged request handed to the wallet. */
export interface DigitalCredentialRequest {
  protocol: string;
  data: unknown;
}

declare global {
  interface DigitalCredentialGetRequest {
    requests: DigitalCredentialRequest[];
  }
  // Augment the standard options bag with the `digital` member.
  interface CredentialRequestOptions {
    digital?: DigitalCredentialGetRequest;
  }
  // The credential the wallet returns for a `digital` request.
  interface DigitalCredential extends Credential {
    readonly protocol: string;
    readonly data: unknown;
  }
  // eslint-disable-next-line no-var
  var DigitalCredential: { prototype: DigitalCredential } | undefined;
}

/** True when this browser exposes the Digital Credentials API. */
export function isDigitalCredentialsSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    !!navigator.credentials &&
    typeof navigator.credentials.get === 'function' &&
    typeof globalThis.DigitalCredential !== 'undefined'
  );
}

/** A user-dismissed / aborted wallet prompt surfaces as one of these DOMExceptions. */
export function isUserDismissal(err: unknown): boolean {
  return (
    !!err &&
    typeof err === 'object' &&
    'name' in err &&
    ((err as { name: string }).name === 'NotAllowedError' ||
      (err as { name: string }).name === 'AbortError')
  );
}

const BASE64URL = /^[A-Za-z0-9_-]+$/;

function safeJsonParse(input: string): unknown {
  try {
    return JSON.parse(input);
  } catch {
    return undefined;
  }
}

/** Coerce a vp_token entry to a string: a bare string, or the first string in an array. */
function asTokenString(value: unknown): string | null {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    const first = value.find((v) => typeof v === 'string');
    return typeof first === 'string' ? first : null;
  }
  return null;
}

/**
 * Pull the credential's vp_token out of a DC API response.
 *
 * The `data` may be a JSON envelope (string or object) or a bare token string.
 * Inside an envelope the vp_token may be a string, an array of presentations, or
 * a map keyed by DCQL credential id whose values are strings or arrays — the
 * OpenID4VP 1.0 shape is `{ vp_token: { <id>: ["<base64url>"] } }`. We normalize
 * all of those to the single base64url string the verifier expects.
 */
export function extractVpToken(data: unknown, credentialId: string): string | null {
  if (data == null) return null;

  let value: unknown = data;
  if (typeof value === 'string') {
    const parsed = safeJsonParse(value);
    // A JSON object/array envelope → dig in; otherwise the string itself is the token.
    if (parsed && typeof parsed === 'object') value = parsed;
    else return BASE64URL.test(value) ? value : null;
  }

  // Unwrap the OpenID4VP vp_token envelope if present.
  const container =
    value && typeof value === 'object' && 'vp_token' in value
      ? (value as { vp_token: unknown }).vp_token
      : value;

  const direct = asTokenString(container);
  if (direct) return direct;

  if (container && typeof container === 'object') {
    const map = container as Record<string, unknown>;
    const byId = asTokenString(map[credentialId]);
    if (byId) return byId;
    for (const entry of Object.values(map)) {
      const token = asTokenString(entry);
      if (token) return token;
    }
  }
  return null;
}

export interface PresentOptions {
  protocol: string;
  signal?: AbortSignal;
}

/**
 * Hand the authorization request to the wallet and return the raw credential it
 * presents, or null if the user presented nothing. Throws for API errors, which
 * the caller classifies via isUserDismissal. Token extraction is left to the
 * caller so it can surface a distinct outcome when a credential comes back
 * unreadable (vs. nothing presented at all).
 */
export async function presentViaWallet(
  authRequest: unknown,
  { protocol, signal }: PresentOptions,
): Promise<DigitalCredential | null> {
  const credential = (await navigator.credentials.get({
    digital: { requests: [{ protocol, data: authRequest }] },
    signal,
  })) as DigitalCredential | null;
  return credential ?? null;
}
