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

/**
 * Pull the credential's vp_token out of a DC API response.
 *
 * The `data` may be a JSON envelope (string or object) or a bare token string,
 * and inside an envelope the vp_token may itself be a string or a map keyed by
 * DCQL credential id (OpenID4VP `{ vp_token: { id: … } }`). We normalize all of
 * those to the single base64url string the verifier expects, and reject anything
 * that is neither an envelope nor a token-shaped string.
 */
export function extractVpToken(data: unknown, credentialId: string): string | null {
  if (data == null) return null;

  let value: unknown = data;
  if (typeof value === 'string') {
    const parsed = safeJsonParse(value);
    // A JSON object envelope → dig in; otherwise the string itself is the token.
    if (parsed && typeof parsed === 'object') value = parsed;
    else return BASE64URL.test(value) ? value : null;
  }

  if (value && typeof value === 'object') {
    const container =
      'vp_token' in value ? (value as { vp_token: unknown }).vp_token : value;
    if (typeof container === 'string') return container;
    if (container && typeof container === 'object') {
      const map = container as Record<string, unknown>;
      if (typeof map[credentialId] === 'string') return map[credentialId] as string;
      const firstString = Object.values(map).find((v) => typeof v === 'string');
      return typeof firstString === 'string' ? firstString : null;
    }
  }
  return null;
}

export interface PresentOptions {
  protocol: string;
  credentialId: string;
  signal?: AbortSignal;
}

/**
 * Hand the authorization request to the wallet and return the vp_token, or null
 * if the wallet returned no credential (dismissed). Throws for API errors, which
 * the caller classifies via isUserDismissal.
 */
export async function presentViaWallet(
  authRequest: unknown,
  { protocol, credentialId, signal }: PresentOptions,
): Promise<string | null> {
  const credential = (await navigator.credentials.get({
    digital: { requests: [{ protocol, data: authRequest }] },
    signal,
  })) as DigitalCredential | null;

  if (!credential) return null;
  return extractVpToken(credential.data, credentialId);
}
