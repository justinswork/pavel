import { describe, it, expect, vi, afterEach } from 'vitest';
import { requestAgeProof, fetchAgeRequest } from '../src/index';
import { extractVpToken } from '../src/dc-api';

afterEach(() => vi.unstubAllGlobals());

/** A minimal Response stand-in for the injected fetch. */
function jsonResponse(status: number, body: unknown) {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as unknown as Response;
}

/** Route the two ceremony calls to canned responses. */
function makeFetch(routes: {
  request?: { status?: number; body?: unknown } | (() => never);
  verify?: { status?: number; body?: unknown };
}) {
  return vi.fn(async (url: RequestInfo | URL, _opts?: RequestInit): Promise<Response> => {
    const u = String(url);
    if (u.includes('/pavel/request')) {
      if (typeof routes.request === 'function') return routes.request();
      return jsonResponse(routes.request?.status ?? 200, routes.request?.body ?? {});
    }
    if (u.includes('/pavel/verify')) {
      return jsonResponse(routes.verify?.status ?? 200, routes.verify?.body ?? {});
    }
    throw new Error(`unexpected url: ${u}`);
  });
}

/** Make the DC API appear present, with the given wallet get() behavior. */
function stubWallet(get: (options: unknown) => Promise<unknown>) {
  vi.stubGlobal('DigitalCredential', class {});
  vi.stubGlobal('navigator', { credentials: { get } });
}

const AUTH_REQUEST = { response_type: 'vp_token', nonce: 'n', dcql_query: { credentials: [] } };

describe('requestAgeProof', () => {
  it('returns unsupported when the Digital Credentials API is absent', async () => {
    vi.stubGlobal('navigator', { credentials: undefined });
    const fetchSpy = makeFetch({});
    const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
    expect(result).toEqual({ ok: false, reason: 'unsupported' });
    expect(fetchSpy).not.toHaveBeenCalled(); // fails closed before any network
  });

  it('runs the full ceremony and resolves ok on a verified presentation', async () => {
    stubWallet(async () => ({ protocol: 'openid4vp', data: { vp_token: { age_check: 'TOKEN123' } } }));
    const fetchSpy = makeFetch({
      request: { body: AUTH_REQUEST },
      verify: { body: { ok: true, outcome: 'verified' } },
    });

    const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
    expect(result).toEqual({ ok: true });

    // The extracted vp_token is posted to verify.
    const verifyCall = fetchSpy.mock.calls.find(([u]) => String(u).includes('/pavel/verify'));
    expect(verifyCall?.[1]?.method).toBe('POST');
    expect(JSON.parse(String(verifyCall?.[1]?.body))).toEqual({ vp_token: 'TOKEN123' });
  });

  it('reuses a pre-fetched request and does not fetch the challenge again', async () => {
    let walletSawRequest: unknown;
    vi.stubGlobal('DigitalCredential', class {});
    vi.stubGlobal('navigator', {
      credentials: {
        get: async (opts: { digital?: { requests?: Array<{ data?: unknown }> } }) => {
          walletSawRequest = opts?.digital?.requests?.[0]?.data;
          return { data: 'TOKEN' };
        },
      },
    });
    const fetchSpy = makeFetch({ verify: { body: { ok: true } } });

    const result = await requestAgeProof({ minAge: 21, request: AUTH_REQUEST, fetch: fetchSpy });
    expect(result).toEqual({ ok: true });

    const urls = fetchSpy.mock.calls.map(([u]) => String(u));
    expect(urls.some((u) => u.includes('/pavel/request'))).toBe(false); // reused, not re-fetched
    expect(urls.some((u) => u.includes('/pavel/verify'))).toBe(true);
    expect(walletSawRequest).toEqual(AUTH_REQUEST); // the pre-fetched request reached the wallet
  });

  it('reads minAge into the request URL', async () => {
    stubWallet(async () => ({ data: 'TOKEN' }));
    const fetchSpy = makeFetch({ verify: { body: { ok: true } } });
    await requestAgeProof({ minAge: 18, fetch: fetchSpy });
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain('/pavel/request?minAge=18');
  });

  it('maps a dismissed wallet prompt (NotAllowedError) to declined', async () => {
    stubWallet(async () => {
      throw Object.assign(new Error('user cancelled'), { name: 'NotAllowedError' });
    });
    const result = await requestAgeProof({ minAge: 21, fetch: makeFetch({ request: { body: AUTH_REQUEST } }) });
    expect(result).toEqual({ ok: false, reason: 'declined' });
  });

  it('maps a null credential (no selection) to declined', async () => {
    stubWallet(async () => null);
    const result = await requestAgeProof({ minAge: 21, fetch: makeFetch({ request: { body: AUTH_REQUEST } }) });
    expect(result).toEqual({ ok: false, reason: 'declined' });
  });

  it('passes server outcomes through as the reason', async () => {
    stubWallet(async () => ({ data: 'TOKEN' }));
    for (const outcome of ['predicate_false', 'untrusted_issuer', 'expired', 'replay', 'malformed'] as const) {
      const fetchSpy = makeFetch({ verify: { status: 400, body: { ok: false, outcome } } });
      const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
      expect(result).toEqual({ ok: false, reason: outcome });
    }
  });

  it('maps an unknown verify outcome to verification_failed', async () => {
    stubWallet(async () => ({ data: 'TOKEN' }));
    const fetchSpy = makeFetch({ verify: { status: 400, body: { ok: false, outcome: 'weird' } } });
    const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
    expect(result).toEqual({ ok: false, reason: 'verification_failed' });
  });

  it('returns request_failed when the challenge cannot be fetched', async () => {
    stubWallet(async () => ({ data: 'TOKEN' }));
    const fetchSpy = makeFetch({ request: { status: 500 } });
    const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
    expect(result).toEqual({ ok: false, reason: 'request_failed' });
  });

  it('returns request_failed when the request fetch throws', async () => {
    stubWallet(async () => ({ data: 'TOKEN' }));
    const fetchSpy = makeFetch({
      request: () => {
        throw new Error('network down');
      },
    });
    const result = await requestAgeProof({ minAge: 21, fetch: fetchSpy });
    expect(result).toEqual({ ok: false, reason: 'request_failed' });
  });
});

describe('fetchAgeRequest', () => {
  it('fetches and returns the parsed authorization request', async () => {
    const fetchSpy = makeFetch({ request: { body: AUTH_REQUEST } });
    const req = await fetchAgeRequest({ minAge: 21, fetch: fetchSpy });
    expect(req).toEqual(AUTH_REQUEST);
    expect(String(fetchSpy.mock.calls[0]?.[0])).toContain('/pavel/request?minAge=21');
  });

  it('throws on a non-2xx response', async () => {
    const fetchSpy = makeFetch({ request: { status: 500 } });
    await expect(fetchAgeRequest({ minAge: 21, fetch: fetchSpy })).rejects.toThrow();
  });
});

describe('extractVpToken', () => {
  it('reads a vp_token map keyed by credential id', () => {
    expect(extractVpToken({ vp_token: { age_check: 'T' } }, 'age_check')).toBe('T');
  });

  it('reads a bare vp_token string', () => {
    expect(extractVpToken({ vp_token: 'T' }, 'age_check')).toBe('T');
  });

  it('reads the OpenID4VP 1.0 array shape { vp_token: { id: ["token"] } }', () => {
    // The exact shape Chrome + CMWallet return on Android.
    expect(extractVpToken({ vp_token: { age_check: ['T'] } }, 'age_check')).toBe('T');
  });

  it('reads a vp_token that is an array directly', () => {
    expect(extractVpToken({ vp_token: ['T'] }, 'age_check')).toBe('T');
  });

  it('parses a JSON string response', () => {
    expect(extractVpToken(JSON.stringify({ vp_token: { age_check: 'T' } }), 'age_check')).toBe('T');
  });

  it('falls back to the first string when the credential id is absent', () => {
    expect(extractVpToken({ vp_token: { other: 'T' } }, 'age_check')).toBe('T');
  });

  it('accepts a plain token string with no envelope', () => {
    expect(extractVpToken('T', 'age_check')).toBe('T');
  });

  it('returns null for undecodable data', () => {
    expect(extractVpToken('not json', 'age_check')).toBeNull();
    expect(extractVpToken(null, 'age_check')).toBeNull();
    expect(extractVpToken({ vp_token: { n: 42 } }, 'age_check')).toBeNull();
  });
});
