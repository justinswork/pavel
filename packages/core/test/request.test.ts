import { describe, it, expect } from 'vitest';
import { buildAgeRequest, agePredicate } from '../src/request';
import { MDL_DOCTYPE, MDL_NAMESPACE } from '../src/backend';

describe('agePredicate', () => {
  it('maps a minimum age to its ISO element identifier', () => {
    expect(agePredicate(21)).toBe('age_over_21');
    expect(agePredicate(18)).toBe('age_over_18');
  });
});

describe('buildAgeRequest', () => {
  const base = { minAge: 21, nonce: 'nonce-123', origin: 'https://shop.example' };

  it('produces an OpenID4VP vp_token request with dc_api default', () => {
    const req = buildAgeRequest(base);
    expect(req.response_type).toBe('vp_token');
    expect(req.response_mode).toBe('dc_api');
    expect(req.nonce).toBe('nonce-123');
  });

  it('queries exactly the mDL doctype and the single age predicate', () => {
    const req = buildAgeRequest(base);
    expect(req.dcql_query.credentials).toHaveLength(1);
    const cred = req.dcql_query.credentials[0]!;
    expect(cred.format).toBe('mso_mdoc');
    expect(cred.meta.doctype_value).toBe(MDL_DOCTYPE);
    expect(cred.claims).toEqual([{ path: [MDL_NAMESPACE, 'age_over_21'] }]);
  });

  it('surfaces the verifier display name and origin in client_metadata', () => {
    const req = buildAgeRequest({ ...base, clientName: 'Cellar & Co.' });
    expect(req.client_metadata.client_name).toBe('Cellar & Co.');
    expect(req.client_metadata.expected_origin).toBe('https://shop.example');
  });
});
