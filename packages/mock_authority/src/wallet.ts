/**
 * MockWallet — a test-only holder that presents an issued mDL.
 *
 * Stands in for the real OS wallet: given an issued mDL, it produces a
 * DeviceResponse that discloses only the requested elements and binds deviceAuth
 * to the DC-API session transcript (our nonce + origin).
 */
import { DeviceResponse } from '@auth0/mdl';
import type { PresentationDefinition } from '@auth0/mdl/lib/mdoc/model/PresentationDefinition.js';
import type { IssuedMdl } from './authority';
import { dcApiSessionTranscript } from '@justinswork/pavel-core';

const MDL_NAMESPACE = 'org.iso.18013.5.1';

export interface PresentOptions {
  /** The server-minted OpenID4VP nonce, single-use and session-bound. */
  nonce: string;
  /** The expected web origin the presentation is bound to. */
  origin: string;
  /** Element identifiers in the mDL namespace to disclose, e.g. ['age_over_21']. */
  disclose: string[];
}

function presentationDefinition(disclose: string[]): PresentationDefinition {
  return {
    id: 'pavel-age-check',
    input_descriptors: [
      {
        id: 'org.iso.18013.5.1.mDL',
        format: { mso_mdoc: { alg: ['ES256'] } },
        constraints: {
          limit_disclosure: 'required',
          fields: disclose.map((element) => ({
            path: [`$['${MDL_NAMESPACE}']['${element}']`],
            intent_to_retain: false,
          })),
        },
      },
    ],
  };
}

export class MockWallet {
  constructor(private readonly credential: IssuedMdl) {}

  /** Present the credential as a base64-encodable DeviceResponse (the vp_token). */
  async present({ nonce, origin, disclose }: PresentOptions): Promise<Uint8Array> {
    const deviceResponse = await DeviceResponse.from(this.credential.issuerSigned)
      .usingPresentationDefinition(presentationDefinition(disclose))
      .usingSessionTranscriptBytes(dcApiSessionTranscript(origin, nonce))
      .authenticateWithSignature(this.credential.devicePrivateKey, 'ES256')
      .sign();
    return deviceResponse.encode();
  }
}
