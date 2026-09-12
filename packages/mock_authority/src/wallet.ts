/**
 * MockWallet — a test-only holder that presents an issued mDL.
 *
 * Stands in for the real OS wallet: given an issued mDL, it produces a
 * DeviceResponse that discloses only the requested elements and binds deviceAuth
 * to the DC-API session transcript (our nonce + origin). The result is the
 * base64url vp_token as it would appear over OpenID4VP.
 */
import { Holder, DeviceRequest, DocRequest, ItemsRequest, SessionTranscript } from '@owf/mdoc';
import { dcApiSessionTranscript, mdocContext, sealIsoMdocResponse } from '@justinswork/pavel-core';
import type { IssuedMdl } from './authority';

const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
const MDL_NAMESPACE = 'org.iso.18013.5.1';

export interface PresentOptions {
  /** The server-minted OpenID4VP nonce, single-use and session-bound. */
  nonce: string;
  /** The expected web origin the presentation is bound to. */
  origin: string;
  /** Element identifiers in the mDL namespace to disclose, e.g. ['age_over_21']. */
  disclose: string[];
}

/** A device request limiting disclosure to the given elements (intent_to_retain: false). */
function deviceRequest(disclose: string[]): DeviceRequest {
  return DeviceRequest.create({
    docRequests: [
      DocRequest.create({
        itemsRequest: ItemsRequest.create({
          docType: MDL_DOCTYPE,
          namespaces: {
            [MDL_NAMESPACE]: Object.fromEntries(disclose.map((element) => [element, false])),
          },
        }),
      }),
    ],
  });
}

export class MockWallet {
  constructor(private readonly credential: IssuedMdl) {}

  /** Present the credential as the base64url vp_token. */
  async present({ nonce, origin, disclose }: PresentOptions): Promise<string> {
    const sessionTranscript = await dcApiSessionTranscript(origin, nonce);
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: deviceRequest(disclose),
        issuerSigned: [this.credential.issuerSigned],
        sessionTranscript,
        signature: { signingKey: this.credential.devicePrivateKey },
      },
      mdocContext,
    );
    return deviceResponse.encodedForOid4Vp;
  }

  /**
   * Present under ISO 18013-7 Annex C (org-iso-mdoc, Safari): bind deviceAuth to the
   * ISO handover transcript, then HPKE-seal the DeviceResponse to the reader key in
   * the EncryptionInfo. Returns the base64url EncryptedResponse.
   */
  async presentIso({
    encryptionInfoBase64Url,
    origin,
    disclose,
  }: {
    encryptionInfoBase64Url: string;
    origin: string;
    disclose: string[];
  }): Promise<string> {
    const sessionTranscript = await SessionTranscript.forIsoMdocDcApi(
      { encryptionInfoBase64Url, origin },
      mdocContext,
    );
    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest: deviceRequest(disclose),
        issuerSigned: [this.credential.issuerSigned],
        sessionTranscript,
        signature: { signingKey: this.credential.devicePrivateKey },
      },
      mdocContext,
    );
    return sealIsoMdocResponse({ deviceResponseBytes: deviceResponse.encode(), encryptionInfoBase64Url, origin });
  }
}
