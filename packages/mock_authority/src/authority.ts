/**
 * MockAuthority — a test-only issuing authority.
 *
 * Generates an IACA root and a document-signer (DS) certificate issued under it,
 * then signs mock mDLs with the DS key via @owf/mdoc's Issuer (using pavel-core's
 * MdocContext). The IACA cert is the trust anchor a verifier is configured with.
 * No real DMV or network is involved.
 */
import 'reflect-metadata'; // required by @peculiar/x509's tsyringe dependency
import { webcrypto } from 'node:crypto';
import * as x509 from '@peculiar/x509';
import { Issuer, CoseKey, DeviceKey, SignatureAlgorithm, type IssuerSigned } from '@owf/mdoc';
import { mdocContext } from '@justinswork/pavel-core';

type CryptoKey = webcrypto.CryptoKey;

x509.cryptoProvider.set(webcrypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

const EC_P256 = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ES256 = { name: 'ECDSA', hash: 'SHA-256' } as const;
const MDL_DOCTYPE = 'org.iso.18013.5.1.mDL';
const MDL_NAMESPACE = 'org.iso.18013.5.1';
const YEAR_MS = 365 * 24 * 3600 * 1000;

const genKey = (): Promise<webcrypto.CryptoKeyPair> =>
  webcrypto.subtle.generateKey(EC_P256, true, ['sign', 'verify']) as Promise<webcrypto.CryptoKeyPair>;
// WebCrypto omits `alg` on exported EC JWKs; CoseKey.fromJwk needs it to set the alg header.
const coseKey = async (k: CryptoKey): Promise<CoseKey> =>
  CoseKey.fromJwk({ ...(await webcrypto.subtle.exportKey('jwk', k)), alg: 'ES256' } as Record<string, unknown>);
const deviceKey = async (k: CryptoKey): Promise<DeviceKey> =>
  DeviceKey.fromJwk({ ...(await webcrypto.subtle.exportKey('jwk', k)), alg: 'ES256' } as Record<string, unknown>);

export interface MockAuthorityOptions {
  /** ISO 3166 country code baked into the certs and the mDL. Default 'US'. */
  country?: string;
  /** Certificate validity, days. Default 365. */
  validityDays?: number;
}

export interface IssueMdlOptions {
  /** Which age_over_NN predicates to sign as true. Default [18, 21]. */
  ageOver?: number[];
  /** Extra/override claims in the mDL namespace. */
  claims?: Record<string, unknown>;
  /** MSO validity window. Default: now → now + 1 year. */
  validFrom?: Date;
  validUntil?: Date;
}

/** A minted, issuer-signed mDL plus the device key it is bound to. */
export interface IssuedMdl {
  /** The issuer-signed mdoc — the credential loaded into a wallet. */
  issuerSigned: IssuerSigned;
  /** The holder device key the credential is bound to (used to present it). */
  devicePrivateKey: CoseKey;
}

export class MockAuthority {
  private constructor(
    private readonly iacaCertPem: string,
    private readonly dsCertDer: Uint8Array,
    private readonly dsPrivateKey: CoseKey,
    private readonly country: string,
  ) {}

  /** Generate a fresh IACA root + document signer. */
  static async create(options: MockAuthorityOptions = {}): Promise<MockAuthority> {
    const country = options.country ?? 'US';
    const validityDays = options.validityDays ?? 365;
    const now = Date.now();
    const notBefore = new Date(now - 60_000);
    const notAfter = new Date(now + validityDays * 24 * 3600 * 1000);

    // IACA root — self-signed CA.
    const iacaKeys = await genKey();
    const iacaCert = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: `C=${country}, O=PAVEL Mock Authority, CN=PAVEL Mock IACA`,
      notBefore,
      notAfter,
      keys: iacaKeys,
      signingAlgorithm: ES256,
      extensions: [
        new x509.BasicConstraintsExtension(true, undefined, true),
        new x509.KeyUsagesExtension(
          x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
          true,
        ),
      ],
    });

    // Document signer — issued under the IACA.
    const dsKeys = await genKey();
    const dsCert = await x509.X509CertificateGenerator.create({
      serialNumber: '02',
      subject: `C=${country}, O=PAVEL Mock Authority, CN=PAVEL Mock Document Signer`,
      issuer: iacaCert.subject,
      notBefore,
      notAfter,
      publicKey: dsKeys.publicKey,
      signingKey: iacaKeys.privateKey,
      signingAlgorithm: ES256,
      extensions: [new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true)],
    });

    const dsPrivateKey = await coseKey(dsKeys.privateKey);
    return new MockAuthority(
      iacaCert.toString('pem'),
      new Uint8Array(dsCert.rawData),
      dsPrivateKey,
      country,
    );
  }

  /** The IACA root certificate (PEM). This is the verifier's trust anchor. */
  get trustAnchor(): string {
    return this.iacaCertPem;
  }

  /** Issue and sign a mock mDL. */
  async issueMdl(options: IssueMdlOptions = {}): Promise<IssuedMdl> {
    const deviceKeys = await genKey();
    const devicePrivateKey = await coseKey(deviceKeys.privateKey);

    const now = new Date();
    const ageOver = options.ageOver ?? [18, 21];
    const claims: Record<string, unknown> = {
      family_name: 'Doe',
      given_name: 'Jane',
      issuing_country: this.country,
      ...Object.fromEntries(ageOver.map((n) => [`age_over_${n}`, true])),
      ...options.claims,
    };

    const issuerSigned = await new Issuer(MDL_DOCTYPE, mdocContext)
      .addIssuerNamespace(MDL_NAMESPACE, claims)
      .sign({
        signingKey: this.dsPrivateKey,
        certificates: [this.dsCertDer],
        algorithm: SignatureAlgorithm.ES256,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: await deviceKey(deviceKeys.publicKey) },
        validityInfo: {
          signed: now,
          validFrom: options.validFrom ?? now,
          validUntil: options.validUntil ?? new Date(now.getTime() + YEAR_MS),
        },
      });

    return { issuerSigned, devicePrivateKey };
  }
}
