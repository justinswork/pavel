/**
 * The MdocContext — the crypto/PKI seam @owf/mdoc requires callers to supply.
 *
 * Unlike @auth0/mdl (which bundled its crypto), every maintained mdoc library
 * now delegates COSE sign1/mac0, X.509 chain validation, and digest/HKDF/random
 * to a caller-provided context. pavel-core owns that context here, once, so both
 * the verification backend (backend-owf.ts) and the test issuer/wallet build on a
 * single implementation.
 *
 * The implementations are conventional: ECDSA over the library-provided
 * `toBeSigned`/`toBeVerified` bytes via @noble/curves, X.509 chains via
 * @peculiar/x509. Adapted from @owf/mdoc's reference `tests/context.ts`.
 */
import 'reflect-metadata'; // @peculiar/x509's tsyringe dependency needs this first
import crypto, { timingSafeEqual } from 'node:crypto';
import { p256 } from '@noble/curves/nist.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { coseKeyToJwkClaim } from '@owf/cose';
import { hex } from '@owf/identity-common';
import { hkdf } from '@panva/hkdf';
import * as x509 from '@peculiar/x509';
import { X509Certificate } from '@peculiar/x509';
import { exportJWK, importX509 } from 'jose';
import { CoseKey, type MdocContext } from '@owf/mdoc';

x509.cryptoProvider.set(globalThis.crypto as unknown as Parameters<typeof x509.cryptoProvider.set>[0]);

export const mdocContext: MdocContext = {
  fetch,
  crypto: {
    digest: async ({ digestAlgorithm, bytes }) => {
      const digest = await crypto.subtle.digest(digestAlgorithm, bytes as Uint8Array<ArrayBuffer>);
      return new Uint8Array(digest);
    },
    random: (length: number) => crypto.getRandomValues(new Uint8Array(length)),
    hdkf: async (input) => {
      const { digestAlgorithm: da, salt, info, publicKey, privateKey } = input;
      const ikm = p256.getSharedSecret(privateKey, publicKey, true).slice(1);
      const digestAlgorithm = da === 'SHA-384' ? 'sha384' : da === 'SHA-512' ? 'sha512' : 'sha256';
      return await hkdf(digestAlgorithm, ikm, salt, info, 32);
    },
  },
  cose: {
    mac0: {
      authenticate: async ({ key, toBeAuthenticated }) =>
        hmac(sha256, key instanceof CoseKey ? key.privateKey : key, toBeAuthenticated),
      verify: async ({ tag, toBeAuthenticated, key }) =>
        timingSafeEqual(tag, hmac(sha256, key instanceof CoseKey ? key.privateKey : key, toBeAuthenticated)),
    },
    sign1: {
      sign: async ({ key, toBeSigned }) => p256.sign(toBeSigned, key.privateKey, { format: 'compact' }),
      verify: async ({ signature, key, toBeVerified }) =>
        p256.verify(signature, toBeVerified, key instanceof CoseKey ? key.publicKey : key, { lowS: false }),
    },
  },
  x509: {
    getIssuerNameField: (input) => new X509Certificate(input.certificate).issuerName.getField(input.field),
    getPublicKey: async (input) => {
      const certificate = new X509Certificate(input.certificate);
      const key = await importX509(certificate.toString(), coseKeyToJwkClaim.algorithm(input.algorithm), {
        extractable: true,
      });
      return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>);
    },
    verifyCertificateChain: async (input) => {
      const { trustedCertificates, x5chain: certificateChain } = input;
      const leaf = certificateChain[0];
      if (!leaf) throw new Error('Certificate chain is empty');
      const parsedLeafCertificate = new x509.X509Certificate(leaf);
      const certificatesToBuildChain = [...certificateChain, ...(trustedCertificates ?? [])].map(
        (c) => new x509.X509Certificate(c),
      );
      const certificateChainBuilder = new x509.X509ChainBuilder({ certificates: certificatesToBuildChain });
      const chain = await certificateChainBuilder.build(parsedLeafCertificate);
      let parsedChain = chain.reverse();
      if (parsedChain.length < certificateChain.length) {
        throw new Error('Could not parse the full chain. Likely due to incorrect ordering');
      }
      let previousCertificate: x509.X509Certificate | undefined;
      if (trustedCertificates) {
        const parsedTrusted = trustedCertificates.map((t) => new X509Certificate(t));
        const idx = parsedChain.findIndex((cert) => parsedTrusted.some((t) => cert.equal(t)));
        if (idx === -1) throw new Error('No trusted certificate was found while validating the X.509 chain');
        if (idx > 0) {
          previousCertificate = parsedChain[idx - 1];
          parsedChain = parsedChain.slice(idx);
        }
      }
      for (let i = 0; i < parsedChain.length; i++) {
        const cert = parsedChain[i];
        if (!cert) continue;
        const publicKey = previousCertificate ? previousCertificate.publicKey : undefined;
        const skip = i === 0 && trustedCertificates && !publicKey;
        if (!skip) await cert.verify({ publicKey });
        previousCertificate = cert;
      }
      return { chain: parsedChain.map((cert) => new Uint8Array(cert.rawData)) };
    },
    getCertificateData: async (input: { certificate: Uint8Array }) => {
      const certificate = new X509Certificate(input.certificate);
      const thumbprint = await certificate.getThumbprint(crypto);
      return {
        issuerName: certificate.issuerName.toString(),
        subjectName: certificate.subjectName.toString(),
        pem: certificate.toString(),
        serialNumber: certificate.serialNumber,
        thumbprint: hex.encode(new Uint8Array(thumbprint)),
        notBefore: certificate.notBefore,
        notAfter: certificate.notAfter,
      };
    },
  },
};
