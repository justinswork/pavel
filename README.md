# PAVEL

**P**rivacy-first **A**ge **V**erification & **E**ligibility **L**ibrary: an open-source TypeScript library that lets a website confirm one fact about a user, such as *over 21*, from the mobile driver's license in their phone wallet, **without ever receiving their personal data**.

> **Status:** works end to end with Google's and Apple's test wallets on real Android and iPhone devices. Not yet published to npm. Accepting real state IDs requires each site to register with Google and Apple; see [Accepting real IDs](#accepting-real-ids). PAVEL began as a graduate capstone project.

```js
// Server: only users who have proven they are 21 or older reach placeOrder
app.use(pavel({ origin: 'https://shop.example', trustAnchors }));
app.post('/checkout', requireAgeProof({ minAge: 21 }), placeOrder);
```

```js
// Browser: when the server asks for proof, open the phone's wallet
const proof = await requestAgeProof({ minAge: 21 });
```

---

## Why

Online age checks usually mean uploading a photo of an ID or typing a name, birthdate, and address for a third party to match. Both expose far more personal data than the question needs.

Mobile driver's licenses in Google Wallet and Apple Wallet support *selective disclosure*: the wallet shares only the fields a site asks for. Because the issuing state also signs ready-made yes/no fields such as `age_over_21`, a site can learn that a user is over 21 without ever seeing their birthdate. Browsers expose this through the [W3C Digital Credentials API](https://www.w3.org/TR/digital-credentials/), available in stable Chrome and Safari.

Using that API directly is hard: several protocols, two encryption schemes, and cryptographic checks that tie each response to the site that asked for it. PAVEL handles all of that behind a few lines of code.

## How it works

1. **The server issues a challenge.** It's random, single-use, expires after 5 minutes, and is tied to your site's address. It offers every format PAVEL supports, and the browser picks the one it understands.
2. **The phone's wallet asks the user.** The wallet shows which site is asking and the single fact requested ("Age over 21"). If the user agrees, the wallet returns a signed answer.
3. **The server verifies the answer.** PAVEL checks that the ID was issued by a trusted authority, that it hasn't been altered, that it's within its validity dates, that the phone's signature ties the answer to this site and this challenge, and finally that the age field is true. The site gets a yes or no, and the session remembers the result.

| Browser | Protocol | Status |
|---|---|---|
| Chrome on Android | OpenID4VP (unsigned) | verified with Google's CMWallet test wallet |
| Safari on iPhone / iPad | ISO 18013-7 Annex C (HPKE-encrypted) | verified with the Multipaz test wallet; Apple Wallet accepts PAVEL's requests (see [Testing](#testing)) |
| Chrome with Google Wallet | OpenID4VP (signed and encrypted) | built and tested against simulated wallets; needs a registered site to confirm |

## Packages

| Package | What it is |
|---|---|
| [`@justinswork/pavel`](packages/middleware) | Express middleware: the age-check endpoints and the `requireAgeProof` route guard. **Start here.** |
| [`@justinswork/pavel-client`](packages/client) | Browser SDK: `requestAgeProof()` opens the wallet and sends the answer to your server. |
| [`@justinswork/pavel-core`](packages/core) | The framework-independent verifier used by the middleware. Use it directly to integrate with something other than Express. |
| [`@justinswork/pavel-mock-authority`](packages/mock_authority) | Test-only: creates a test issuer and signed test IDs, so everything can be tested offline. |
| [`apps/demo`](apps/demo) | Cellar & Co., an example store with age-restricted products, wired up end to end. |

See the [middleware README](packages/middleware/README.md) for the full setup, options, and API.

**Step-by-step example:** [pull request #1](https://github.com/justinswork/pavel/pull/1) adds PAVEL to the example store one commit at a time, the same steps a developer would take on their own site. [Pull request #2](https://github.com/justinswork/pavel/pull/2) then adds optional extras: a dev wallet for testing without a phone, a re-verify-every-checkout option, and the settings for accepting real IDs.

## Run it locally

PAVEL uses [pnpm](https://pnpm.io) workspaces. With Node.js 24 (if you don't have pnpm, run `corepack enable` first):

```bash
pnpm install
pnpm test        # all packages
pnpm dev         # the example store at http://localhost:3000
```

Desktop browsers have no wallet, so the example store shows a labeled stand-in "dev wallet" that presents real signed test IDs and can trigger every outcome.

To try it on a phone, the store must be reachable over HTTPS, for example through a temporary tunnel. Set `ORIGIN` to the public address so it matches what the phone's browser sees:

```bash
ORIGIN=https://your-tunnel.example pnpm dev
```

On Android, install Google's [CMWallet](https://github.com/digitalcredentialsdev/CMWallet) test wallet; on iPhone, install Apple's free "Wallet Identity Developer" profile from Apple's developer profiles page.

## Testing

- **127 automated tests** across the packages. They use real cryptography: a test issuer signs real test IDs, a test wallet presents them the way a phone would, and PAVEL verifies them with the same code a real site runs. Fixed test cases cover every outcome, and dedicated tests cover reused challenges, answers made for another site, untrusted issuers, and that PAVEL never asks for anything beyond the age question.
- **Real phones:**
  - *Android:* Chrome with Google's CMWallet test wallet on a physical phone: verified end to end.
  - *iPhone:* Apple Wallet with Apple's developer profile accepted PAVEL's request, and PAVEL decrypted and read the response. Apple's simulated license has no issuer certificate, so PAVEL correctly rejects it as untrusted.
  - *Safari:* the Multipaz test wallet presenting to Safari on an iPad: verified end to end.
- **Real IDs:** real Iowa mobile driver's licenses in Google Wallet and Apple Wallet were refused by the wallets themselves, as expected for an unregistered site.

## Accepting real IDs

Google Wallet and Apple Wallet only release real state IDs to websites registered with them. Google approves verifiers individually; Apple requires a verified organization in an eligible category, such as licensed alcohol sales. PAVEL already includes what registration requires: signed requests and configurable reader certificates for both platforms (see the [middleware README](packages/middleware/README.md#accepting-real-ids)).

Each site also chooses which issuers to trust by supplying their root certificates, usually one per state.

## Privacy

- The site learns only a yes/no for one age threshold, the document type, and the issuer's public certificate.
- The issuing state is never contacted, and no personal data is sent anywhere for matching.
- PAVEL can only ask for a single age field; its request builders accept nothing else.
- **Limitation:** the same credential looks the same every time it's presented, so two cooperating sites could recognize the same user. Removing that requires zero-knowledge proofs (see the roadmap).

## Roadmap

Not yet done:

- Publishing the packages to npm
- A maintained default list of state root certificates (for example from AAMVA's Digital Trust Service), with an option to restrict it to specific states
- Revocation checking (today PAVEL enforces validity dates only)
- A shared store for single-use proofs across multiple server instances
- Concurrent-load benchmarks
- Zero-knowledge proofs for unlinkability, for example Google's [Longfellow-ZK](https://github.com/google/longfellow-zk)
- Other eligibility facts beyond age, such as residency or student status

## Docs

- [Glossary](docs/GLOSSARY.md): the acronyms and terms used throughout
- [Architecture](docs/ARCHITECTURE.md): the original design document
- [Safari / ISO 18013-7 notes](docs/safari-org-iso-mdoc.md)

## License

[Apache-2.0](LICENSE)
