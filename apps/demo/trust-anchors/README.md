# Trust anchors

Every `*.pem` file in this folder is loaded as a trusted issuer by the store, the same way a real site lists the issuers whose IDs it accepts. These two are **test** issuers; a production site would trust real issuing authorities (for example, state DMVs) instead.

- **`cmwallet-issuer.pem`**: the root certificate of Google's [CMWallet](https://github.com/digitalcredentialsdev/CMWallet) test wallet (`CN=digitalcredentials.dev`). With it, CMWallet's built-in test driver's license verifies on a real Android phone.
- **`multipaz-testapp.pem`**: the document-signing certificate of the Multipaz test wallet. Multipaz sends only this certificate, not its root, and PAVEL accepts a trusted certificate anywhere in the chain, so trusting it directly is enough. It expires in December 2027.
