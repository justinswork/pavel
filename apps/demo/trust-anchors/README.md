# Trust anchors

Every `*.pem` in this directory is loaded as a trusted IACA root by the demo
server (in addition to the ephemeral `MockAuthority` root the dev wallet uses).
This mirrors how a real deployment configures the issuer roots it accepts.

- **`cmwallet-issuer.pem`** — the IACA root of Google's [CMWallet](https://github.com/digitalcredentialsdev/CMWallet)
  sample wallet (`CN=digitalcredentials.dev`). Trusting it lets CMWallet's
  built-in test mDL verify on a real Android device: install the CMWallet APK,
  serve the demo over an HTTPS tunnel with `ORIGIN` set to the tunnel URL, and a
  `21+` checkout should reach `verified`. This is a test anchor — a production
  deployment would trust real issuing-authority roots, not this one.
