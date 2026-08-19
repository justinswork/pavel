/**
 * PAVEL demo store — Express server.
 *
 * Wires a minimal e-commerce store to the REAL PAVEL stack: `@justinswork/pavel`
 * (middleware) + `@justinswork/pavel-core` (verifier). The one thing this testbed
 * can't supply is an OS wallet, so a dev-only endpoint (`/dev-wallet/present`)
 * uses `@justinswork/pavel-mock-authority` to mint and present real, cryptographic
 * mDL DeviceResponses on demand — a stand-in for the wallet, not for the verifier.
 *
 * The browser first tries the real Digital Credentials API via the pavel-client
 * SDK; where no wallet exists it falls back to the dev wallet (see public/).
 */
import { fileURLToPath } from 'node:url';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import { pavel, requireAgeProof } from '@justinswork/pavel';
import { MockAuthority, MockWallet } from '@justinswork/pavel-mock-authority';
import { CATALOG, CATALOG_BY_ID, MIN_AGE } from './catalog.js';

// The store keeps a cart in the session; pavel/pavelPending are augmented by the middleware.
declare module 'express-session' {
  interface SessionData {
    cart?: Record<string, number>;
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
// The pavel-client browser SDK, built to its IIFE bundle (see the build:client script).
const CLIENT_BUNDLE = path.join(__dirname, '..', '..', '..', 'packages', 'client', 'dist', 'zk-age.js');

const PORT = Number(process.env.PORT ?? 3000);
const ORIGIN = process.env.ORIGIN ?? `http://localhost:${PORT}`;

// The trust root the store verifies against, and a second, untrusted authority the
// dev wallet can present from to demonstrate the untrusted_issuer outcome.
const authority = await MockAuthority.create();
const untrustedAuthority = await MockAuthority.create();

// Any *.pem in trust-anchors/ is also trusted — e.g. CMWallet's IACA, so its
// built-in test mDL verifies when presented from a real Android device.
const TRUST_DIR = path.join(__dirname, '..', 'trust-anchors');
function loadExtraTrustAnchors(): string[] {
  try {
    return readdirSync(TRUST_DIR)
      .filter((f) => f.endsWith('.pem'))
      .map((f) => readFileSync(path.join(TRUST_DIR, f), 'utf8'));
  } catch {
    return [];
  }
}
const extraTrustAnchors = loadExtraTrustAnchors();

const app = express();
app.use(express.json());
app.use(
  session({
    name: 'pavel.sid',
    secret: 'pavel-demo-not-for-production',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 },
  }),
);

// ── Mount the REAL PAVEL ceremony endpoints (GET /pavel/request, POST /pavel/verify).
app.use(
  pavel({
    origin: ORIGIN,
    trustAnchors: [authority.trustAnchor, ...extraTrustAnchors],
    clientName: 'Cellar & Co.',
  }),
);

// ── Dev wallet ───────────────────────────────────────────────────────────────
// DEV ONLY. A real deployment has no such endpoint — the user's OS wallet presents
// the credential. Here we mint a real mDL and present it against the pending
// challenge, choosing a credential that drives the requested demo outcome.
app.post('/dev-wallet/present', async (req, res) => {
  const pending = req.session.pavelPending;
  if (!pending) {
    res.status(409).json({ error: 'no_pending_request' });
    return;
  }
  const minAge = pending.minAge;
  const predicate = `age_over_${minAge}`;
  const scenario = String((req.body as { scenario?: unknown } | undefined)?.scenario ?? 'over');

  try {
    let issued;
    let disclose: string[];
    switch (scenario) {
      case 'under': // valid credential, predicate signed false → predicate_false
        issued = await authority.issueMdl({ ageOver: [], claims: { [predicate]: false } });
        disclose = [predicate];
        break;
      case 'absent': // credential never carried this predicate → predicate_unavailable
        issued = await authority.issueMdl({ ageOver: [13] });
        disclose = ['age_over_13'];
        break;
      case 'untrusted': // signed by an authority the store doesn't trust → untrusted_issuer
        issued = await untrustedAuthority.issueMdl({ ageOver: [minAge] });
        disclose = [predicate];
        break;
      case 'over': // valid, over the bar → verified
      default:
        issued = await authority.issueMdl({ ageOver: [minAge] });
        disclose = [predicate];
        break;
    }
    const vpToken = await new MockWallet(issued).present({ nonce: pending.nonce, origin: ORIGIN, disclose });
    res.json({ vp_token: vpToken });
  } catch (err) {
    console.error('dev-wallet present failed:', err);
    res.status(500).json({ error: 'present_failed' });
  }
});

// Serve the pavel-client SDK bundle at the path index.html references.
// no-store so on-device debugging never serves a stale bundle.
app.get('/zk-age.js', (_req, res) => {
  res.type('application/javascript').set('Cache-Control', 'no-store').sendFile(CLIENT_BUNDLE);
});

// ── Store API ──────────────────────────────────────────────────────────────

app.get('/api/catalog', (_req, res) => {
  res.json({ minAge: MIN_AGE, products: CATALOG });
});

function cartView(cart: Record<string, number>) {
  const items = Object.entries(cart)
    .map(([id, qty]) => {
      const product = CATALOG_BY_ID.get(id);
      if (!product) return null;
      return { ...product, qty, lineTotal: Number((product.price * qty).toFixed(2)) };
    })
    .filter((x): x is NonNullable<typeof x> => x !== null);
  const total = Number(items.reduce((sum, i) => sum + i.lineTotal, 0).toFixed(2));
  const hasRestricted = items.some((i) => i.ageRestricted);
  return { items, total, hasRestricted };
}

app.get('/api/cart', (req, res) => {
  res.json(cartView(req.session.cart ?? {}));
});

app.post('/api/cart', (req, res) => {
  const { productId, qty } = req.body ?? {};
  const product = CATALOG_BY_ID.get(String(productId));
  if (!product) {
    res.status(400).json({ error: 'unknown_product' });
    return;
  }
  const cart = req.session.cart ?? {};
  const next = (cart[product.id] ?? 0) + (Number.isInteger(qty) ? qty : 1);
  if (next <= 0) delete cart[product.id];
  else cart[product.id] = next;
  req.session.cart = cart;
  res.json(cartView(cart));
});

app.post('/api/cart/clear', (req, res) => {
  req.session.cart = {};
  res.json(cartView({}));
});

/**
 * Checkout. If the cart holds an age-restricted item, it must pass the age
 * gate. We apply requireAgeProof conditionally so unrestricted carts sail
 * through — demonstrating the gate driving a real purchase flow.
 */
app.post(
  '/api/checkout',
  (req, res, next) => {
    const { hasRestricted } = cartView(req.session.cart ?? {});
    if (!hasRestricted) return next();
    // Demo toggle: a real store hard-codes this per its compliance policy.
    const forceReverify = Boolean(req.body?.forceReverify);
    return requireAgeProof({ minAge: MIN_AGE, forceReverify })(req, res, next);
  },
  (req, res) => {
    const view = cartView(req.session.cart ?? {});
    if (view.items.length === 0) {
      res.status(400).json({ error: 'empty_cart' });
      return;
    }
    req.session.cart = {};
    res.json({ ok: true, orderTotal: view.total, itemCount: view.items.length });
  },
);

// Verification status, for the header badge.
app.get('/api/status', (req, res) => {
  res.json({
    verified: Boolean(req.session.pavel?.verified),
    verifiedMinAge: req.session.pavel?.verifiedMinAge ?? null,
  });
});

// A standalone gated route mirroring the README example.
app.get('/premium-content', requireAgeProof({ minAge: MIN_AGE }), (_req, res) => {
  res.send('Access granted — age verified, no personal data received.');
});

// ── Static frontend ──────────────────────────────────────────────────────────
app.use(express.static(PUBLIC_DIR));

app.listen(PORT, () => {
  console.log(`PAVEL demo store running at ${ORIGIN}`);
  console.log(`  real middleware + verifier · dev wallet stands in for the OS wallet · min age ${MIN_AGE}`);
  console.log(`  trust anchors: MockAuthority + ${extraTrustAnchors.length} from trust-anchors/`);
});
