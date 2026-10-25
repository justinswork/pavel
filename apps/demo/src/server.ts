/**
 * Cellar & Co. — an example store: a product catalog, a session cart, and checkout.
 */
import { fileURLToPath } from 'node:url';
import { readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import { pavel, requireAgeProof } from '@justinswork/pavel';
import { MockAuthority, MockWallet } from '@justinswork/pavel-mock-authority';
import { CATALOG, CATALOG_BY_ID, MIN_AGE } from './catalog.js';

// The store keeps a cart in the session (PAVEL adds its own fields alongside).
declare module 'express-session' {
  interface SessionData {
    cart?: Record<string, number>;
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const DEV_DIR = path.join(__dirname, '..', 'dev');
// The PAVEL browser SDK's ready-made script build, served to the page as /pavel-client.js.
const CLIENT_BUNDLE = path.join(__dirname, '..', 'node_modules', '@justinswork', 'pavel-client', 'dist', 'zk-age.js');

const PORT = Number(process.env.PORT ?? 3000);
// The address users reach the store at. PAVEL binds every age check to it, so behind a
// tunnel or proxy set ORIGIN to the public address (a trailing slash is ignored).
const ORIGIN = (process.env.ORIGIN ?? `http://localhost:${PORT}`).replace(/\/+$/, '');

// The ID issuers the store accepts: every *.pem in trust-anchors/.
const TRUST_DIR = path.join(__dirname, '..', 'trust-anchors');
const trustAnchors = readdirSync(TRUST_DIR)
  .filter((f) => f.endsWith('.pem'))
  .map((f) => readFileSync(path.join(TRUST_DIR, f), 'utf8'));

// DEV ONLY: a stand-in wallet for browsers without one (like desktop browsers). It mints real,
// signed test IDs from a test issuer the store trusts in development, so it must never run in
// production, where it would let anyone pass the age check.
const DEV_WALLET = process.env.NODE_ENV !== 'production';
const testIssuer = DEV_WALLET ? await MockAuthority.create() : undefined;
const untrustedTestIssuer = DEV_WALLET ? await MockAuthority.create() : undefined;
if (testIssuer) trustAnchors.push(testIssuer.trustAnchor);

const app = express();
app.use(express.json());
app.use(
  session({
    name: 'cellar.sid',
    secret: 'demo-store-not-for-production',
    resave: false,
    saveUninitialized: true,
    cookie: { httpOnly: true, sameSite: 'lax', maxAge: 60 * 60 * 1000 },
  }),
);

// PAVEL's age-check endpoints: GET /pavel/request and POST /pavel/verify.
app.use(pavel({ origin: ORIGIN, trustAnchors, clientName: 'Cellar & Co.' }));

// ── Dev wallet (development only) ────────────────────────────────────────────
if (testIssuer && untrustedTestIssuer) {
  app.use('/dev', express.static(DEV_DIR));

  // Present a test ID against the user's pending age check, choosing one that produces the
  // outcome picked in the dev wallet.
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
        case 'under': // valid ID, age field signed false → predicate_false
          issued = await testIssuer.issueMdl({ ageOver: [], claims: { [predicate]: false } });
          disclose = [predicate];
          break;
        case 'absent': // the ID never carried this age field → predicate_unavailable
          issued = await testIssuer.issueMdl({ ageOver: [13] });
          disclose = ['age_over_13'];
          break;
        case 'untrusted': // signed by an issuer the store doesn't trust → untrusted_issuer
          issued = await untrustedTestIssuer.issueMdl({ ageOver: [minAge] });
          disclose = [predicate];
          break;
        case 'over': // valid and old enough → verified
        default:
          issued = await testIssuer.issueMdl({ ageOver: [minAge] });
          disclose = [predicate];
          break;
      }
      const vpToken = await new MockWallet(issued).present({ nonce: pending.nonce, origin: ORIGIN, disclose });
      res.json({ vp_token: vpToken });
    } catch (err) {
      console.error('dev wallet failed:', err);
      res.status(500).json({ error: 'present_failed' });
    }
  });
}

// ── Store API ──────────────────────────────────────────────────────────────

app.get('/api/catalog', (_req, res) => {
  res.json({ products: CATALOG });
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

// A cart with a 21+ item must pass PAVEL's age check before the order goes through. Until
// the user has proven their age, requireAgeProof answers 401 and the order is not placed.
const ageCheck = requireAgeProof({ minAge: MIN_AGE });

app.post(
  '/api/checkout',
  (req, res, next) => {
    const { hasRestricted } = cartView(req.session.cart ?? {});
    return hasRestricted ? ageCheck(req, res, next) : next();
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

// ── Static frontend ──────────────────────────────────────────────────────────
app.get('/pavel-client.js', (_req, res) => {
  res.type('application/javascript').sendFile(CLIENT_BUNDLE);
});
app.use(express.static(PUBLIC_DIR));

app.listen(PORT, () => {
  console.log(`Cellar & Co. running at ${ORIGIN}`);
  console.log(`  trusting ${trustAnchors.length} ID issuer(s)${DEV_WALLET ? ', including the dev wallet’s test issuer' : ''}`);
  if (DEV_WALLET) console.log('  dev wallet: ON (set NODE_ENV=production to turn it off)');
});
