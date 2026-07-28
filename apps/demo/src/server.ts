/**
 * PAVEL demo store — Express server.
 *
 * Wires a minimal e-commerce store to the MOCK PAVEL gate (src/pavel-mock).
 * The store is the end-to-end testbed: browse → cart → checkout, where a cart
 * containing an age-restricted item forces the verification ceremony.
 */

import { fileURLToPath } from 'node:url';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import { CATALOG, CATALOG_BY_ID, MIN_AGE } from './catalog.js';
import { pavel, requireAgeProof } from './pavel-mock/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const PORT = Number(process.env.PORT ?? 3000);
const ORIGIN = process.env.ORIGIN ?? `http://localhost:${PORT}`;

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

// ── Mount the PAVEL ceremony endpoints (GET /pavel/request, POST /pavel/verify).
app.use(
  pavel({
    origin: ORIGIN,
    trustAnchors: [], // mock verifier ignores these; real -core would take IACA certs
  }),
);

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
app.post('/api/checkout', (req, res, next) => {
  const { hasRestricted } = cartView(req.session.cart ?? {});
  if (!hasRestricted) return next();
  // Demo toggle: a real store hard-codes this per its compliance policy.
  const forceReverify = Boolean(req.body?.forceReverify);
  return requireAgeProof({ minAge: MIN_AGE, forceReverify })(req, res, next);
}, (req, res) => {
  const view = cartView(req.session.cart ?? {});
  if (view.items.length === 0) {
    res.status(400).json({ error: 'empty_cart' });
    return;
  }
  req.session.cart = {};
  res.json({ ok: true, orderTotal: view.total, itemCount: view.items.length });
});

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
  console.log(`  (mock age-gate — min age ${MIN_AGE})`);
});
