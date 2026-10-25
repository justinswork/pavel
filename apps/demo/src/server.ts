/**
 * Cellar & Co. — an example store: a product catalog, a session cart, and checkout.
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import express from 'express';
import session from 'express-session';
import { CATALOG, CATALOG_BY_ID } from './catalog.js';

// The store keeps a cart in the session.
declare module 'express-session' {
  interface SessionData {
    cart?: Record<string, number>;
  }
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

const PORT = Number(process.env.PORT ?? 3000);

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
  return { items, total };
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

app.post('/api/checkout', (req, res) => {
  const view = cartView(req.session.cart ?? {});
  if (view.items.length === 0) {
    res.status(400).json({ error: 'empty_cart' });
    return;
  }
  req.session.cart = {};
  res.json({ ok: true, orderTotal: view.total, itemCount: view.items.length });
});

// ── Static frontend ──────────────────────────────────────────────────────────
app.use(express.static(PUBLIC_DIR));

app.listen(PORT, () => {
  console.log(`Cellar & Co. running at http://localhost:${PORT}`);
});
