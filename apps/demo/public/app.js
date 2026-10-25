/** Store front-end: catalog, cart, and the age-checked checkout. */
(function () {
  'use strict';

  const grid = document.getElementById('product-grid');
  const cartItemsEl = document.getElementById('cart-items');
  const cartTotalEl = document.getElementById('cart-total');
  const checkoutBtn = document.getElementById('checkout-btn');
  const clearBtn = document.getElementById('clear-btn');
  const checkoutMsg = document.getElementById('checkout-msg');
  const reverifyToggle = document.getElementById('reverify-toggle');

  const money = (n) => `$${n.toFixed(2)}`;

  async function api(path, options) {
    const r = await fetch(path, options);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  }

  function renderCatalog(products) {
    grid.innerHTML = '';
    for (const p of products) {
      const card = document.createElement('div');
      card.className = 'card';
      card.innerHTML = `
        <div class="card-emoji">${p.emoji}</div>
        <div class="card-body">
          <div class="card-name">${p.name}${
            p.ageRestricted ? ' <span class="pill pill-21">21+</span>' : ''
          }</div>
          <div class="card-blurb">${p.blurb}</div>
          <div class="card-foot">
            <span class="price">${money(p.price)}</span>
            <button class="btn btn-add" data-id="${p.id}">Add</button>
          </div>
        </div>`;
      grid.appendChild(card);
    }
    grid.querySelectorAll('.btn-add').forEach((btn) =>
      btn.addEventListener('click', () => addToCart(btn.dataset.id)),
    );
  }

  function renderCart(view) {
    cartItemsEl.innerHTML = '';
    if (view.items.length === 0) {
      cartItemsEl.innerHTML = '<p class="empty">Your cart is empty.</p>';
    }
    for (const it of view.items) {
      const row = document.createElement('div');
      row.className = 'cart-row';
      row.innerHTML = `
        <span class="cart-emoji">${it.emoji}</span>
        <span class="cart-name">${it.name}${
          it.ageRestricted ? ' <span class="pill pill-21">21+</span>' : ''
        }</span>
        <span class="qty">
          <button class="qbtn" data-id="${it.id}" data-delta="-1">−</button>
          <span>${it.qty}</span>
          <button class="qbtn" data-id="${it.id}" data-delta="1">+</button>
        </span>
        <span class="cart-line">${money(it.lineTotal)}</span>`;
      cartItemsEl.appendChild(row);
    }
    cartItemsEl.querySelectorAll('.qbtn').forEach((btn) =>
      btn.addEventListener('click', () =>
        addToCart(btn.dataset.id, Number(btn.dataset.delta)),
      ),
    );
    cartTotalEl.textContent = money(view.total);
    checkoutBtn.disabled = view.items.length === 0;
    checkoutBtn.textContent = view.hasRestricted ? 'Checkout (age check) →' : 'Checkout →';
  }

  function msg(text, kind) {
    checkoutMsg.textContent = text;
    checkoutMsg.className = `checkout-msg ${kind ? 'msg-' + kind : ''}`;
  }

  async function addToCart(productId, qty = 1) {
    const { body } = await api('/api/cart', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ productId, qty }),
    });
    renderCart(body);
  }

  async function checkout() {
    msg('', null);
    const placeOrder = () =>
      api('/api/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ forceReverify: reverifyToggle.checked }),
      });
    let res = await placeOrder();
    let ageChecked = false;

    // The server says an age check is needed (and which age): run it, then try again.
    if (res.status === 401 && res.body.error === 'age_verification_required') {
      const { minAge } = res.body;
      msg('Age verification required — opening wallet…', 'info');
      const proof = await runAgeCheck(minAge);
      if (!proof.ok) {
        msg(reasonText(proof.reason, minAge), 'error');
        return;
      }
      ageChecked = true;
      res = await placeOrder();
    }

    if (res.status === 200 && res.body.ok) {
      msg(
        `Order placed — ${res.body.itemCount} item(s), ${money(res.body.orderTotal)}.` +
          (ageChecked ? ' No personal data was received.' : ''),
        'success',
      );
      const cart = await api('/api/cart');
      renderCart(cart.body);
    } else if (res.body.error === 'empty_cart') {
      msg('Your cart is empty.', 'error');
    } else {
      msg('Checkout failed.', 'error');
    }
  }

  /**
   * Open the phone's wallet through PAVEL. If no wallet answered (for example, in a desktop
   * browser) and the dev wallet is loaded, which it only is in development, use it instead.
   */
  async function runAgeCheck(minAge) {
    let walletAnswered = false;
    const proof = await window.pavelClient.requestAgeProof({
      minAge,
      onDiagnostic: (event) => {
        if (event.stage === 'walletResponse') walletAnswered = true;
      },
    });
    if (proof.ok || walletAnswered || !window.pavelDevWallet) return proof;
    return window.pavelDevWallet.run({ minAge });
  }

  function reasonText(reason, minAge) {
    switch (reason) {
      case 'declined':
        return 'You declined to share your age. Checkout cancelled.';
      case 'unsupported':
        return "This browser doesn't support digital IDs. Try Chrome on Android or Safari on iPhone.";
      case 'predicate_false':
        return `Your ID shows you are not over ${minAge}, so age-restricted items can't be purchased.`;
      case 'predicate_unavailable':
        return "That ID doesn't include the age information this store needs.";
      case 'untrusted_issuer':
        return "That ID is from an issuer this store doesn't accept.";
      default:
        return `Age verification failed (${reason}).`;
    }
  }

  clearBtn.addEventListener('click', async () => {
    const { body } = await api('/api/cart/clear', { method: 'POST' });
    renderCart(body);
    msg('', null);
  });
  checkoutBtn.addEventListener('click', checkout);

  // Boot.
  (async () => {
    const [cat, cart] = await Promise.all([api('/api/catalog'), api('/api/cart')]);
    renderCatalog(cat.body.products);
    renderCart(cart.body);
  })();
})();
