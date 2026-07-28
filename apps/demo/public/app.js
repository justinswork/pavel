/** Store front-end: catalog, cart, and the age-gated checkout flow. */
(function () {
  'use strict';

  const grid = document.getElementById('product-grid');
  const cartItemsEl = document.getElementById('cart-items');
  const cartTotalEl = document.getElementById('cart-total');
  const checkoutBtn = document.getElementById('checkout-btn');
  const clearBtn = document.getElementById('clear-btn');
  const checkoutMsg = document.getElementById('checkout-msg');
  const badge = document.getElementById('verify-badge');
  const reverifyToggle = document.getElementById('reverify-toggle');

  let minAge = 21;

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

  function setBadge(verified, age) {
    if (verified) {
      badge.className = 'badge badge-verified';
      badge.textContent = `✓ Age-verified (${age}+)`;
    } else {
      badge.className = 'badge badge-unverified';
      badge.textContent = 'Not age-verified';
    }
  }

  function msg(text, kind) {
    checkoutMsg.textContent = text;
    checkoutMsg.className = `checkout-msg ${kind ? 'msg-' + kind : ''}`;
  }

  async function refreshStatus() {
    const { body } = await api('/api/status');
    setBadge(body.verified, body.verifiedMinAge);
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
    const checkoutReq = () =>
      api('/api/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ forceReverify: reverifyToggle.checked }),
      });
    let res = await checkoutReq();

    // Gate says verification is required → run the PAVEL ceremony, then retry.
    if (res.status === 401 && res.body.error === 'age_verification_required') {
      msg('Age verification required — opening wallet…', 'info');
      const proof = await window.pavelClient.requestAgeProof({ minAge });
      await refreshStatus();
      if (!proof.ok) {
        msg(reasonText(proof.reason), 'error');
        return;
      }
      res = await checkoutReq();
    }

    if (res.status === 200 && res.body.ok) {
      msg(
        `Order placed — ${res.body.itemCount} item(s), ${money(res.body.orderTotal)}. No personal data was received.`,
        'success',
      );
      const cart = await api('/api/cart');
      renderCart(cart.body);
      // With forceReverify the proof is now consumed — reflect it in the badge.
      await refreshStatus();
    } else if (res.body.error === 'empty_cart') {
      msg('Your cart is empty.', 'error');
    } else {
      msg('Checkout failed.', 'error');
    }
  }

  function reasonText(reason) {
    switch (reason) {
      case 'declined':
        return 'You declined to share age. Checkout cancelled.';
      case 'predicate_false':
        return `Verification says you are not over ${minAge}. Age-restricted items cannot be purchased.`;
      case 'predicate_unavailable':
        return 'That credential does not carry the requested age attribute.';
      case 'untrusted_issuer':
        return 'That credential is from an issuer this store does not trust.';
      case 'unsupported':
        return 'This browser has no digital wallet support.';
      default:
        return `Verification failed (${reason}).`;
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
    minAge = cat.body.minAge ?? 21;
    renderCatalog(cat.body.products);
    renderCart(cart.body);
    await refreshStatus();
  })();
})();
