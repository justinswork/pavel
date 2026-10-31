/**
 * dev-wallet.js — DEVELOPMENT ONLY. A stand-in for the phone's wallet, for browsers that
 * don't have one (like desktop browsers). The server only serves this file outside
 * production.
 *
 * It drives the store's real PAVEL endpoints with a simulated wallet in the middle:
 *
 *   GET  /pavel/request        → the real challenge
 *   (you pick an outcome in the dialog below)
 *   POST /dev-wallet/present   → the server presents a real, signed test ID
 *   POST /pavel/verify         → the real PAVEL verifier
 *
 * Only the wallet is simulated; the challenge, the ID's signatures, and the verification
 * are all real. Exposes window.pavelDevWallet.run({ minAge }).
 */
(function () {
  'use strict';

  function escapeHtml(s) {
    return String(s).replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]),
    );
  }

  /** Present the scenario choices; resolve to a server scenario id or { declined }. */
  function openWallet(authRequest, minAge) {
    return new Promise((resolve) => {
      const scenarios = [
        { id: 'over', label: `✅ Present credential — over ${minAge}`, hint: 'Valid mDL, predicate true → "verified"', kind: 'primary' },
        { id: 'under', label: `🔞 Present credential — under ${minAge}`, hint: 'Valid mDL, predicate false → "predicate_false"', kind: 'normal' },
        { id: 'absent', label: '❓ Credential without this predicate', hint: 'Issuer never signed it → "predicate_unavailable"', kind: 'normal' },
        { id: 'untrusted', label: '⚠️ Credential from untrusted issuer', hint: 'Signer not in trust list → "untrusted_issuer"', kind: 'normal' },
        { id: 'decline', label: 'Cancel / decline sharing', hint: 'Dismiss the wallet prompt', kind: 'ghost', declined: true },
      ];

      const nonce = authRequest.nonce ?? '';
      const origin = window.location.origin;
      const clientName = authRequest.client_metadata?.client_name || 'A website';

      const overlay = document.createElement('div');
      overlay.className = 'mw-overlay';
      overlay.innerHTML = `
        <div class="mw-modal" role="dialog" aria-modal="true" aria-label="Dev wallet">
          <div class="mw-badge">DEV WALLET · real credential, simulated holder</div>
          <h2 class="mw-title">${escapeHtml(clientName)} requests:</h2>
          <p class="mw-ask">Share <strong>“are you over ${minAge}?”</strong> — yes/no only.<br>
             <span class="mw-fine">Your name, birthdate, address and photo stay on your device.</span></p>
          <div class="mw-scenarios"></div>
          <div class="mw-meta">nonce <code>${escapeHtml(String(nonce).slice(0, 12))}…</code> · origin <code>${escapeHtml(origin)}</code></div>
        </div>`;

      const list = overlay.querySelector('.mw-scenarios');
      for (const s of scenarios) {
        const btn = document.createElement('button');
        btn.className = `mw-btn mw-${s.kind}`;
        btn.innerHTML = `<span class="mw-btn-label">${escapeHtml(s.label)}</span><span class="mw-btn-hint">${escapeHtml(s.hint)}</span>`;
        btn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          resolve(s.declined ? { declined: true } : { scenario: s.id });
        });
        list.appendChild(btn);
      }
      document.body.appendChild(overlay);
    });
  }

  /** Run the ceremony with the dev wallet. Returns { ok } | { ok:false, reason }. */
  async function run({ minAge }) {
    let authRequest;
    try {
      const r = await fetch(`/pavel/request?minAge=${encodeURIComponent(minAge)}`);
      if (!r.ok) return { ok: false, reason: 'request_failed' };
      const fetched = await r.json();
      // The server offers several protocols; the dev wallet answers the unsigned OpenID4VP one.
      authRequest =
        fetched?.requests?.find((x) => x.protocol === 'openid4vp-v1-unsigned')?.data ?? fetched;
    } catch {
      return { ok: false, reason: 'request_failed' };
    }

    const choice = await openWallet(authRequest, minAge);
    if (choice.declined) return { ok: false, reason: 'declined' };

    let vpToken;
    try {
      const r = await fetch('/dev-wallet/present', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ scenario: choice.scenario }),
      });
      if (!r.ok) return { ok: false, reason: 'verification_failed' };
      ({ vp_token: vpToken } = await r.json());
    } catch {
      return { ok: false, reason: 'verification_failed' };
    }

    try {
      const r = await fetch('/pavel/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vp_token: vpToken }),
      });
      const body = await r.json();
      return body.ok ? { ok: true } : { ok: false, reason: body.outcome || 'verification_failed' };
    } catch {
      return { ok: false, reason: 'verification_failed' };
    }
  }

  // Make it obvious this store is running in development mode.
  const banner = document.createElement('div');
  banner.className = 'dev-banner';
  banner.innerHTML =
    '🔒 <strong>Development mode</strong> — if this browser has no ID wallet, a stand-in <em>dev wallet</em> presents real, signed test IDs.';
  document.body.prepend(banner);

  window.pavelDevWallet = { run };
})();
