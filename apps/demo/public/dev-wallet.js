/**
 * dev-wallet.js — the DEV WALLET fallback for environments with no OS wallet.
 *
 * The real ceremony (pavel-client → navigator.credentials.get → an OS wallet)
 * can't run in a plain browser, so this drives the same REAL server endpoints
 * with a simulated holder in the middle:
 *
 *   GET /pavel/request   → the real challenge (mints the session nonce)
 *   (user picks a scenario in the modal below)
 *   POST /dev-wallet/present → the server mints & presents a REAL mDL DeviceResponse
 *   POST /pavel/verify   → the real @justinswork/pavel-core pipeline
 *
 * Only the holder is simulated. The request, the credential crypto, and the
 * verification are all real. Exposes window.pavelDevWallet.run({ minAge }).
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
      authRequest = await r.json();
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

  window.pavelDevWallet = { run };
})();
