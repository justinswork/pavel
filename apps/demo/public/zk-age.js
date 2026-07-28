/**
 * zk-age.js — MOCK of the PAVEL client SDK (@justinswork/pavel-client).
 *
 * Public surface matches ARCHITECTURE.md §8:
 *   window.pavelClient.requestAgeProof({ minAge }) -> { ok, reason? }
 *
 * The real SDK calls navigator.credentials.get({ digital: … }) to invoke the OS
 * wallet. No wallet exists in this testbed, so requestAgeProof drives a clearly
 * labelled SIMULATED WALLET modal that fabricates the vp_token the wallet would
 * otherwise return. Everything server-side (nonce, origin, session) is real.
 */
(function () {
  'use strict';

  function base64urlEncode(str) {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  /**
   * The mock wallet. Given the OpenID4VP request, presents scenario choices and
   * resolves to either a fabricated vp_token or a { declined: true } signal.
   */
  function openMockWallet(authRequest, minAge) {
    return new Promise((resolve) => {
      const predicate = `age_over_${minAge}`;
      const nonce = authRequest.nonce;
      const origin = window.location.origin;

      // Each scenario builds a token that exercises a specific pipeline outcome.
      const scenarios = [
        {
          label: `✅ Present credential — over ${minAge}`,
          hint: 'Valid mDL, predicate true → "verified"',
          kind: 'primary',
          token: { claims: { [predicate]: true }, issuer: 'mock-iaca' },
        },
        {
          label: `🔞 Present credential — under ${minAge}`,
          hint: 'Valid mDL, predicate false → "predicate_false"',
          kind: 'normal',
          token: { claims: { [predicate]: false }, issuer: 'mock-iaca' },
        },
        {
          label: '❓ Credential without this predicate',
          hint: 'Issuer never signed it → "predicate_unavailable"',
          kind: 'normal',
          token: { claims: {}, issuer: 'mock-iaca' },
        },
        {
          label: '⚠️ Credential from untrusted issuer',
          hint: 'Signer not in trust list → "untrusted_issuer"',
          kind: 'normal',
          token: { claims: { [predicate]: true }, issuer: 'rogue-dmv' },
        },
        {
          label: 'Cancel / decline sharing',
          hint: 'User dismisses the wallet prompt',
          kind: 'ghost',
          declined: true,
        },
      ];

      const overlay = document.createElement('div');
      overlay.className = 'mw-overlay';
      overlay.innerHTML = `
        <div class="mw-modal" role="dialog" aria-modal="true" aria-label="Simulated wallet">
          <div class="mw-badge">SIMULATED WALLET · not a real credential</div>
          <h2 class="mw-title">${escapeHtml(
            authRequest.client_metadata?.client_name || 'A website',
          )} requests:</h2>
          <p class="mw-ask">Share <strong>“are you over ${minAge}?”</strong> — yes/no only.<br>
             <span class="mw-fine">Your name, birthdate, address and photo stay on your device.</span></p>
          <div class="mw-scenarios"></div>
          <div class="mw-meta">nonce <code>${escapeHtml(nonce.slice(0, 12))}…</code> · origin <code>${escapeHtml(
            origin,
          )}</code></div>
        </div>`;

      const list = overlay.querySelector('.mw-scenarios');
      for (const s of scenarios) {
        const btn = document.createElement('button');
        btn.className = `mw-btn mw-${s.kind}`;
        btn.innerHTML = `<span class="mw-btn-label">${escapeHtml(s.label)}</span><span class="mw-btn-hint">${escapeHtml(
          s.hint,
        )}</span>`;
        btn.addEventListener('click', () => {
          document.body.removeChild(overlay);
          if (s.declined) {
            resolve({ declined: true });
            return;
          }
          const presentation = {
            nonce,
            origin,
            doctype: 'org.iso.18013.5.1.mDL',
            issuer: s.token.issuer,
            claims: s.token.claims,
          };
          resolve({ vpToken: base64urlEncode(JSON.stringify(presentation)) });
        });
        list.appendChild(btn);
      }

      document.body.appendChild(overlay);
    });
  }

  function escapeHtml(s) {
    return String(s).replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]),
    );
  }

  /**
   * Run the whole ceremony: GET request → (mock) wallet → POST verify.
   * Returns { ok: true } | { ok: false, reason }.
   */
  async function requestAgeProof({ minAge }) {
    // The real SDK feature-detects the DC API here and returns 'unsupported'
    // when absent. In this testbed we always fall through to the mock wallet.
    let authRequest;
    try {
      const r = await fetch(`/pavel/request?minAge=${encodeURIComponent(minAge)}`);
      if (!r.ok) return { ok: false, reason: 'request_failed' };
      authRequest = await r.json();
    } catch {
      return { ok: false, reason: 'request_failed' };
    }

    const walletResult = await openMockWallet(authRequest, minAge);
    if (walletResult.declined) return { ok: false, reason: 'declined' };

    try {
      const r = await fetch('/pavel/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ vp_token: walletResult.vpToken }),
      });
      const body = await r.json();
      if (body.ok) return { ok: true };
      // Map server outcomes to the SDK's reason vocabulary (ARCHITECTURE.md §8).
      const reason =
        body.outcome === 'predicate_false'
          ? 'predicate_false'
          : body.outcome || 'verification_failed';
      return { ok: false, reason };
    } catch {
      return { ok: false, reason: 'verification_failed' };
    }
  }

  window.pavelClient = { requestAgeProof };
})();
