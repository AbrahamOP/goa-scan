'use strict';
// Fonctions injectées dans l'onglet par chrome.scripting.executeScript.
// Elles sont sérialisées avant l'injection : aucune référence à une variable extérieure.
// Tout ce qu'elles renvoient vient de la page, donc est traité comme non fiable.

/* exported collectPage, collectGlobals, collectScriptSources */

// Monde isolé : texte des scripts inline et adresse de tous les scripts, y compris ceux
// chargés dynamiquement (import(), chunks), pour la recherche de secrets.
function collectScriptSources() {
  const MAX_ONE = 2e6;
  const MAX_TOTAL = 6e6;
  let total = 0;
  let n = 0;
  const inline = [];
  const urls = new Set();
  for (const s of document.scripts) {
    if (s.src) { urls.add(s.src); continue; }
    n++;
    const t = s.textContent || '';
    if (!t.trim() || total >= MAX_TOTAL) continue;
    const text = t.slice(0, Math.min(MAX_ONE, MAX_TOTAL - total));
    total += text.length;
    inline.push({ n, text });
  }
  for (const e of performance.getEntriesByType('resource')) {
    if (e.initiatorType === 'script' || /\.m?js(\?|$)/.test(e.name)) urls.add(e.name);
  }
  return { inline, urls: [...urls].filter((u) => /^https?:/.test(u)).slice(0, 80) };
}

// Monde isolé : lecture du DOM.
function collectPage() {
  const MAX = 200;
  const cut = (s, n = 300) => String(s ?? '').slice(0, n);
  const abs = (u) => { try { return new URL(u, document.baseURI).href; } catch { return null; } };
  const nav = performance.getEntriesByType('navigation')[0];

  const out = {
    docUrl: nav ? nav.name : location.href,
    contentType: document.contentType,
    scripts: [], inlineScripts: 0, stylesheets: [], iframes: [], forms: [], mixed: [],
    passwordFields: document.querySelectorAll('input[type="password" i]').length,
    inlineHandlers: 0, metaCsp: [], metaReferrer: null, generator: null,
    comments: { total: 0, flagged: [] },
    storage: { local: 0, session: 0, flagged: [] },
    emails: [], serviceWorker: false, hints: {},
  };

  const mixed = (kind, u) => {
    if (typeof u === 'string' && u.startsWith('http:') && out.mixed.length < MAX) out.mixed.push({ kind, url: cut(u) });
  };

  for (const s of document.scripts) {
    if (!s.src) { out.inlineScripts++; continue; }
    if (out.scripts.length < MAX) out.scripts.push({ src: cut(s.src), integrity: !!s.integrity });
    mixed('script', s.src);
  }
  for (const l of document.querySelectorAll('link[rel~="stylesheet" i][href]')) {
    if (out.stylesheets.length < MAX) out.stylesheets.push({ href: cut(l.href), integrity: !!l.integrity });
    mixed('stylesheet', l.href);
  }
  for (const f of document.querySelectorAll('iframe, frame')) {
    if (out.iframes.length < MAX) out.iframes.push({ src: cut(f.src), sandbox: f.hasAttribute('sandbox') });
    mixed('iframe', f.src);
  }
  for (const m of document.querySelectorAll('img[src], video[src], audio[src], source[src], embed[src], object[data]')) {
    const obj = m.tagName === 'OBJECT' || m.tagName === 'EMBED';
    mixed(obj ? 'object' : 'media', m.tagName === 'OBJECT' ? m.data : m.src);
  }
  for (const f of document.forms) {
    if (out.forms.length >= MAX) break;
    out.forms.push({
      action: cut(abs(f.getAttribute('action') || location.href)),
      method: cut((f.getAttribute('method') || 'get').toLowerCase(), 10),
      password: !!f.querySelector('input[type="password" i]'),
    });
  }

  const els = document.getElementsByTagName('*');
  for (let i = 0; i < els.length && i < 5000; i++) {
    for (const a of els[i].attributes) if (a.name.startsWith('on')) out.inlineHandlers++;
  }

  for (const m of document.querySelectorAll('meta[http-equiv]')) {
    if (m.httpEquiv.toLowerCase() === 'content-security-policy') out.metaCsp.push(cut(m.content, 4000));
  }
  out.metaReferrer = cut(document.querySelector('meta[name="referrer" i]')?.content, 60) || null;
  out.generator = cut(document.querySelector('meta[name="generator" i]')?.content, 120) || null;

  const KW = /passw|secret|api[_-]?key|token|private[_-]?key|credential/i;
  const tw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
  while (tw.nextNode() && out.comments.total < 2000) {
    out.comments.total++;
    const t = tw.currentNode.data.trim().replace(/\s+/g, ' ');
    if (KW.test(t) && out.comments.flagged.length < 20) out.comments.flagged.push(cut(t, 140));
  }

  // Noms de clés seulement : les valeurs ne sortent jamais de la page.
  const SENS = /token|jwt|auth|session|secret|passw|bearer|credential|api[_-]?key/i;
  const JWT = /(^|")eyJ[\w-]{5,}\.[\w-]{5,}\./;
  for (const [name, get] of [['local', () => localStorage], ['session', () => sessionStorage]]) {
    try {
      const st = get();
      out.storage[name] = st.length;
      for (let i = 0; i < st.length && i < 500; i++) {
        const k = st.key(i);
        const jwt = JWT.test((st.getItem(k) || '').slice(0, 5000));
        if ((jwt || SENS.test(k)) && out.storage.flagged.length < 30) out.storage.flagged.push({ area: name, key: cut(k, 80), jwt });
      }
    } catch { /* stockage bloqué par la page ou le navigateur */ }
  }

  const emails = new Set();
  const text = (document.body?.innerText || '').slice(0, 300000);
  for (const e of text.match(/[\w.+-]+@[\w-]+(\.[\w-]+)*\.[a-z]{2,}/gi) || []) emails.add(e.toLowerCase());
  for (const a of document.querySelectorAll('a[href^="mailto:" i]')) {
    const e = decodeURIComponent(a.getAttribute('href').slice(7).split('?')[0] || '');
    if (e) emails.add(e.toLowerCase());
  }
  out.emails = [...emails].slice(0, 20).map((e) => cut(e, 120));

  out.serviceWorker = !!navigator.serviceWorker?.controller;
  out.hints = {
    wordpress: !!document.querySelector('link[href*="/wp-content/"], script[src*="/wp-content/"], script[src*="/wp-includes/"]'),
    nextjs: !!document.getElementById('__NEXT_DATA__') || !!document.querySelector('script[src*="/_next/"]'),
    nuxt: !!document.getElementById('__NUXT_DATA__') || !!document.querySelector('script[src*="/_nuxt/"]'),
    angular: cut(document.querySelector('[ng-version]')?.getAttribute('ng-version'), 20) || null,
    shopify: !!document.querySelector('script[src*="cdn.shopify.com"], link[href*="cdn.shopify.com"]'),
    drupal: !!document.querySelector('[data-drupal-selector], script[src*="/core/misc/drupal"]'),
  };
  return out;
}

// Monde principal : versions des bibliothèques exposées en variables globales.
function collectGlobals() {
  const v = (x) => (typeof x === 'string' || typeof x === 'number') ? String(x).slice(0, 40) : null;
  const safe = (fn) => { try { return fn(); } catch { return null; } };
  return {
    jquery: safe(() => v(window.jQuery?.fn?.jquery)),
    jqueryUI: safe(() => v(window.jQuery?.ui?.version)),
    angularjs: safe(() => v(window.angular?.version?.full)),
    react: safe(() => v(window.React?.version)),
    vue: safe(() => v(window.Vue?.version) || (window.__VUE__ ? '3.x' : null)),
    bootstrap: safe(() => v(window.bootstrap?.Tooltip?.VERSION) || v(window.jQuery?.fn?.tooltip?.Constructor?.VERSION)),
    lodash: safe(() => v(window._?.VERSION)),
    moment: safe(() => v(window.moment?.version)),
    next: safe(() => v(window.next?.version)),
  };
}
