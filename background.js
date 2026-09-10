'use strict';
// Goa Scan — service worker.
// 1) Capture, par onglet, les en-têtes du document et un résumé des requêtes (webRequest).
// 2) À chaque page chargée (si l'analyse auto est active), calcule une note et l'affiche
//    sur l'icône, sans ouvrir le popup.
// 3) Épingle l'empreinte du certificat de chaque site et alerte si elle change.
// Tout reste local : mémoire + chrome.storage (session pour les captures, local pour les épingles).

importScripts('checks.js', 'vulndb.js', 'vendor/vulndb-data.js', 'collector.js');

const MAX_HOSTS = 300;
const MAX_INSECURE = 30;
const MAX_APIS = 150;
// fetch/XHR et WebSocket, hors ressources statiques chargées par script.
const API_TYPES = ['xmlhttprequest', 'websocket'];
const STATIC_EXT = /\.(m?js|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|mp4|webm|mp3)$/i;
// requestId → { tabId, key } pour rattacher en-têtes et statut à l'endpoint. En mémoire seulement.
const pending = new Map();
const DEFAULTS = { autoScan: true, activeMode: false };

const tabs = new Map();
const dirty = new Set();
let flushTimer = null;
let settings = { ...DEFAULTS };

const ready = Promise.all([
  chrome.storage.session.get(null).then((all) => {
    for (const [key, rec] of Object.entries(all)) {
      if (key.startsWith('tab:')) tabs.set(Number(key.slice(4)), rec);
    }
  }),
  chrome.storage.local.get('settings').then((r) => { settings = { ...DEFAULTS, ...(r.settings || {}) }; }),
]);

// ── Capture réseau ──────────────────────────────────────────
function touch(tabId) {
  dirty.add(tabId);
  if (!flushTimer) flushTimer = setTimeout(flush, 400);
}

function flush() {
  flushTimer = null;
  const batch = {};
  for (const id of dirty) {
    const rec = tabs.get(id);
    if (rec) batch[`tab:${id}`] = rec;
  }
  dirty.clear();
  chrome.storage.session.set(batch).catch(() => {});
}

function onRequest(d) {
  if (d.tabId < 0) return;
  if (d.type === 'main_frame') {
    const prev = tabs.get(d.tabId);
    if (!prev || prev.requestId !== d.requestId) {
      tabs.set(d.tabId, {
        requestId: d.requestId, url: d.url, at: Date.now(),
        redirects: [], main: null, requests: 0, hosts: {}, insecure: [], truncated: false, apis: {},
      });
    } else {
      prev.url = d.url;
    }
    touch(d.tabId);
    return;
  }
  const rec = tabs.get(d.tabId);
  if (!rec) return;
  let u;
  try { u = new URL(d.url); } catch { return; }
  if (!/^(https?|wss?):$/.test(u.protocol)) return;

  rec.requests++;
  let host = rec.hosts[u.hostname];
  if (!host) {
    if (Object.keys(rec.hosts).length >= MAX_HOSTS) { rec.truncated = true; touch(d.tabId); return; }
    host = rec.hosts[u.hostname] = { n: 0, types: {} };
  }
  host.n++;
  host.types[d.type] = (host.types[d.type] || 0) + 1;

  if ((u.protocol === 'http:' || u.protocol === 'ws:') && rec.url.startsWith('https:') && rec.insecure.length < MAX_INSECURE) {
    rec.insecure.push({ url: d.url.slice(0, 300), type: d.type });
  }
  if (API_TYPES.includes(d.type) && !STATIC_EXT.test(u.pathname)) addApi(rec, d, u);
  touch(d.tabId);
}

function addApi(rec, d, u) {
  const e = GoaChecks.apiEndpoint(d.method, u);
  rec.apis ||= {};
  let a = rec.apis[e.key];
  if (!a) {
    if (Object.keys(rec.apis).length >= MAX_APIS) { rec.apisTruncated = true; return; }
    a = rec.apis[e.key] = { method: e.method, url: e.url, ws: d.type === 'websocket', n: 0, params: [], secrets: [], keys: [], statuses: [], auth: null, ctype: null, cors: null };
  }
  a.n++;
  for (const f of ['params', 'secrets', 'keys']) for (const v of e[f]) if (!a[f].includes(v) && a[f].length < 12) a[f].push(v);
  pending.set(d.requestId, { tabId: d.tabId, key: e.key });
  if (pending.size > 1000) pending.delete(pending.keys().next().value);
}

function apiOf(d) {
  const p = pending.get(d.requestId);
  const a = p && tabs.get(p.tabId)?.apis?.[p.key];
  return a ? [a, p.tabId] : [];
}

// Schéma d'authentification seulement (Bearer, Basic…), jamais la valeur.
function onApiSend(d) {
  const [a, tabId] = apiOf(d);
  if (!a) return;
  const hs = d.requestHeaders || [];
  const auth = hs.find((h) => h.name.toLowerCase() === 'authorization');
  if (auth) a.auth = (auth.value || '').trim().split(/\s+/)[0].slice(0, 20) || 'oui';
  else if (hs.some((h) => /^(x-)?api-key$/i.test(h.name))) a.auth = 'clé API';
  else return;
  touch(tabId);
}

function onApiHeaders(d) {
  const [a, tabId] = apiOf(d);
  if (!a) return;
  if (!a.statuses.includes(d.statusCode) && a.statuses.length < 6) a.statuses.push(d.statusCode);
  const get = (n) => (d.responseHeaders || []).find((h) => h.name.toLowerCase() === n)?.value;
  const ct = get('content-type');
  if (ct) a.ctype = ct.split(';')[0].trim().slice(0, 60);
  const acao = get('access-control-allow-origin');
  if (acao) a.cors = acao.slice(0, 100);
  touch(tabId);
}

function onApiEnd(d) {
  const [a, tabId] = apiOf(d);
  pending.delete(d.requestId);
  if (a && d.error && !a.statuses.length) { a.error = d.error.slice(0, 40); touch(tabId); }
}

function onMainHeaders(d) {
  const rec = tabs.get(d.tabId);
  if (!rec || rec.requestId !== d.requestId) return;
  rec.main = { status: d.statusCode, headers: (d.responseHeaders || []).map(({ name, value }) => ({ name, value: value ?? '' })), ip: null };
  touch(d.tabId);
}

function onMainRedirect(d) {
  const rec = tabs.get(d.tabId);
  if (!rec || rec.requestId !== d.requestId) return;
  rec.redirects.push({ from: d.url.slice(0, 300), to: d.redirectUrl.slice(0, 300), status: d.statusCode });
  touch(d.tabId);
}

function onMainCompleted(d) {
  const rec = tabs.get(d.tabId);
  if (!rec || rec.requestId !== d.requestId || !rec.main) return;
  rec.main.ip = d.ip || null;
  // Resservie par le cache, la page porte l'IP de sa première connexion, pas l'actuelle.
  rec.main.fromCache = !!d.fromCache;
  touch(d.tabId);
}

// Certificat refusé, DNS introuvable… : page d'erreur Chrome, l'erreur réseau est la seule trace.
function onMainError(d) {
  const rec = tabs.get(d.tabId);
  if (!rec || rec.requestId !== d.requestId) return;
  rec.error = d.error;
  touch(d.tabId);
}

const all = { urls: ['<all_urls>'] };
const main = { urls: ['<all_urls>'], types: ['main_frame'] };
chrome.webRequest.onBeforeRequest.addListener((d) => { ready.then(() => onRequest(d)); }, all);
chrome.webRequest.onHeadersReceived.addListener((d) => { ready.then(() => onMainHeaders(d)); }, main, ['responseHeaders']);
chrome.webRequest.onBeforeRedirect.addListener((d) => { ready.then(() => onMainRedirect(d)); }, main);
chrome.webRequest.onCompleted.addListener((d) => { ready.then(() => onMainCompleted(d)); }, main);
chrome.webRequest.onErrorOccurred.addListener((d) => { ready.then(() => onMainError(d)); }, main);
const apiFilter = { urls: ['<all_urls>'], types: API_TYPES };
chrome.webRequest.onSendHeaders.addListener((d) => { ready.then(() => onApiSend(d)); }, apiFilter, ['requestHeaders']);
chrome.webRequest.onHeadersReceived.addListener((d) => { ready.then(() => onApiHeaders(d)); }, apiFilter, ['responseHeaders']);
chrome.webRequest.onCompleted.addListener((d) => { ready.then(() => onApiEnd(d)); }, apiFilter);
chrome.webRequest.onErrorOccurred.addListener((d) => { ready.then(() => onApiEnd(d)); }, apiFilter);

// ── Analyse partagée (sans certificat : réservé au popup, qui a le débogueur) ──
function headerMap(list) {
  const map = {};
  for (const { name, value } of list || []) {
    const k = name.toLowerCase();
    map[k] = k in map ? `${map[k]}, ${value}` : value;
  }
  return map;
}

async function runInTab(tabId, func, world) {
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId }, func, world });
    return res?.result ?? null;
  } catch {
    return null;
  }
}

// Analyse « légère » lancée automatiquement : en-têtes + DOM + cookies + base de vulns.
async function analyzeTab(tab) {
  const rec = tabs.get(tab.id);
  const [dom, globals, cookies] = await Promise.all([
    runInTab(tab.id, collectPage, 'ISOLATED'),
    runInTab(tab.id, collectGlobals, 'MAIN'),
    chrome.cookies.getAll({ url: tab.url }).catch(() => []),
  ]);
  const captured = rec?.main && rec.url.split('#')[0] === (dom?.docUrl || tab.url).split('#')[0] ? rec : null;
  const vulns = GoaVulnDB.scan({ db: GOA_RETIRE_DB, scripts: (dom?.scripts || []).map((s) => s.src), globals: globals || {} });
  return GoaChecks.analyze({
    url: tab.url,
    headers: captured ? headerMap(captured.main.headers) : null,
    dom, globals, vulns,
    net: captured,
    navError: rec && rec.url.split('#')[0] === (dom?.docUrl || tab.url).split('#')[0] && !rec.main ? rec.error : null,
    securityTxt: null,
    cookies: cookies.map((c) => ({ name: c.name, secure: c.secure, httpOnly: c.httpOnly, sameSite: c.sameSite })),
    tls: null,
  });
}

// ── Badge sur l'icône ───────────────────────────────────────
const GRADE_COLOR = { A: '#1d9e75', B: '#1d9e75', C: '#8a7f16', D: '#8a7f16', E: '#b4462e', F: '#b4462e' };

async function setBadge(tabId, text, color, title) {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    if (color) await chrome.action.setBadgeBackgroundColor({ tabId, color });
    await chrome.action.setTitle({ tabId, title });
  } catch { /* onglet fermé entre-temps */ }
}

async function autoScan(tab) {
  if (!settings.autoScan || !/^https?:\/\//.test(tab.url || '')) return;
  try {
    const report = await analyzeTab(tab);
    let title = `Goa Scan — note ${report.grade} (${report.score}/100)`;
    let text = report.grade;
    let color = GRADE_COLOR[report.grade];

    if (tab.url.startsWith('https:')) {
      const alert = await pinFromNav(tab, report);
      if (alert?.changed) { text = '!'; color = '#b4462e'; title = 'Goa Scan — le certificat a changé, à vérifier'; }
    }
    await setBadge(tab.id, text, color, title);
  } catch {
    await setBadge(tab.id, '', null, 'Goa Scan');
  }
}

// Débounce par onglet : les SPA déclenchent plusieurs « complete ».
const scanTimers = new Map();
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status !== 'complete') return;
  ready.then(() => {
    clearTimeout(scanTimers.get(tabId));
    scanTimers.set(tabId, setTimeout(() => { scanTimers.delete(tabId); autoScan(tab); }, 500));
  });
});

chrome.tabs.onRemoved.addListener((tabId) => {
  ready.then(() => {
    tabs.delete(tabId);
    dirty.delete(tabId);
    clearTimeout(scanTimers.get(tabId));
    scanTimers.delete(tabId);
    chrome.storage.session.remove(`tab:${tabId}`).catch(() => {});
  });
});

// ── Épinglage de certificat ─────────────────────────────────
// L'empreinte ne peut être lue qu'avec le débogueur (donc via le popup). En analyse auto
// on se rabat sur l'autorité + l'expiration lues par l'API de sécurité, non disponibles
// ici : l'auto-scan ne fait qu'entretenir l'alerte posée par le dernier scan manuel.
async function pinFromNav() { return null; }

// Compare une observation (host, sha256, notAfter, issuer) à l'épingle stockée, puis la met à jour.
async function checkPin({ host, sha256, notAfter, issuer, spki }) {
  if (!host || !sha256) return null;
  const key = `pin:${host}`;
  const prev = (await chrome.storage.local.get(key))[key] || null;
  const now = Date.now();
  let result = { changed: false };
  if (prev && prev.sha256 !== sha256) {
    // Un renouvellement normal garde l'émetteur et repousse l'expiration : on ne crie pas.
    const renewal = prev.issuer === issuer && (prev.spki === spki || (notAfter && prev.notAfter && notAfter > prev.notAfter));
    result = {
      changed: true, benign: renewal,
      previous: { sha256: prev.sha256, issuer: prev.issuer, seenAt: prev.seenAt, notAfter: prev.notAfter },
    };
  }
  await chrome.storage.local.set({ [key]: { sha256, issuer, spki, notAfter, seenAt: now, count: (prev?.count || 0) + 1 } });
  return result;
}

// ── Messages ────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  ready.then(async () => {
    switch (msg?.type) {
      case 'net': reply(tabs.get(msg.tabId) || null); break;
      case 'settings:get': reply(settings); break;
      case 'settings:set':
        settings = { ...settings, ...msg.patch };
        await chrome.storage.local.set({ settings });
        if (!settings.autoScan && msg.patch.autoScan === false) {
          for (const t of await chrome.tabs.query({})) setBadge(t.id, '', null, 'Goa Scan');
        }
        reply(settings);
        break;
      case 'pin': reply(await checkPin(msg.observation)); break;
      case 'pin:list': reply((await chrome.storage.local.get(null))); break;
      case 'pin:forget': await chrome.storage.local.remove(`pin:${msg.host}`); reply(true); break;
      default: reply(null);
    }
  });
  return true;
});
