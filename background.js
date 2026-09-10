'use strict';
// Goa Scan — service worker.
// Garde, pour chaque onglet, les en-têtes de réponse du document principal et un
// résumé des requêtes émises par la page. Rien ne quitte le navigateur : les
// données vivent en mémoire et dans chrome.storage.session (vidé à la fermeture).

const MAX_HOSTS = 300;
const MAX_INSECURE = 30;

const tabs = new Map();
const dirty = new Set();
let flushTimer = null;

// Le service worker peut être arrêté à tout moment : on recharge l'état au réveil
// et chaque événement attend ce rechargement pour garder l'ordre d'arrivée.
const ready = chrome.storage.session.get(null).then((all) => {
  for (const [key, rec] of Object.entries(all)) {
    if (key.startsWith('tab:')) tabs.set(Number(key.slice(4)), rec);
  }
});

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
    // Une redirection garde le même requestId : même navigation, on ne repart pas de zéro.
    const prev = tabs.get(d.tabId);
    if (!prev || prev.requestId !== d.requestId) {
      tabs.set(d.tabId, {
        requestId: d.requestId, url: d.url, at: Date.now(),
        redirects: [], main: null, requests: 0, hosts: {}, insecure: [], truncated: false,
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
    if (Object.keys(rec.hosts).length >= MAX_HOSTS) {
      rec.truncated = true;
      touch(d.tabId);
      return;
    }
    host = rec.hosts[u.hostname] = { n: 0, types: {} };
  }
  host.n++;
  host.types[d.type] = (host.types[d.type] || 0) + 1;

  const insecure = u.protocol === 'http:' || u.protocol === 'ws:';
  if (insecure && rec.url.startsWith('https:') && rec.insecure.length < MAX_INSECURE) {
    rec.insecure.push({ url: d.url.slice(0, 300), type: d.type });
  }
  touch(d.tabId);
}

function onMainHeaders(d) {
  const rec = tabs.get(d.tabId);
  if (!rec || rec.requestId !== d.requestId) return;
  rec.main = {
    status: d.statusCode,
    headers: (d.responseHeaders || []).map(({ name, value }) => ({ name, value: value ?? '' })),
    ip: null,
  };
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
  touch(d.tabId);
}

// Certificat refusé, DNS introuvable… : Chrome affiche une page d'erreur à laquelle
// rien ne peut s'attacher, l'erreur réseau est la seule trace.
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

chrome.tabs.onRemoved.addListener((tabId) => {
  ready.then(() => {
    tabs.delete(tabId);
    dirty.delete(tabId);
    chrome.storage.session.remove(`tab:${tabId}`).catch(() => {});
  });
});

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg?.type !== 'net') return false;
  ready.then(() => reply(tabs.get(msg.tabId) || null));
  return true;
});
