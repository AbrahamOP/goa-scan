'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../checks.js');

const dom = (over = {}) => ({
  docUrl: 'https://exemple.fr/', scripts: [], inlineScripts: 0, stylesheets: [], iframes: [], forms: [], mixed: [],
  passwordFields: 0, inlineHandlers: 0, metaCsp: [], metaReferrer: null, generator: null,
  comments: { total: 0, flagged: [] }, storage: { local: 0, session: 0, flagged: [] },
  emails: [], serviceWorker: false, hints: {}, ...over,
});
const net = (over = {}) => ({ url: 'https://exemple.fr/', redirects: [], requests: 0, hosts: {}, insecure: [], ...over });
const input = (over = {}) => ({ url: 'https://exemple.fr/', headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, ...over });
const failing = (r) => r.findings.filter((f) => !f.ok).map((f) => f.id);
const find = (r, id) => r.findings.find((f) => f.id === id && !f.ok);

const GOOD_HEADERS = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=()',
  'cross-origin-opener-policy': 'same-origin',
  server: 'nginx',
};

test('siteOf regroupe les sous-domaines', () => {
  assert.equal(C.siteOf('a.b.exemple.fr'), 'exemple.fr');
  assert.equal(C.siteOf('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(C.siteOf('user.github.io'), 'user.github.io');
  assert.equal(C.siteOf('192.168.1.1'), '192.168.1.1');
});

test('cmpVer compare les versions numériquement', () => {
  assert.equal(C.cmpVer('1.12.4', '3.5.0'), -1);
  assert.equal(C.cmpVer('3.10.0', '3.5.0'), 1);
  assert.equal(C.cmpVer('3.5', '3.5.0'), 0);
});

test('page en HTTP : critique et note plafonnée', () => {
  const r = C.analyze(input({ url: 'http://exemple.fr/', headers: GOOD_HEADERS }));
  assert.equal(find(r, 'https').sev, 'critical');
  assert.ok(r.score <= 40);
});

test('site bien configuré : aucun constat, note A', () => {
  const r = C.analyze(input({ headers: GOOD_HEADERS, securityTxt: true, dom: dom(), net: net() }));
  assert.deepEqual(failing(r), []);
  assert.equal(r.grade, 'A');
  assert.equal(r.score, 100);
});

test("CSP : 'unsafe-inline' neutralisé par un nonce", () => {
  const withNonce = C.analyze(input({ headers: { 'content-security-policy': "script-src 'self' 'unsafe-inline' 'nonce-x'" } }));
  assert.equal(find(withNonce, 'csp-inline'), undefined);
  const without = C.analyze(input({ headers: { 'content-security-policy': "script-src 'self' 'unsafe-inline'" } }));
  assert.ok(find(without, 'csp-inline'));
});

test('CSP : avec deux politiques, la plus stricte l’emporte', () => {
  const r = C.analyze(input({ headers: { 'content-security-policy': "script-src 'unsafe-inline' *, script-src 'self'" } }));
  assert.equal(find(r, 'csp-inline'), undefined);
  assert.equal(find(r, 'csp-wide'), undefined);
});

test('CSP en meta : compte pour les scripts mais pas pour frame-ancestors', () => {
  const r = C.analyze(input({ dom: dom({ metaCsp: ["script-src 'self'; frame-ancestors 'none'"] }) }));
  assert.equal(find(r, 'csp'), undefined);
  assert.ok(find(r, 'framing'));
});

test('CSP Report-Only seule : signalée', () => {
  const r = C.analyze(input({ headers: { 'content-security-policy-report-only': "default-src 'self'" } }));
  assert.match(find(r, 'csp').title, /Report-Only/);
});

test('cookie de session sans HttpOnly ni Secure : haute', () => {
  const r = C.analyze(input({ cookies: [{ name: 'PHPSESSID', secure: false, httpOnly: false, sameSite: 'lax' }] }));
  assert.equal(find(r, 'cookie-secure').sev, 'high');
  assert.equal(find(r, 'cookie-httponly').sev, 'high');
});

test('jeton CSRF lisible en JS : pas signalé', () => {
  const r = C.analyze(input({ cookies: [{ name: 'csrftoken', secure: true, httpOnly: false, sameSite: 'strict' }] }));
  assert.equal(find(r, 'cookie-httponly'), undefined);
});

test('bibliothèques vulnérables : constat par composant, CVE en items', () => {
  const r = C.analyze(input({ vulns: [{ component: 'jquery', version: '1.12.4', sev: 'medium', cves: ['CVE-2020-11022'], summaries: ['XSS'], count: 3, source: 'globale' }] }));
  const f = find(r, 'lib-jquery');
  assert.equal(f.sev, 'medium');
  assert.match(f.title, /jquery 1\.12\.4/);
  assert.ok(f.items.includes('CVE-2020-11022'));
  assert.equal(C.analyze(input({ vulns: [] })).findings.find((x) => x.id === 'lib-jquery'), undefined);
});

test('contenu mixte actif : DOM et réseau fusionnés', () => {
  const r = C.analyze(input({
    dom: dom({ mixed: [{ kind: 'script', url: 'http://cdn.x/a.js' }, { kind: 'media', url: 'http://cdn.x/i.png' }] }),
    net: net({ insecure: [{ url: 'ws://live.x/socket', type: 'websocket' }, { url: 'http://cdn.x/a.js', type: 'script' }] }),
  }));
  assert.deepEqual(find(r, 'mixed-active').items.sort(), ['http://cdn.x/a.js', 'ws://live.x/socket']);
  assert.deepEqual(find(r, 'mixed-passive').items, ['http://cdn.x/i.png']);
});

test('formulaire HTTP et jetons dans le Web Storage', () => {
  const r = C.analyze(input({
    dom: dom({
      forms: [{ action: 'http://exemple.fr/login', method: 'post', password: true }],
      storage: { local: 2, session: 0, flagged: [{ area: 'local', key: 'access_token', jwt: true }] },
    }),
  }));
  assert.equal(find(r, 'form-http').sev, 'high');
  assert.equal(find(r, 'storage-tokens').sev, 'medium');
});

test('scripts tiers sans SRI, scripts du même site ignorés', () => {
  const r = C.analyze(input({
    dom: dom({ scripts: [
      { src: 'https://cdn.exemple.fr/app.js', integrity: false },
      { src: 'https://cdnjs.cloudflare.com/lib.js', integrity: false },
    ] }),
  }));
  assert.deepEqual(find(r, 'sri').items, ['https://cdnjs.cloudflare.com/lib.js']);
});

test('traqueurs identifiés dans les domaines contactés', () => {
  const r = C.analyze(input({ net: net({ hosts: { 'www.google-analytics.com': { n: 2, types: { script: 2 } }, 'cdn.exemple.fr': { n: 5, types: {} } } }) }));
  assert.deepEqual(find(r, 'trackers').items, ['www.google-analytics.com']);
  assert.equal(r.hosts.find((h) => h.host === 'cdn.exemple.fr').third, false);
});

test('en-têtes indisponibles : pas de plantage, constat informatif', () => {
  const r = C.analyze(input({ headers: null }));
  assert.ok(find(r, 'no-headers'));
  assert.equal(find(r, 'hsts'), undefined);
});

test('divulgation de version et technologies détectées', () => {
  const r = C.analyze(input({ headers: { server: 'Apache/2.4.29 (Ubuntu)', 'x-powered-by': 'PHP/7.2.24', 'cf-ray': 'abc' } }));
  assert.ok(find(r, 'server-version'));
  assert.ok(find(r, 'stack-headers'));
  const names = r.tech.map((t) => t.name);
  assert.ok(names.includes('Apache') && names.includes('Cloudflare'));
});
