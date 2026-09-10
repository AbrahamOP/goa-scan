'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../checks.js');
const P = require('../probes.js');
const E = require('../export.js');

const input = (over = {}) => ({ url: 'https://exemple.fr/', headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, ...over });
const net = (apis) => ({ url: 'https://exemple.fr/', redirects: [], requests: 0, hosts: {}, insecure: [], apis });
const api = (method, url, over = {}) => {
  const e = C.apiEndpoint(method, url);
  return { [e.key]: { method: e.method, url: e.url, ws: false, n: 1, params: e.params, secrets: e.secrets, keys: e.keys, statuses: [200], auth: null, ctype: 'application/json', cors: null, ...over } };
};
const find = (r, id) => r.findings.find((f) => f.id === id);

test('apiEndpoint regroupe les identifiants et ne garde que les noms de paramètres', () => {
  const a = C.apiEndpoint('get', 'https://api.exemple.fr/v1/users/123/orders/550e8400-e29b-41d4-a716-446655440000?page=2&sort=asc');
  const b = C.apiEndpoint('GET', 'https://api.exemple.fr/v1/users/456/orders/6ba7b810-9dad-11d1-80b4-00c04fd430c8?page=3');
  assert.equal(a.url, 'https://api.exemple.fr/v1/users/:id/orders/:uuid');
  assert.equal(a.key, b.key);
  assert.deepEqual(a.params, ['page', 'sort']);
  assert.equal(JSON.stringify(a).includes('asc'), false);
});

test('apiEndpoint repère jetons et clés, pas les valeurs courtes', () => {
  const e = C.apiEndpoint('GET', 'https://exemple.fr/api?access_token=abcdefgh12345&q=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig&key=AIzaSyA-1234567&auth=1');
  assert.deepEqual(e.secrets, ['access_token', 'q']);
  assert.deepEqual(e.keys, ['key']);
  assert.equal(JSON.stringify(e).includes('abcdefgh'), false);
});

test('jeton dans l’URL → moyenne ; clé d’API → info ; Basic → faible ; 5xx → info', () => {
  const r = C.analyze(input({
    net: net({
      ...api('GET', 'https://exemple.fr/api/me?token=abcdefgh12345'),
      ...api('GET', 'https://maps.googleapis.com/maps/api/js?key=AIzaSyA-1234567'),
      ...api('POST', 'https://exemple.fr/api/login', { auth: 'Basic' }),
      ...api('GET', 'https://exemple.fr/api/fail', { statuses: [500] }),
    }),
  }));
  assert.equal(find(r, 'api-url-secrets').sev, 'medium');
  assert.match(find(r, 'api-url-secrets').items[0], /GET https:\/\/exemple\.fr\/api\/me \?token/);
  assert.equal(find(r, 'api-url-keys').sev, 'info');
  assert.equal(find(r, 'api-basic').sev, 'low');
  assert.match(find(r, 'api-5xx').items[0], /500/);
  // Les API du site passent avant les tierces.
  assert.equal(r.apis.at(-1).host, 'maps.googleapis.com');
  assert.equal(r.apis.at(-1).third, true);
});

test('appels propres : constat conforme, aucun appel : rien', () => {
  const ok = C.analyze(input({ net: net(api('GET', 'https://exemple.fr/api/items')) }));
  assert.equal(find(ok, 'api-url-secrets').ok, true);
  const none = C.analyze(input({ net: net({}) }));
  assert.equal(none.findings.some((f) => f.cat === 'api'), false);
  assert.deepEqual(none.apis, []);
});

test('parseApiDoc : OpenAPI 3 et Swagger 2 avec basePath, rejette le HTML', () => {
  const o = P.parseApiDoc(JSON.stringify({ openapi: '3.0.1', info: { title: 'Boutique' }, paths: { '/items': { get: { summary: 'Liste' }, post: {} }, '/items/{id}': { delete: {} } } }));
  assert.equal(o.kind, 'OpenAPI');
  assert.equal(o.total, 3);
  assert.deepEqual(o.routes[0], { method: 'GET', path: '/items', summary: 'Liste' });
  const s = P.parseApiDoc(JSON.stringify({ swagger: '2.0', basePath: '/v2/', paths: { '/pets': { get: {} } } }));
  assert.equal(s.routes[0].path, '/v2/pets');
  assert.equal(P.parseApiDoc('<!doctype html><html></html>'), null);
  assert.equal(P.parseApiDoc('{"hello":"world"}'), null);
});

test('documentation d’API publique → constat faible + export Markdown', () => {
  const apiDoc = { path: '/openapi.json', kind: 'OpenAPI', version: '3.0.1', title: 'Boutique', total: 1, routes: [{ method: 'GET', path: '/items', summary: 'Liste' }] };
  const r = C.analyze(input({ probes: { files: [], dns: null, apiDoc }, net: net(api('GET', 'https://exemple.fr/api/items')) }));
  assert.equal(find(r, 'api-doc').sev, 'low');
  const md = E.buildMarkdown({ raw: { url: 'https://exemple.fr/', scannedAt: '2026-09-10T10:00:00.000Z', cookies: [], probes: { apiDoc } }, report: r });
  assert.match(md, /## Appels d’API/);
  assert.match(md, /\| GET \| https:\/\/exemple\.fr\/api\/items \| 1 \| 200 \| — \|/);
  assert.match(md, /## Documentation OpenAPI 3\.0\.1 \(\/openapi\.json\)/);
});

test('endpoints du JS recoupés avec les appels vus, chemins sensibles signalés', () => {
  const ep = (u) => { const e = C.apiEndpoint('GET', u); return { url: e.url, params: e.params, source: 'app.js', line: 1 }; };
  const r = C.analyze(input({
    net: net(api('GET', 'https://exemple.fr/api/users/7')),
    jsEndpoints: [ep('https://exemple.fr/api/users/1'), ep('https://exemple.fr/admin/export'), ep('https://tiers.io/admin')],
  }));
  const by = Object.fromEntries(r.jsEndpoints.map((e) => [e.url, e]));
  assert.equal(by['https://exemple.fr/api/users/:id'].called, true);
  assert.equal(by['https://exemple.fr/admin/export'].sensitive, true);
  assert.equal(by['https://exemple.fr/admin/export'].called, false);
  assert.equal(by['https://tiers.io/admin'].third, true);
  // Un chemin sensible d'un autre domaine n'est pas le problème du site analysé.
  assert.deepEqual(find(r, 'js-endpoints-sensitive').items, ['https://exemple.fr/admin/export']);
});
