'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../secrets.js');
const C = require('../checks.js');

// Jetons factices assemblés à l'exécution : aucun motif complet dans le dépôt
// (la protection des pushs GitHub les bloquerait, à raison).
const AWS = 'AK' + 'IA' + 'Q3EGRTZ7LWBN4XKD';
const GH = 'gh' + 'p_' + 'a1B2c3D4e5'.repeat(3) + 'f6G7h8';
const SK = 'sk_' + 'live_' + 'Z9y8X7w6'.repeat(3);
const PK = 'pk_' + 'live_' + 'A1b2C3d4'.repeat(3);
const GKEY = 'AI' + 'za' + 'SyD4x9Kq2LmN7pQr5StU8vWx0YzA1bC3dEf';
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.${'s1gNaTuRe'.repeat(3)}`;

const ids = (hits) => hits.map((h) => h.id);

test('formats connus reconnus, valeurs masquées, ligne calculée', () => {
  const text = `const a = 1;\nconst aws = "${AWS}";\nfetch(u, { headers: { Authorization: "token ${GH}" } });\nStripe("${SK}");`;
  const hits = S.scan(text, 'app.js');
  assert.deepEqual(ids(hits).sort(), ['aws-access-key', 'github-token', 'stripe-secret']);
  const aws = hits.find((h) => h.id === 'aws-access-key');
  assert.equal(aws.line, 2);
  assert.equal(aws.sev, 'high');
  assert.equal(JSON.stringify(hits).includes(AWS), false);
  assert.equal(JSON.stringify(hits).includes(SK), false);
  assert.equal(aws.value, 'AKIAQ…XKD');
});

test('clés publiques marquées comme telles', () => {
  const hits = S.scan(`Stripe("${PK}"); initMap({ key: "${GKEY}" });`, 'inline');
  assert.deepEqual(hits.map((h) => [h.id, h.public]).sort(), [['google-api-key', true], ['stripe-public', true]]);
});

test('JWT : service_role critique, anon publique, JSON invalide ignoré', () => {
  const hits = S.scan(`a="${jwt({ role: 'service_role', iss: 'supabase' })}"; b="${jwt({ role: 'anon' })}"; c="${jwt({ sub: '42' })}"; d="eyJhbGciOiJub25lIn0.eyJub3QtanNvbg.c2lnbmF0dXJlMTIz"`, 'x');
  const by = Object.fromEntries(hits.map((h) => [h.id, h]));
  assert.equal(by['supabase-service-role'].sev, 'critical');
  assert.equal(by['supabase-anon'].public, true);
  assert.equal(by.jwt.sev, 'info');
  assert.equal(hits.length, 3);
});

test('affectations génériques : secret plausible signalé, libellés et gabarits ignorés', () => {
  const hits = S.scan('x={password:"Password",apiKey:"your_api_key_here_123456",label:"client_secret"};z={apiKey:"df2b9f8c-760a-445f-810e-4b47a4fe41a7"};y={client_secret:"k3Jd9sL2mQ8xZ7vB"}', 'x');
  assert.deepEqual(hits.map((h) => h.name), ['Secret potentiel (client_secret)']);
  assert.equal(hits[0].sev, 'info');
});

test('identifiants dans une URL : mot de passe masqué, gabarit ignoré', () => {
  const hits = S.scan('db="postgres://admin:S3cr3tPw@db.interne:5432/app"; doc="https://user:password@example.com"', 'x');
  assert.equal(hits.length, 1);
  assert.equal(hits[0].value, 'postgres://admin:••••@db.interne');
});

test('clé privée : seul l’en-tête est rapporté', () => {
  const hits = S.scan('const k = `-----BEGIN RSA PRIVATE KEY-----\nMIIEow...`;', 'x');
  assert.equal(hits[0].id, 'private-key');
  assert.equal(hits[0].value, '-----BEGIN RSA PRIVATE KEY-----');
});

test('endpoints : chemins, URL, gabarits ; fichiers statiques et espaces de noms écartés', () => {
  const text = 'a="/api/users/42";\nb=`/api/items/${id}/share`;\nc="https://api.exemple.fr/v1/x?y=1";\nd="/static/logo.png";\ne="http://www.w3.org/2000/svg";\nf="api/v2/orders";\ng="//cdn.exemple.fr/data";\nh="/";\ni="a/b";';
  const eps = S.endpoints(text);
  assert.deepEqual(eps.map((e) => e.path), ['/api/users/42', '/api/items/:param/share', 'https://api.exemple.fr/v1/x?y=1', 'api/v2/orders', 'https://cdn.exemple.fr/data']);
  assert.deepEqual(eps.map((e) => e.line), [1, 2, 3, 6, 7]);
});

test('params : query strings, searchParams, FormData et objets ; bruit écarté', () => {
  const text = [
    'const u = "/api/search?q=chat&page=2&sort_by=date";',
    'url.searchParams.get("token"); formData.append("file_id", f);',
    'fetch(x, { params: { user_id: 1, "org-slug": s } });',
    'const data = { internalStuff: "une longue phrase avec des espaces" };',
    'map.get("notAParam because too long and spaces");',
  ].join('\n');
  const p = S.params(text).sort();
  // data/body ne sont pas des sources : ils portent trop d'objets internes (mesuré en réel).
  assert.deepEqual(p, ['file_id', 'org-slug', 'page', 'q', 'sort_by', 'token', 'user_id']);
});

test('params : & hors chaîne-URL ignoré, doublons dédupliqués', () => {
  assert.deepEqual(S.params('const a = 1 & 2; const b = 3 && 4;'), []);
  assert.deepEqual(S.params('x="/a?id=1"; y="/b?id=2&id=3";'), ['id']);
});

test('analyse : un constat par type de secret, publiques et « à vérifier » à part', () => {
  const hits = [
    ...S.scan(`"${AWS}" "${SK}" "${PK}"`, 'app.js'),
    ...S.scan('{client_secret:"k3Jd9sL2mQ8xZ7vB"}', 'script inline n°1'),
  ];
  const r = C.analyze({ url: 'https://exemple.fr/', headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, jsSecrets: { scanned: { inline: 1, external: 1, bytes: 10 }, hits } });
  const f = (id) => r.findings.find((x) => x.id === id);
  assert.equal(f('js-stripe-secret').sev, 'critical');
  assert.equal(f('js-aws-access-key').sev, 'high');
  assert.match(f('js-aws-access-key').items[0], /— app\.js$/);
  assert.equal(f('js-public-keys').sev, 'info');
  assert.equal(f('js-to-check').sev, 'info');
  assert.equal(f('js-secrets'), undefined);

  const clean = C.analyze({ url: 'https://exemple.fr/', headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, jsSecrets: { scanned: { inline: 2, external: 3, bytes: 10 }, hits: [] } });
  assert.equal(clean.findings.find((x) => x.id === 'js-secrets').ok, true);
});
