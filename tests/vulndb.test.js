'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const V = require('../vulndb.js');
const { DB } = require('../vendor/vulndb-data.js');

test('base embarquée non vide et cohérente', () => {
  assert.ok(Object.keys(DB).length > 50);
  assert.ok(DB.jquery && DB.jquery.vulns.length > 0);
});

test('cmp compare des versions non triviales', () => {
  assert.equal(V.cmp('1.12.4', '3.5.0') < 0, true);
  assert.equal(V.cmp('3.5.0', '3.5.0'), 0);
  assert.equal(V.cmp('2.0.0-rc1', '2.0.0') < 0, true); // pré-version < stable
  assert.equal(V.cmp('1.10', '1.9.9') > 0, true);
});

test('jQuery 1.12.4 détecté par variable globale, avec CVE', () => {
  const [hit] = V.scan({ db: DB, globals: { jquery: '1.12.4' } });
  assert.equal(hit.component, 'jquery');
  assert.equal(hit.source, 'globale');
  assert.ok(hit.count >= 1);
  assert.ok(hit.cves.some((c) => /^CVE-/.test(c)));
  assert.ok(['critical', 'high', 'medium', 'low'].includes(hit.sev));
});

test('jQuery à jour : aucun résultat', () => {
  assert.deepEqual(V.scan({ db: DB, globals: { jquery: '3.7.1' } }), []);
});

test('détection par URL de script (extracteur uri retire.js)', () => {
  const hits = V.scan({ db: DB, scripts: ['https://cdn.example/1.12.4/jquery.min.js'] });
  assert.ok(hits.some((h) => h.component === 'jquery' && h.version === '1.12.4' && h.source === 'URL'));
});

test('extractVersion tire la version d’un nom de fichier', () => {
  assert.equal(V.extractVersion(DB.jquery, 'https://x/jquery-2.1.4.min.js'), '2.1.4');
  assert.equal(V.extractVersion(DB.jquery, 'https://x/app.js'), null);
});

test('résultats triés par gravité décroissante', () => {
  const hits = V.scan({ db: DB, globals: { jquery: '1.4.0', bootstrap: '3.0.0' } });
  const order = ['critical', 'high', 'medium', 'low'];
  for (let i = 1; i < hits.length; i++) {
    assert.ok(order.indexOf(hits[i - 1].sev) <= order.indexOf(hits[i].sev));
  }
});
