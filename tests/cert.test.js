'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const { parseCertificate, fingerprint } = require('../cert.js');
const C = require('../checks.js');

// Fixtures : certificats générés par openssl + chaîne réelle de github.com (2026-09).
const der = (name) => fs.readFileSync(path.join(__dirname, 'fixtures', `${name}.b64`), 'utf8').trim();
const DAY = 86400000;

test('RSA 2048 auto-signé avec SAN DNS et IP', () => {
  const c = parseCertificate(der('rsa'));
  assert.equal(c.subject.cn, 'exemple.fr');
  assert.equal(c.subject.o, 'Goa Test');
  assert.deepEqual(c.key, { type: 'RSA', bits: 2048 });
  assert.equal(c.sigAlg, 'sha256WithRSA');
  assert.deepEqual(c.san, ['exemple.fr', 'www.exemple.fr', '203.0.113.13']);
  assert.equal(c.selfSigned, true);
  assert.equal(Math.round((c.notAfter - c.notBefore) / DAY), 90);
});

test('ECDSA P-256 wildcard', () => {
  const c = parseCertificate(der('ec'));
  assert.deepEqual(c.key, { type: 'EC', curve: 'P-256', bits: 256 });
  assert.equal(c.sigAlg, 'ecdsaWithSHA256');
  assert.ok(c.san.includes('*.example.com'));
});

test('RSA 1024 signé en SHA-1', () => {
  const c = parseCertificate(der('weak'));
  assert.deepEqual(c.key, { type: 'RSA', bits: 1024 });
  assert.equal(c.sigAlg, 'sha1WithRSA');
});

test('chaîne réelle github.com : feuille DV avec SCT, intermédiaire CA', () => {
  const leaf = parseCertificate(der('github-gh1'));
  assert.equal(leaf.subject.cn, 'github.com');
  assert.match(leaf.issuer.o, /Sectigo/);
  assert.equal(leaf.validation, 'DV');
  assert.equal(leaf.sct, true);
  assert.equal(leaf.isCA, false);
  assert.equal(parseCertificate(der('github-gh2')).isCA, true);
});

test('empreinte SHA-256 identique à celle de Node', async () => {
  const b64 = der('ec');
  const expected = createHash('sha256').update(Buffer.from(b64, 'base64')).digest('hex').match(/../g).join(':').toUpperCase();
  assert.equal(await fingerprint(b64), expected);
});

test('hostMatches : un joker couvre une seule étiquette', () => {
  const names = ['*.example.com'];
  assert.equal(C.hostMatches('doc.example.com', names), true);
  assert.equal(C.hostMatches('a.b.example.com', names), false);
  assert.equal(C.hostMatches('example.com', names), false);
  assert.equal(C.hostMatches('203.0.113.13', ['203.0.113.13']), true);
});

const tlsOf = (...names) => ({ status: 'ok', protocol: 'TLS 1.3', chain: names.map((n) => parseCertificate(der(n))) });
const run = (url, tls, now) => C.analyze({ url, headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, tls, now });
const failing = (r) => r.findings.filter((f) => !f.ok && f.cat === 'certificate').map((f) => `${f.sev}:${f.id}`);

test('chaîne github.com valide : aucun constat sur le certificat', () => {
  const r = run('https://github.com/', tlsOf('github-gh1', 'github-gh2', 'github-gh3'), Date.UTC(2026, 9, 1));
  assert.deepEqual(failing(r), []);
});

test('certificat expiré et nom non couvert : critiques', () => {
  const leaf = parseCertificate(der('github-gh1'));
  const r = run('https://gist.github.com/', tlsOf('github-gh1'), leaf.notAfter + DAY);
  assert.ok(failing(r).includes('critical:cert-expiry'));
  assert.ok(failing(r).includes('critical:cert-name'));
});

test('expiration proche : haute sous 14 jours, faible sous 30', () => {
  const { notAfter } = parseCertificate(der('github-gh1'));
  assert.ok(failing(run('https://github.com/', tlsOf('github-gh1'), notAfter - 5 * DAY)).includes('high:cert-expiry'));
  assert.ok(failing(run('https://github.com/', tlsOf('github-gh1'), notAfter - 20 * DAY)).includes('low:cert-expiry'));
});

test('auto-signé, clé courte, SHA-1 : tous signalés', () => {
  const c = parseCertificate(der('weak'));
  const r = run('https://faible.test/', tlsOf('weak'), c.notBefore + DAY);
  const f = failing(r);
  for (const id of ['high:cert-self', 'high:cert-sig', 'high:cert-key']) assert.ok(f.includes(id), id);
});

test('wildcard de 825 jours : durée signalée, wildcard en info', () => {
  const c = parseCertificate(der('ec'));
  const f = failing(run('https://doc.example.com/', tlsOf('ec'), c.notBefore + DAY));
  assert.ok(f.includes('low:cert-lifetime'));
  assert.ok(f.includes('info:cert-wildcard'));
  assert.ok(!f.includes('critical:cert-name'));
});

test('certificat refusé par Chrome : critique, note F, pas de faux « en-têtes indisponibles »', () => {
  const r = C.analyze({
    url: 'https://expired.badssl.com/', headers: null, dom: null, net: null, globals: {}, cookies: [],
    securityTxt: null, tls: { status: 'error', error: 'Cannot attach to this target.' }, navError: 'net::ERR_CERT_DATE_INVALID',
  });
  const f = r.findings.filter((x) => !x.ok).map((x) => x.id);
  assert.ok(f.includes('cert-error'));
  assert.match(r.findings.find((x) => x.id === 'cert-error').detail, /expiré/);
  assert.ok(!f.includes('no-headers') && !f.includes('cert-unavailable'));
  assert.equal(r.grade, 'F');
});

test('erreur réseau sans rapport avec TLS : ignorée', () => {
  const r = C.analyze({ url: 'https://exemple.fr/', headers: null, dom: null, net: null, globals: {}, cookies: [], navError: 'net::ERR_ABORTED' });
  assert.equal(r.findings.find((x) => x.id === 'cert-error'), undefined);
});

test('TLS 1.0, échange RSA, CBC et CT non conforme', () => {
  const tls = { ...tlsOf('github-gh1'), protocol: 'TLS 1', keyExchange: 'RSA', cipher: 'AES_128_CBC', ct: 'not-compliant' };
  const f = failing(run('https://github.com/', tls, Date.UTC(2026, 9, 1)));
  assert.ok(f.includes('high:tls-protocol'));
  assert.ok(f.includes('medium:tls-cipher'));
  assert.ok(f.includes('medium:tls-ct'));
});

test('TLS 1.3 AES-GCM : protocole et chiffrement conformes', () => {
  const tls = { ...tlsOf('github-gh1'), keyExchange: '', group: 'X25519MLKEM768', cipher: 'AES_128_GCM', ct: 'compliant' };
  const f = failing(run('https://github.com/', tls, Date.UTC(2026, 9, 1)));
  assert.deepEqual(f, []);
});
