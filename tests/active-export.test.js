'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const C = require('../checks.js');
const E = require('../export.js');

const input = (over = {}) => ({ url: 'https://exemple.fr/', headers: {}, dom: null, net: null, globals: {}, cookies: [], securityTxt: null, ...over });
const find = (r, id) => r.findings.find((f) => f.id === id);

test('mode actif : fichier exposé → constat critique, DNS manquant → faibles', () => {
  const r = C.analyze(input({
    probes: {
      files: [{ path: '/.git/HEAD', sev: 'critical', title: 'Dépôt Git exposé', evidence: 'ref: …', status: 200 }],
      dns: { domain: 'exemple.fr', dnssec: false, caa: false, spf: 'v=spf1 -all', dmarc: null },
    },
  }));
  assert.equal(find(r, 'file-/.git/HEAD').sev, 'critical');
  assert.match(find(r, 'file-/.git/HEAD').items[0], /ref/);
  assert.equal(find(r, 'dns-spf').ok, true);
  assert.equal(find(r, 'dns-dmarc').sev, 'low');
  assert.equal(find(r, 'dns-caa').sev, 'low');
  assert.equal(find(r, 'dns-dnssec').sev, 'low');
});

test('sans mode actif : aucune catégorie « active »', () => {
  const r = C.analyze(input({}));
  assert.equal(r.findings.some((f) => f.cat === 'active'), false);
});

const REPORT = {
  raw: {
    url: 'https://exemple.fr/login', scannedAt: '2026-09-10T10:00:00.000Z', version: '0.2.0',
    status: 200, ip: '203.0.113.4',
    cookies: [{ name: 'sid', secure: true, httpOnly: false, sameSite: 'lax' }],
  },
  report: {
    grade: 'D', score: 55, counts: { critical: 1, high: 0, medium: 1, low: 2 },
    tech: [{ name: 'nginx', version: '1.25', source: 'Server' }],
    findings: [
      { cat: 'certificate', ok: false, sev: 'critical', title: 'Certificat expiré', detail: 'Expiré hier.', fix: 'Renouveler.', items: [] },
      { cat: 'headers', ok: false, sev: 'medium', title: 'CSP absente', detail: 'Pas de CSP.', fix: 'Ajouter une CSP.', items: [] },
      { cat: 'headers', ok: true, sev: 'info', title: 'HSTS actif', items: [] },
    ],
    hosts: [],
  },
};

test('export Markdown : titres, note, sections, correctifs', () => {
  const md = E.buildMarkdown(REPORT);
  assert.match(md, /# Rapport de sécurité — exemple\.fr/);
  assert.match(md, /\*\*Note\*\* : D \(55\/100\)/);
  assert.match(md, /## Certificat & TLS/);
  assert.match(md, /### \[Critique\] Certificat expiré/);
  assert.match(md, /\*\*Correctif :\*\* Renouveler\./);
  assert.match(md, /## Points conformes/);
  assert.match(md, /\| sid \| oui \| non \| lax \|/);
});

test('export HTML imprimable : document complet, gravité en attribut', () => {
  const html = E.buildPrintableHtml(REPORT);
  assert.match(html, /^<!doctype html>/);
  assert.match(html, /data-sev="Critique"/);
  assert.match(html, /<script>print\(\)<\/script>/);
  assert.ok(!html.includes('<h3>[')); // le préfixe [gravité] a bien été transformé
});

test('mdToHtml échappe le HTML injecté', () => {
  const html = E.mdToHtml('- <script>alert(1)</script>');
  assert.ok(!html.includes('<script>alert'));
  assert.match(html, /&lt;script&gt;/);
});
