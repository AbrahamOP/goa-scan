#!/usr/bin/env node
'use strict';
// Construit le zip prêt à téléverser sur le Chrome Web Store : dist/goa-scan-<version>.zip.
// N'embarque QUE ce que l'extension exécute (pas les tests, outils, docs). Vérifie au passage
// les contraintes du store qui, sinon, ne sautent aux yeux qu'après un refus.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'));

// Fichiers et dossiers réellement chargés par l'extension.
const INCLUDE = [
  'manifest.json',
  'background.js', 'popup.js', 'popup.html', 'popup.css',
  'checks.js', 'cert.js', 'collector.js', 'export.js', 'probes.js', 'secrets.js', 'vulndb.js',
  'vendor', 'icons', 'fonts', 'LICENSE',
];

const problems = [];
if (manifest.description.length > 132) problems.push(`description ${manifest.description.length} > 132 caractères`);
if (!/^\d+\.\d+(\.\d+){0,2}$/.test(manifest.version)) problems.push(`version « ${manifest.version} » non conforme`);
for (const size of [16, 32, 48, 128]) {
  if (!fs.existsSync(path.join(root, 'icons', `icon${size}.png`))) problems.push(`icône icons/icon${size}.png manquante`);
}
for (const name of INCLUDE) {
  if (!fs.existsSync(path.join(root, name))) problems.push(`fichier attendu absent : ${name}`);
}
// Le store refuse le code distant : aucune de nos sources ne doit charger un script externe.
for (const f of INCLUDE.filter((n) => n.endsWith('.js'))) {
  const src = fs.readFileSync(path.join(root, f), 'utf8');
  if (/\bimportScripts\s*\(\s*['"`]https?:/.test(src) || /<script[^>]+src=["']https?:/.test(src)) {
    problems.push(`${f} semble charger du code distant`);
  }
}
if (problems.length) {
  console.error('Blocages avant packaging :');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

const dist = path.join(root, 'dist');
fs.mkdirSync(dist, { recursive: true });
const zipPath = path.join(dist, `goa-scan-${manifest.version}.zip`);
fs.rmSync(zipPath, { force: true });
// -r récursif, -X sans métadonnées de fichier (zip reproductible).
execFileSync('zip', ['-r', '-X', '-q', zipPath, ...INCLUDE], { cwd: root });

const kb = (fs.statSync(zipPath).size / 1024).toFixed(0);
console.log(`OK  ${path.relative(root, zipPath)}  (${kb} Ko, version ${manifest.version})`);
console.log('Téléverser tel quel ; visibilité « Non répertorié » ou « Privé » à la soumission.');
