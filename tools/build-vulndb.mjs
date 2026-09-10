#!/usr/bin/env node
'use strict';
// Régénère vendor/vulndb-data.js depuis le dépôt public retire.js (licence Apache-2.0).
// Usage : node tools/build-vulndb.mjs
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = 'https://raw.githubusercontent.com/RetireJS/retire.js/master/repository/jsrepository-master.json';
const root = path.dirname(fileURLToPath(import.meta.url));
const outFile = path.join(root, '..', 'vendor', 'vulndb-data.js');

const res = await fetch(SRC);
if (!res.ok) { console.error('téléchargement échoué :', res.status); process.exit(1); }
const raw = await res.json();

const out = {};
let vulnCount = 0;
for (const [name, c] of Object.entries(raw)) {
  if (name === 'retire-example') continue;
  const ex = c.extractors || {};
  const vulns = (c.vulnerabilities || []).map((v) => {
    const r = (v.ranges && v.ranges[0]) || v;
    return {
      below: r.below || null,
      atOrAbove: r.atOrAbove || r.above || null,
      sev: v.severity || 'medium',
      cve: (v.identifiers && v.identifiers.CVE) || [],
      s: (v.identifiers && v.identifiers.summary) || v.summary || '',
    };
  }).filter((v) => v.below);
  vulnCount += vulns.length;
  out[name] = {
    uri: (ex.uri || []).filter(Boolean),
    filename: (ex.filename || []).filter(Boolean),
    filecontent: (ex.filecontent || []).filter(Boolean),
    vulns,
  };
}

const meta = { source: 'RetireJS/retire.js jsrepository-master.json', fetched: new Date().toISOString().slice(0, 10), components: Object.keys(out).length };
const js = `'use strict';
// Base de vulnérabilités JS embarquée, dérivée de retire.js (licence Apache-2.0).
// ${meta.source} — récupérée le ${meta.fetched}, ${meta.components} composants.
// Régénérée par tools/build-vulndb.mjs. Ne pas éditer à la main.
(function (root) {
  var DB = ${JSON.stringify(out)};
  var META = ${JSON.stringify(meta)};
  if (typeof module !== 'undefined' && module.exports) module.exports = { DB: DB, META: META };
  else { root.GOA_RETIRE_DB = DB; root.GOA_RETIRE_META = META; }
})(globalThis);
`;
fs.writeFileSync(outFile, js);
console.log(`écrit ${outFile} : ${meta.components} composants, ${vulnCount} vulnérabilités, ${js.length} octets`);
