'use strict';
// Goa Scan — détection de bibliothèques JS vulnérables via la base retire.js embarquée.
// Fonctions pures : la base est fournie en argument, aucune API Chrome, testable sous Node.
(function (root) {
  // §§version§§ dans les extracteurs retire.js = un numéro de version à capturer.
  // Non-greedy : les extracteurs uri/filename ont toujours un suffixe (/jquery…, .min.js…),
  // sinon la version avale le « .min » du nom de fichier.
  const VERSION = '([0-9][0-9.a-z_\\-]+?)';
  const cache = new Map();

  function compile(pattern) {
    if (cache.has(pattern)) return cache.get(pattern);
    let re = null;
    try { re = new RegExp(pattern.replace(/§§version§§/g, VERSION)); } catch { /* motif retire.js non supporté */ }
    cache.set(pattern, re);
    return re;
  }

  // Comparaison de versions tolérante : segments numériques, une pré-version (-beta, rc)
  // est réputée antérieure à la version stable correspondante.
  function cmp(a, b) {
    const split = (v) => String(v).toLowerCase().replace(/[+].*$/, '').split(/[.\-]/);
    const pa = split(a);
    const pb = split(b);
    const len = Math.max(pa.length, pb.length);
    for (let i = 0; i < len; i++) {
      const xa = pa[i];
      const xb = pb[i];
      if (xa === xb) continue;
      if (xa === undefined) return isNaN(pb[i]) ? 1 : -1; // 1.0 > 1.0.0-rc
      if (xb === undefined) return isNaN(pa[i]) ? -1 : 1;
      const na = Number(xa);
      const nb = Number(xb);
      if (!isNaN(na) && !isNaN(nb)) { if (na !== nb) return na < nb ? -1 : 1; continue; }
      if (!isNaN(na)) return 1; // un segment numérique > un segment alphabétique (stable > pré-version)
      if (!isNaN(nb)) return -1;
      return xa < xb ? -1 : 1;
    }
    return 0;
  }

  function vulnsFor(entry, version) {
    return entry.vulns.filter((v) => {
      if (v.atOrAbove && cmp(version, v.atOrAbove) < 0) return false;
      return cmp(version, v.below) < 0;
    });
  }

  function extractVersion(entry, text) {
    for (const key of ['uri', 'filename']) {
      for (const pattern of entry[key] || []) {
        const re = compile(pattern);
        const m = re && re.exec(text);
        if (m && m[1]) return m[1].replace(/[._\-]$/, '');
      }
    }
    return null;
  }

  // globals : { jquery: '1.12.4', ... } → noms de composants retire.js
  const GLOBAL_MAP = {
    jquery: 'jquery', jqueryUI: 'jquery-ui', angularjs: 'angularjs', react: 'react',
    vue: 'vue', bootstrap: 'bootstrap', lodash: 'lodash', moment: 'moment', next: 'next.js',
  };

  const worst = (a, b) => { const o = ['critical', 'high', 'medium', 'low']; return o.indexOf(a) <= o.indexOf(b) ? a : b; };

  // input : { db, scripts:[url…], globals:{} } → [{ component, version, sev, cves:[], summaries:[], source }]
  function scan({ db, scripts = [], globals = {} }) {
    if (!db) return [];
    const hits = new Map(); // clé = composant@version
    const record = (component, version, source) => {
      if (!version || !db[component]) return;
      const vulns = vulnsFor(db[component], version);
      if (!vulns.length) return;
      const key = `${component}@${version}`;
      if (hits.has(key)) { if (source === 'globale') hits.get(key).source = source; return; }
      const cves = [...new Set(vulns.flatMap((v) => v.cve))];
      hits.set(key, {
        component, version, source,
        sev: vulns.map((v) => v.sev).reduce(worst),
        cves,
        summaries: [...new Set(vulns.map((v) => v.s).filter(Boolean))].slice(0, 4),
        count: vulns.length,
      });
    };

    for (const [key, version] of Object.entries(globals)) {
      if (version && GLOBAL_MAP[key]) record(GLOBAL_MAP[key], version, 'globale');
    }
    for (const url of scripts) {
      for (const [name, entry] of Object.entries(db)) {
        const v = extractVersion(entry, url);
        if (v) record(name, v, 'URL');
      }
    }
    const order = ['critical', 'high', 'medium', 'low'];
    return [...hits.values()].sort((a, b) => order.indexOf(a.sev) - order.indexOf(b.sev) || a.component.localeCompare(b.component));
  }

  const api = { scan, cmp, extractVersion };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaVulnDB = api;
})(globalThis);
