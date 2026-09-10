'use strict';
// Goa Scan — export du rapport en Markdown et en page imprimable (→ PDF via le navigateur).
// Fonctions pures : entrée = { raw, report }, sortie = chaîne. Testable sous Node.
(function (root) {
  const SEV = { critical: 'Critique', high: 'Haute', medium: 'Moyenne', low: 'Faible', info: 'Info' };
  const CATS = [
    ['certificate', 'Certificat & TLS'],
    ['transport', 'Transport'],
    ['headers', 'En-têtes de sécurité'],
    ['exposure', 'Exposition'],
    ['cookies', 'Cookies'],
    ['content', 'Contenu de la page'],
    ['active', 'Mode actif (fichiers & DNS)'],
    ['api', 'API'],
    ['jscode', 'Code JavaScript'],
    ['network', 'Réseau'],
  ];
  const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');

  function buildMarkdown({ raw, report }) {
    const L = [];
    const date = new Date(raw.scannedAt);
    L.push(`# Rapport de sécurité — ${new URL(raw.url).hostname}`, '');
    L.push(`> Généré par **Goa Scan ${raw.version || ''}** le ${date.toISOString().slice(0, 16).replace('T', ' ')} UTC.`, '');
    L.push(`- **URL analysée** : ${raw.url}`);
    L.push(`- **Note** : ${report.grade} (${report.score}/100)`);
    if (raw.status != null) L.push(`- **Statut HTTP** : ${raw.status}`);
    if (raw.ip) L.push(`- **Adresse IP** : ${raw.ip}${raw.ipInfo?.load ? ` (page servie par ${raw.ipInfo.load.ip}${raw.ipInfo.load.fromCache ? ', depuis le cache' : ''})` : ''}`);
    const c = report.counts;
    L.push(`- **Constats** : ${c.critical} critique(s), ${c.high} haute(s), ${c.medium} moyenne(s), ${c.low} faible(s)`);
    L.push('');

    if (report.tech?.length) {
      L.push('## Technologies détectées', '');
      L.push('| Composant | Version | Source |', '|---|---|---|');
      for (const t of report.tech) L.push(`| ${esc(t.name)} | ${esc(t.version) || '—'} | ${esc(t.source)} |`);
      L.push('');
    }

    for (const [cat, label] of CATS) {
      const fs = report.findings.filter((f) => f.cat === cat);
      const issues = fs.filter((f) => !f.ok);
      if (!issues.length) continue;
      L.push(`## ${label}`, '');
      for (const f of issues) {
        L.push(`### [${SEV[f.sev]}] ${esc(f.title)}`, '');
        if (f.detail) L.push(esc(f.detail), '');
        if (f.items?.length) { for (const it of f.items) L.push(`- \`${esc(it)}\``); L.push(''); }
        if (f.fix) L.push(`**Correctif :** ${esc(f.fix)}`, '');
      }
    }

    const ok = report.findings.filter((f) => f.ok);
    if (ok.length) {
      L.push('## Points conformes', '');
      for (const f of ok) L.push(`- ${esc(f.title)}`);
      L.push('');
    }

    if (report.apis?.length) {
      L.push('## Appels d’API', '');
      L.push('| Méthode | Endpoint | Appels | Statut | Auth |', '|---|---|---|---|---|');
      for (const a of report.apis) {
        L.push(`| ${a.ws ? 'WS' : a.method} | ${esc(a.url)}${a.params.length ? ` ?${esc(a.params.join('&'))}` : ''} | ${a.n} | ${esc(a.statuses.join(' ') || a.error) || '—'} | ${esc(a.auth) || '—'} |`);
      }
      L.push('', '_Noms de paramètres seulement : les valeurs ne sont pas collectées._', '');
    }
    if (report.jsEndpoints?.length) {
      L.push(`## Endpoints cités dans le JavaScript (${report.jsEndpoints.length})`, '');
      for (const e of report.jsEndpoints) {
        const flags = [e.called && 'appelé', e.sensitive && 'sensible', e.third && 'autre domaine'].filter(Boolean);
        L.push(`- \`${esc(e.url)}\`${flags.length ? ` — ${flags.join(', ')}` : ''}`);
      }
      L.push('');
    }
    if (raw.jsParams?.length) {
      L.push(`## Paramètres cités dans le JavaScript (${raw.jsParams.length})`, '');
      L.push(raw.jsParams.map((p) => `\`${esc(p.name)}\`${p.count > 1 ? ` ×${p.count}` : ''}`).join(', '), '');
    }
    const doc = raw.probes?.apiDoc;
    if (doc) {
      L.push(`## Documentation ${doc.kind} ${doc.version} (${esc(doc.path)})`, '');
      L.push('| Méthode | Route | Description |', '|---|---|---|');
      for (const r of doc.routes) L.push(`| ${r.method} | ${esc(r.path)} | ${esc(r.summary) || '—'} |`);
      L.push('');
    }

    if (raw.cookies?.length) {
      L.push('## Cookies', '');
      L.push('| Nom | Secure | HttpOnly | SameSite |', '|---|---|---|---|');
      for (const k of raw.cookies) L.push(`| ${esc(k.name)} | ${k.secure ? 'oui' : 'non'} | ${k.httpOnly ? 'oui' : 'non'} | ${esc(k.sameSite)} |`);
      L.push('', '_Les valeurs des cookies ne sont pas collectées._', '');
    }

    L.push('---', '', '_Analyse locale, non intrusive (hors mode actif). Ce rapport ne remplace pas un audit complet._');
    return L.join('\n');
  }

  // Rendu Markdown → HTML minimal (titres, listes, gras, code, tableaux, citations).
  function mdToHtml(md) {
    const esch = (s) => s.replace(/[&<>]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[m]));
    const inline = (s) => esch(s)
      .replace(/`([^`]+)`/g, '<code>$1</code>')
      .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    const lines = md.split('\n');
    const out = [];
    let list = false, table = null;
    const closeList = () => { if (list) { out.push('</ul>'); list = false; } };
    const closeTable = () => { if (table) { out.push('</tbody></table>'); table = null; } };
    for (let i = 0; i < lines.length; i++) {
      const ln = lines[i];
      const t = ln.trim();
      if (/^\|(.+)\|$/.test(t)) {
        const cells = t.slice(1, -1).split('|').map((x) => x.trim());
        if (/^[-\s|]+$/.test(t)) continue;
        if (!table) { closeList(); out.push('<table><thead><tr>' + cells.map((c) => `<th>${inline(c)}</th>`).join('') + '</tr></thead><tbody>'); table = true; }
        else out.push('<tr>' + cells.map((c) => `<td>${inline(c)}</td>`).join('') + '</tr>');
        continue;
      }
      closeTable();
      if (/^#{1,3}\s/.test(t)) { closeList(); const lvl = t.match(/^#+/)[0].length; out.push(`<h${lvl}>${inline(t.replace(/^#+\s/, ''))}</h${lvl}>`); }
      else if (/^[-*]\s/.test(t)) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${inline(t.replace(/^[-*]\s/, ''))}</li>`); }
      else if (/^>\s?/.test(t)) { closeList(); out.push(`<blockquote>${inline(t.replace(/^>\s?/, ''))}</blockquote>`); }
      else if (t === '---') { closeList(); out.push('<hr>'); }
      else if (t === '') closeList();
      else { closeList(); out.push(`<p>${inline(t)}</p>`); }
    }
    closeList(); closeTable();
    return out.join('\n');
  }

  const STYLE = `
    :root{--g:#1d9e75;--v:#534ab7;--ink:#1a2420;--mut:#5d7268;--line:#d9e4de}
    *{box-sizing:border-box}
    body{max-width:820px;margin:32px auto;padding:0 24px;font:14px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:var(--ink)}
    h1{font-size:24px;border-bottom:3px solid var(--g);padding-bottom:8px}
    h2{font-size:18px;margin-top:28px;border-bottom:1px solid var(--line);padding-bottom:4px}
    h3{font-size:14px;margin:16px 0 4px}
    h3::before{content:attr(data-sev);font:700 10px/1.6 monospace;text-transform:uppercase;padding:1px 6px;border-radius:3px;margin-right:8px;color:#fff}
    blockquote{color:var(--mut);border-left:3px solid var(--line);margin:0;padding:2px 12px}
    code{background:#f0f4f2;padding:1px 4px;border-radius:3px;font-size:12px;overflow-wrap:anywhere}
    table{border-collapse:collapse;width:100%;margin:8px 0;font-size:13px}
    th,td{border:1px solid var(--line);padding:5px 8px;text-align:left;overflow-wrap:anywhere}
    th{background:#f0f4f2}
    strong{color:var(--v)}
    hr{border:0;border-top:1px solid var(--line);margin:24px 0}
    @media print{body{margin:0}}`;

  function buildPrintableHtml(data) {
    const body = mdToHtml(buildMarkdown(data))
      .replace(/<h3>\[([^\]]+)\]\s*/g, (m, sev) => `<h3 data-sev="${sev}" class="s-${sev.toLowerCase()}">`);
    const sevColors = { critique: '#b4462e', haute: '#c25b32', moyenne: '#534ab7', faible: '#5d7268', info: '#5d7268' };
    const colorCss = Object.entries(sevColors).map(([k, v]) => `.s-${k}::before{background:${v}}`).join('');
    return `<!doctype html><html lang="fr"><head><meta charset="utf-8"><title>Goa Scan — ${new URL(data.raw.url).hostname}</title><style>${STYLE}${colorCss}</style></head><body>${body}<script>print()</script></body></html>`;
  }

  const api = { buildMarkdown, buildPrintableHtml, mdToHtml };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaExport = api;
})(globalThis);
