'use strict';
/* global GoaChecks, collectPage, collectGlobals */
// Goa Scan — popup et rapport complet (même page, ouverte avec ?tab=<id>).
// Tout ce qui vient de la page analysée est inséré en textContent, jamais en HTML.

const SEV_LABEL = { critical: 'Critique', high: 'Haute', medium: 'Moyenne', low: 'Faible', info: 'Info' };
const TABS = [
  { id: 'summary', label: 'Synthèse' },
  { id: 'headers', label: 'En-têtes', cats: ['transport', 'headers', 'exposure'] },
  { id: 'cookies', label: 'Cookies', cats: ['cookies'] },
  { id: 'content', label: 'Contenu', cats: ['content'] },
  { id: 'network', label: 'Réseau', cats: ['network'] },
];
const SAMESITE = { no_restriction: 'None', lax: 'Lax', strict: 'Strict', unspecified: 'Non défini' };

const params = new URLSearchParams(location.search);
const fullPage = params.has('tab');
const state = { tab: null, raw: null, report: null, active: 'summary', busy: false };
const $ = (id) => document.getElementById(id);

function el(tag, props, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') n.className = v;
    else if (k === 'text') n.textContent = v;
    else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids.flat()) if (c != null && c !== false) n.append(c instanceof Node ? c : String(c));
  return n;
}

// ── Collecte ────────────────────────────────────────────────

const stripHash = (u) => String(u).split('#')[0];

async function runInTab(tabId, func, world) {
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId }, func, world });
    return res?.result ?? null;
  } catch {
    return null; // page protégée (Chrome Web Store, PDF, chrome://…)
  }
}

async function fetchSecurityTxt(url) {
  try {
    const r = await fetch(new URL('/.well-known/security.txt', url), { credentials: 'omit', cache: 'no-store' });
    if (!r.ok) return false;
    return /^\s*contact\s*:/im.test((await r.text()).slice(0, 20000));
  } catch {
    return null;
  }
}

// Secours quand la page a été chargée avant l'extension : on redemande le document, sans cookies.
async function refetchHeaders(url) {
  try {
    const r = await fetch(url, { credentials: 'omit', cache: 'no-store' });
    r.body?.cancel();
    return { headers: [...r.headers].map(([name, value]) => ({ name, value })), status: r.status };
  } catch {
    return null;
  }
}

function headerMap(list) {
  const map = {};
  for (const { name, value } of list) {
    const k = name.toLowerCase();
    map[k] = k in map ? `${map[k]}, ${value}` : value;
  }
  return map;
}

async function gather(tab) {
  const url = tab.url;
  const [net, dom, globals, cookies, securityTxt] = await Promise.all([
    chrome.runtime.sendMessage({ type: 'net', tabId: tab.id }).catch(() => null),
    runInTab(tab.id, collectPage, 'ISOLATED'),
    runInTab(tab.id, collectGlobals, 'MAIN'),
    chrome.cookies.getAll({ url }).catch(() => []),
    fetchSecurityTxt(url),
  ]);

  // La capture n'est valable que si elle concerne le document affiché (pas une page
  // restaurée depuis le cache, ni une navigation interrompue).
  const docUrl = stripHash(dom?.docUrl || url);
  const captured = net?.main && stripHash(net.url) === docUrl ? net : null;

  let rawHeaders = captured ? captured.main.headers : null;
  let status = captured ? captured.main.status : null;
  let headerSource = rawHeaders ? 'capture' : null;
  if (!rawHeaders) {
    const r = await refetchHeaders(url);
    if (r) ({ headers: rawHeaders, status } = r, headerSource = 'refetch');
  }

  return {
    url,
    scannedAt: new Date().toISOString(),
    headers: rawHeaders ? headerMap(rawHeaders) : null,
    rawHeaders: rawHeaders || [],
    headerSource,
    status,
    ip: captured?.main.ip || null,
    net: captured,
    dom,
    globals,
    securityTxt,
    // Les valeurs des cookies ne sont jamais conservées.
    cookies: cookies.map((c) => ({
      name: c.name, domain: c.domain, path: c.path, secure: c.secure, httpOnly: c.httpOnly,
      sameSite: c.sameSite, expires: c.session ? null : new Date(c.expirationDate * 1000).toISOString(),
    })),
  };
}

// ── Actions ─────────────────────────────────────────────────

function setBusy(busy) {
  state.busy = busy;
  $('rescan').disabled = busy;
  $('reload').disabled = busy;
  $('full').disabled = busy;
  $('export').disabled = busy || !state.report;
}

function showMessage(text) {
  $('panel').replaceChildren(el('p', { class: 'status', text }));
}

async function scan() {
  setBusy(true);
  showMessage('Analyse en cours…');
  try {
    state.raw = await gather(state.tab);
    state.report = GoaChecks.analyze(state.raw);
    render();
  } catch (e) {
    state.report = null;
    showMessage(`Analyse impossible : ${e.message}`);
  } finally {
    setBusy(false);
  }
}

function waitComplete(tabId) {
  return new Promise((resolve) => {
    let loading = false;
    const finish = () => {
      chrome.tabs.onUpdated.removeListener(onUpdated);
      clearTimeout(timer);
      setTimeout(resolve, 600); // laisse arriver les dernières requêtes
    };
    const onUpdated = (id, info) => {
      if (id !== tabId) return;
      if (info.status === 'loading') loading = true;
      else if (info.status === 'complete' && loading) finish();
    };
    const timer = setTimeout(finish, 20000);
    chrome.tabs.onUpdated.addListener(onUpdated);
  });
}

async function reloadAndScan() {
  const id = state.tab.id;
  setBusy(true);
  showMessage('Rechargement de la page…');
  const done = waitComplete(id);
  try {
    await chrome.tabs.reload(id, { bypassCache: true });
    await done;
    state.tab = await chrome.tabs.get(id);
  } catch {
    showMessage('L’onglet analysé n’est plus disponible.');
    setBusy(false);
    return;
  }
  await scan();
}

function openFull() {
  chrome.tabs.create({ url: chrome.runtime.getURL(`popup.html?tab=${state.tab.id}`) });
}

function exportJson() {
  const { raw, report } = state;
  const data = {
    tool: 'Goa Scan', version: chrome.runtime.getManifest().version, scannedAt: raw.scannedAt,
    url: raw.url, score: report.score, grade: report.grade, counts: report.counts,
    findings: report.findings, tech: report.tech, hosts: report.hosts,
    status: raw.status, ip: raw.ip, headerSource: raw.headerSource, headers: raw.rawHeaders, cookies: raw.cookies,
  };
  const href = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a = el('a', { href, download: `goa-scan-${new URL(raw.url).hostname}-${raw.scannedAt.slice(0, 10)}.json` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
}

// ── Rendu ───────────────────────────────────────────────────

function renderTarget(url) {
  const t = $('target');
  t.title = url;
  try {
    const u = new URL(url);
    t.replaceChildren(`${u.protocol}//`, el('span', { class: 'host', text: u.host }), u.pathname + u.search);
    if (fullPage) document.title = `Goa Scan — ${u.host}`;
  } catch {
    t.textContent = url;
  }
}

function render() {
  const { report } = state;
  const g = $('grade');
  g.textContent = report.grade;
  g.className = `grade ${'AB'.includes(report.grade) ? 'g-good' : 'CD'.includes(report.grade) ? 'g-mid' : 'g-bad'}`;
  g.setAttribute('aria-label', `Note ${report.grade}`);
  $('score').textContent = report.score;

  const counts = ['critical', 'high', 'medium', 'low']
    .filter((s) => report.counts[s])
    .map((s) => el('span', {}, el('b', { class: `c-${s}`, text: report.counts[s] }), ` ${SEV_LABEL[s].toLowerCase()}`));
  $('counts').replaceChildren(...(counts.length ? counts : ['Aucun problème détecté']));
  $('scorecard').hidden = false;

  renderTabs();
  renderPanel();
}

function renderTabs() {
  const nav = $('tabs');
  nav.hidden = false;
  nav.replaceChildren(...TABS.map((t) => {
    const n = t.cats ? state.report.findings.filter((f) => !f.ok && f.sev !== 'info' && t.cats.includes(f.cat)).length : 0;
    return el('button', {
      type: 'button', role: 'tab', 'aria-selected': String(state.active === t.id),
      onclick: () => { state.active = t.id; renderTabs(); renderPanel(); },
    }, t.label, n ? el('span', { class: 'n', text: n }) : null);
  }));
}

function renderPanel() {
  const panel = $('panel');
  const def = TABS.find((t) => t.id === state.active);
  const extras = { headers: headersExtra, cookies: cookiesExtra, content: contentExtra, network: networkExtra };
  panel.replaceChildren(...(def.id === 'summary' ? summaryPanel() : categoryPanel(def, extras[def.id])));
  panel.scrollTop = 0;
}

function findingNode(f) {
  const tag = f.ok
    ? el('span', { class: 'sev sev-ok', text: 'OK' })
    : el('span', { class: `sev sev-${f.sev}`, text: SEV_LABEL[f.sev] });
  const title = el('span', { class: 'ftitle', text: f.title });
  const body = [];
  if (f.detail) body.push(el('p', { text: f.detail }));
  if (f.items.length) body.push(el('ul', { class: 'items' }, f.items.map((i) => el('li', { text: i }))));
  if (f.fix) body.push(el('p', { class: 'fix' }, el('strong', { text: 'Correctif : ' }), f.fix));
  if (!body.length) return el('div', { class: 'finding plain' }, tag, title);
  return el('details', { class: 'finding' }, el('summary', {}, tag, title), el('div', { class: 'fbody' }, body));
}

const list = (findings) => el('div', { class: 'findings' }, findings.map(findingNode));
const okGroup = (ok) => el('details', { class: 'okgroup' }, el('summary', { text: `${ok.length} point${ok.length > 1 ? 's' : ''} conforme${ok.length > 1 ? 's' : ''}` }), list(ok));
const facts = (pairs) => el('div', { class: 'facts' }, pairs.map(([k, v]) => el('div', { class: 'fact' }, el('div', { class: 'k', text: k }), el('div', { class: 'v', text: String(v), title: String(v) }))));
const yn = (b) => el('span', { class: b ? 'yes' : 'no', text: b ? 'oui' : 'non' });

function table(heads, rows, nowrap = false) {
  return el('div', { class: 'tblwrap' }, el('table', { class: nowrap ? 'tbl nowrap' : 'tbl' },
    el('thead', {}, el('tr', {}, heads.map((h) => el('th', { text: h })))),
    el('tbody', {}, rows.map((r) => el('tr', {}, r.map((c) => el('td', {}, c)))))));
}

function captureNote() {
  const { raw } = state;
  if (raw.net) return null;
  return el('div', { class: 'note' },
    'Cette page a été chargée avant l’ouverture de Goa Scan (ou restaurée depuis le cache) : les requêtes réseau n’ont pas été capturées',
    raw.headerSource === 'refetch' ? ' et les en-têtes viennent d’une requête de secours, sans cookies.' : '.',
    el('br'),
    el('button', { type: 'button', onclick: reloadAndScan, text: 'Recharger et analyser' }));
}

function summaryPanel() {
  const { raw, report } = state;
  const issues = report.findings.filter((f) => !f.ok && f.sev !== 'info');
  const checks = report.findings.filter((f) => !f.ok && f.sev === 'info');
  const ok = report.findings.filter((f) => f.ok);
  const out = [
    facts([
      ['Statut HTTP', raw.status ?? '—'],
      ['Adresse IP', raw.ip || '—'],
      ['Cookies', raw.cookies.length],
      ['Requêtes', raw.net ? raw.net.requests : '—'],
      ['Domaines tiers', raw.net ? report.hosts.filter((h) => h.third).length : '—'],
      ['Scripts externes', raw.dom ? raw.dom.scripts.length : '—'],
    ]),
  ];
  const note = captureNote();
  if (note) out.push(el('div', { style: 'margin-top:10px' }, note));
  if (!raw.dom) out.push(el('div', { class: 'note', text: 'Le contenu de cette page ne peut pas être inspecté (page protégée par Chrome, PDF ou document non HTML) : seuls les en-têtes et les cookies sont analysés.' }));

  out.push(el('h2', { text: 'À corriger' }));
  out.push(issues.length ? list(issues) : el('div', { class: 'empty' }, el('img', { src: 'icons/specter.svg', alt: '' }), 'Rien à corriger sur cette page.'));
  if (checks.length) out.push(el('h2', { text: 'À vérifier' }), list(checks));
  if (ok.length) out.push(okGroup(ok));

  if (report.tech.length) {
    out.push(el('h2', { text: 'Technologies détectées' }), el('div', { class: 'chips' }, report.tech.map((t) =>
      el('span', { class: 'chip', title: `Source : ${t.source}` }, t.name, t.version ? el('span', { class: 'ver', text: t.version }) : null))));
  }

  out.push(el('h2', { text: 'Aller plus loin' }),
    el('div', { class: 'tools' }, toolLinks().map(([label, href]) => el('a', { href, target: '_blank', rel: 'noopener noreferrer', text: label }))),
    el('p', { class: 'hint', text: 'Ces services externes reçoivent le domaine analysé. Une extension ne peut pas lire le certificat TLS : SSL Labs le détaille.' }));
  return out;
}

function toolLinks() {
  const u = new URL(state.raw.url);
  const e = encodeURIComponent;
  const links = [
    ['SSL Labs', `https://www.ssllabs.com/ssltest/analyze.html?d=${e(u.hostname)}&hideResults=on`],
    ['securityheaders.com', `https://securityheaders.com/?q=${e(u.origin)}&hide=on&followRedirects=on`],
    ['Mozilla Observatory', `https://developer.mozilla.org/en-US/observatory/analyze?host=${e(u.hostname)}`],
    ['VirusTotal', `https://www.virustotal.com/gui/domain/${e(u.hostname)}`],
    ['crt.sh', `https://crt.sh/?q=${e(u.hostname)}`],
  ];
  const ip = state.raw.ip;
  if (ip && !/^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1$|f[cd])/i.test(ip)) links.push(['Shodan', `https://www.shodan.io/host/${e(ip)}`]);
  return links;
}

function categoryPanel(def, extra) {
  const fs = state.report.findings.filter((f) => def.cats.includes(f.cat));
  const issues = fs.filter((f) => !f.ok);
  const ok = fs.filter((f) => f.ok);
  const out = [];
  if (issues.length) out.push(list(issues));
  if (ok.length) out.push(issues.length ? okGroup(ok) : list(ok));
  return out.concat(extra());
}

function headersExtra() {
  const { raw } = state;
  const source = {
    capture: 'Capturés au chargement de la page.',
    refetch: 'Reconstitués par une requête de secours sans cookies : rechargez la page pour la réponse exacte.',
  }[raw.headerSource] || 'Indisponibles.';
  const out = [el('h2', { text: `En-têtes de réponse (${raw.rawHeaders.length})` }), el('p', { class: 'hint', text: source })];
  if (raw.rawHeaders.length) {
    const rows = [...raw.rawHeaders].sort((a, b) => a.name.localeCompare(b.name)).map((h) => [h.name.toLowerCase(), h.value]);
    out.push(table(['En-tête', 'Valeur'], rows));
  }
  if (raw.net?.redirects.length) {
    out.push(el('h2', { text: 'Redirections' }), table(['Code', 'De → vers'], raw.net.redirects.map((r) => [r.status, `${r.from} → ${r.to}`])));
  }
  return out;
}

function cookiesExtra() {
  const { cookies } = state.raw;
  if (!cookies.length) return [];
  return [
    el('h2', { text: `Cookies (${cookies.length})` }),
    table(['Nom', 'Domaine', 'Secure', 'HttpOnly', 'SameSite', 'Expiration'], cookies.map((c) => [
      c.name, c.domain, yn(c.secure), yn(c.httpOnly), SAMESITE[c.sameSite] || c.sameSite, c.expires ? c.expires.slice(0, 10) : 'session',
    ]), true),
    el('p', { class: 'hint', text: 'Les valeurs des cookies ne sont ni lues à l’écran ni exportées.' }),
  ];
}

function contentExtra() {
  const { dom } = state.raw;
  if (!dom) return [el('div', { class: 'note', text: 'Contenu non inspectable sur cette page.' })];
  const pageSite = GoaChecks.siteOf(new URL(state.raw.url).hostname);
  const third = (u) => { try { return GoaChecks.siteOf(new URL(u).hostname) !== pageSite; } catch { return false; } };
  const out = [
    el('h2', { text: 'Inventaire' }),
    facts([
      ['Scripts inline', dom.inlineScripts],
      ['Gestionnaires on*', dom.inlineHandlers],
      ['Commentaires HTML', dom.comments.total],
      ['Champs mot de passe', dom.passwordFields],
      ['localStorage', `${dom.storage.local} clés`],
      ['sessionStorage', `${dom.storage.session} clés`],
    ]),
  ];
  if (dom.scripts.length) {
    out.push(el('h2', { text: `Scripts externes (${dom.scripts.length})` }),
      table(['Source', 'Tiers', 'SRI'], dom.scripts.map((s) => [s.src, third(s.src) ? el('span', { class: 'tag', text: 'tiers' }) : '—', yn(s.integrity)])));
  }
  if (dom.forms.length) {
    out.push(el('h2', { text: `Formulaires (${dom.forms.length})` }),
      table(['Méthode', 'Action', 'Mot de passe'], dom.forms.map((f) => [f.method.toUpperCase(), f.action, f.password ? 'oui' : '—'])));
  }
  if (dom.iframes.length) {
    out.push(el('h2', { text: `Iframes (${dom.iframes.length})` }),
      table(['Source', 'Sandbox'], dom.iframes.map((f) => [f.src || '(vide)', yn(f.sandbox)])));
  }
  return out;
}

function networkExtra() {
  const { raw, report } = state;
  if (!raw.net) return [captureNote()];
  const hosts = report.hosts;
  const typeSummary = (types) => Object.entries(types).sort((a, b) => b[1] - a[1]).map(([t, n]) => `${t} ${n}`).join(', ');
  const out = [
    el('h2', { text: 'Requêtes de la page' }),
    facts([
      ['Requêtes', raw.net.requests],
      ['Domaines', hosts.length],
      ['Domaines tiers', hosts.filter((h) => h.third).length],
    ]),
  ];
  if (hosts.length) {
    out.push(el('h2', { text: 'Domaines contactés' }),
      table(['Domaine', 'Req.', 'Types'], hosts.map((h) => [
        el('span', {}, h.host, h.tracker ? el('span', { class: 'tag', text: ' · traqueur' }) : h.third ? el('span', { class: 'tag', text: ' · tiers' }) : null),
        h.n, typeSummary(h.types),
      ])));
  }
  if (raw.net.truncated) out.push(el('p', { class: 'hint', text: 'Liste tronquée à 300 domaines.' }));
  out.push(el('p', { class: 'hint', text: 'Le « site » d’un domaine est estimé sans la Public Suffix List complète : un domaine tiers peut occasionnellement être mal classé.' }));
  return out;
}

// ── Démarrage ───────────────────────────────────────────────

async function main() {
  document.body.classList.toggle('full', fullPage);
  $('full').hidden = fullPage;
  $('rescan').addEventListener('click', scan);
  $('reload').addEventListener('click', reloadAndScan);
  $('full').addEventListener('click', openFull);
  $('export').addEventListener('click', exportJson);

  try {
    state.tab = fullPage
      ? await chrome.tabs.get(Number(params.get('tab')))
      : (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  } catch {
    state.tab = null;
  }

  if (!state.tab || !/^https?:\/\//.test(state.tab.url || '')) {
    renderTarget(state.tab?.url || '');
    showMessage(state.tab
      ? 'Cette page ne peut pas être analysée : Goa Scan fonctionne sur les pages http:// et https://.'
      : 'L’onglet analysé n’existe plus.');
    for (const id of ['rescan', 'reload', 'full', 'export']) $(id).disabled = true;
    return;
  }
  renderTarget(state.tab.url);
  await scan();
}

main();
