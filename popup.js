'use strict';
/* global GoaChecks, GoaCert, GoaVulnDB, GoaProbes, GoaExport, GoaSecrets, GOA_RETIRE_DB, collectPage, collectGlobals, collectScriptSources */
// Goa Scan — popup et rapport complet (même page, ouverte avec ?tab=<id>).
// Tout ce qui vient de la page analysée est inséré en textContent, jamais en HTML.

const SEV_LABEL = { critical: 'Critique', high: 'Haute', medium: 'Moyenne', low: 'Faible', info: 'Info' };
const TABS = [
  { id: 'summary', label: 'Synthèse' },
  { id: 'cert', label: 'Certificat', cats: ['certificate'] },
  { id: 'headers', label: 'En-têtes', cats: ['transport', 'headers', 'exposure'] },
  { id: 'cookies', label: 'Cookies', cats: ['cookies'] },
  { id: 'content', label: 'Contenu', cats: ['content'] },
  { id: 'active', label: 'Actif', cats: ['active'], optional: true },
  { id: 'api', label: 'API', cats: ['api'] },
  { id: 'network', label: 'Réseau', cats: ['network'] },
];
const SAMESITE = { no_restriction: 'None', lax: 'Lax', strict: 'Strict', unspecified: 'Non défini' };

const params = new URLSearchParams(location.search);
const fullPage = params.has('tab');
const state = { tab: null, raw: null, report: null, active: 'summary', busy: false, settings: { autoScan: true, activeMode: false } };
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
  for (const c of kids.flat(Infinity)) if (c != null && c !== false) n.append(c instanceof Node ? c : String(c));
  return n;
}

// ── Collecte ────────────────────────────────────────────────

const stripHash = (u) => String(u).split('#')[0];

// Une page figée ou un serveur lent ne doivent pas bloquer l'analyse entière.
const TIMEOUT = 6000;
const withTimeout = (p) => Promise.race([p, new Promise((resolve) => setTimeout(() => resolve(null), TIMEOUT))]);

async function runInTab(tabId, func, world) {
  try {
    const [res] = await withTimeout(chrome.scripting.executeScript({ target: { tabId }, func, world })) || [];
    return res?.result ?? null;
  } catch {
    return null; // page protégée (Chrome Web Store, PDF, chrome://…)
  }
}

async function fetchSecurityTxt(url) {
  try {
    const r = await fetch(new URL('/.well-known/security.txt', url), { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(TIMEOUT) });
    if (!r.ok) return false;
    return /^\s*contact\s*:/im.test((await r.text()).slice(0, 20000));
  } catch {
    return null;
  }
}

// IP de l'origine lue sur nos propres requêtes sans cache (security.txt, secours) : celle
// capturée au chargement peut venir du cache ou d'un proxy de préchargement.
function watchIp(url) {
  const { hostname } = new URL(url);
  let ip = null;
  const on = (d) => {
    if (!ip && d.ip && !d.fromCache && d.initiator === location.origin && new URL(d.url).hostname === hostname) ip = d.ip;
  };
  const events = [chrome.webRequest.onResponseStarted, chrome.webRequest.onBeforeRedirect, chrome.webRequest.onCompleted];
  for (const ev of events) ev.addListener(on, { urls: ['<all_urls>'], types: ['xmlhttprequest'] });
  return async () => {
    // L'événement peut arriver juste après la réponse du fetch.
    for (let i = 0; !ip && i < 6; i++) await new Promise((r) => setTimeout(r, 50));
    for (const ev of events) ev.removeListener(on);
    return ip;
  };
}

// Secrets dans le JavaScript : scripts inline + scripts externes relus depuis l'extension,
// sans cookies. Traqueurs ignorés ; dans les scripts tiers, seuls les formats de secrets
// connus comptent (clés publiques, JWT et « secrets potentiels » y sont du bruit).
const JS_MAX_SCRIPTS = 80;
const JS_MAX_BYTES = 3e6;
const JS_MAX_TOTAL = 25e6;

function shortSrc(u) {
  try {
    const x = new URL(u);
    const p = x.pathname.split('/').filter(Boolean);
    return `${x.host}/${p.length > 2 ? '…/' : ''}${p.slice(-2).join('/')}`;
  } catch {
    return String(u).slice(0, 60);
  }
}

async function scanJsSecrets(sources, pageUrl) {
  if (!sources) return null;
  const pageSite = GoaChecks.siteOf(new URL(pageUrl).hostname);
  const hits = [];
  const push = (list, third) => { for (const h of list) if (!(third && (h.public || h.sev === 'info'))) hits.push({ ...h, third }); };
  for (const s of sources.inline) push(GoaSecrets.scan(s.text, `script inline n°${s.n}`), false);

  // Scripts du site d'abord : ce sont eux qui portent les secrets de l'application.
  const isThird = (u) => GoaChecks.siteOf(new URL(u).hostname) !== pageSite;
  const urls = sources.urls.filter((u) => !GoaChecks.isTracker(new URL(u).hostname)).sort((a, b) => isThird(a) - isThird(b));
  const todo = urls.slice(0, JS_MAX_SCRIPTS);
  let bytes = sources.inline.reduce((n, s) => n + s.text.length, 0);
  let external = 0;
  const worker = async () => {
    while (todo.length && bytes < JS_MAX_TOTAL) {
      const u = todo.shift();
      try {
        const r = await fetch(u, { credentials: 'omit', cache: 'force-cache', signal: AbortSignal.timeout(TIMEOUT) });
        if (!r.ok) continue;
        const text = (await r.text()).slice(0, JS_MAX_BYTES);
        bytes += text.length;
        external++;
        push(GoaSecrets.scan(text, shortSrc(u)), isThird(u));
      } catch { /* script injoignable : ignoré */ }
    }
  };
  await Promise.all(Array.from({ length: 6 }, worker));

  // Même clé vue dans plusieurs scripts : une seule ligne.
  const seen = new Set();
  const unique = hits.filter((h) => !seen.has(h.id + h.value) && seen.add(h.id + h.value));
  return {
    scanned: { inline: sources.inline.length, external, bytes, trackers: sources.urls.length - urls.length, skipped: Math.max(0, urls.length - JS_MAX_SCRIPTS) },
    hits: unique.slice(0, 100),
  };
}

// Secours quand la page a été chargée avant l'extension : on redemande le document, sans cookies.
async function refetchHeaders(url) {
  try {
    const r = await fetch(url, { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(TIMEOUT) });
    r.body?.cancel();
    return { headers: [...r.headers].map(([name, value]) => ({ name, value })), status: r.status };
  } catch {
    return null;
  }
}

// Certificat : Chrome ne l'expose aux extensions que via le protocole DevTools, et
// seulement par le domaine Network (Security leur est fermé). Permission optionnelle,
// attachement de quelques centaines de ms, puis détachement.

// Paramètres TLS : une requête sonde HEAD vers la même origine, sans cookies, dont on
// ne garde que securityDetails. Si la CSP de la page la bloque, on garde la chaîne seule.
function probeSecurityDetails(target, origin) {
  return new Promise((resolve) => {
    const done = (v) => { clearTimeout(timer); chrome.debugger.onEvent.removeListener(onEvent); resolve(v); };
    const onEvent = (src, method, p) => {
      if (src.tabId === target.tabId && method === 'Network.responseReceived' && p.response?.securityDetails && p.response.url.startsWith(origin)) {
        done(p.response.securityDetails);
      }
    };
    const timer = setTimeout(() => done(null), 3000);
    chrome.debugger.onEvent.addListener(onEvent);
    const expression = `fetch(${JSON.stringify(origin + '/')}, { method: 'HEAD', cache: 'no-store', credentials: 'omit' }).catch(() => {})`;
    chrome.debugger.sendCommand(target, 'Runtime.evaluate', { expression, silent: true }).catch(() => done(null));
  });
}

async function scanTls(tab) {
  if (!tab.url.startsWith('https:')) return null;
  if (!(await chrome.permissions.contains({ permissions: ['debugger'] }))) return { status: 'no-permission' };
  const target = { tabId: tab.id };
  const origin = new URL(tab.url).origin;
  try {
    await chrome.debugger.attach(target, '1.3');
  } catch (e) {
    return { status: 'error', error: `Attachement impossible : ${e.message}` };
  }
  try {
    await chrome.debugger.sendCommand(target, 'Network.enable');
    const d = await probeSecurityDetails(target, origin);
    const r = await chrome.debugger.sendCommand(target, 'Network.getCertificate', { origin }).catch(() => null);
    const ders = r?.tableNames || [];
    if (!d && !ders.length) return { status: 'error', error: 'Chrome n’a renvoyé ni certificat ni paramètres TLS pour cette origine.' };
    const chain = [];
    for (const der of ders.slice(0, 6)) {
      try { chain.push({ ...GoaCert.parseCertificate(der), sha256: await GoaCert.fingerprint(der) }); } catch { /* certificat illisible : ignoré */ }
    }
    return {
      status: 'ok', chain,
      protocol: d?.protocol || '', keyExchange: d?.keyExchange || '', group: d?.keyExchangeGroup || '',
      cipher: d?.cipher || '', mac: d?.mac || '', ct: d?.certificateTransparencyCompliance || '',
      ech: !!d?.encryptedClientHello,
    };
  } catch (e) {
    return { status: 'error', error: e.message };
  } finally {
    chrome.debugger.detach(target).catch(() => {});
  }
}

async function enableCertScan() {
  // Doit rester dans le gestionnaire de clic : la demande exige un geste utilisateur.
  const granted = await chrome.permissions.request({ permissions: ['debugger'] }).catch(() => false);
  if (granted) {
    state.active = 'cert';
    await scan();
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
  const stopIp = /^https?:/.test(url) ? watchIp(url) : async () => null;
  const [net, dom, globals, cookies, securityTxt, tls, sources] = await Promise.all([
    withTimeout(chrome.runtime.sendMessage({ type: 'net', tabId: tab.id }).catch(() => null)),
    runInTab(tab.id, collectPage, 'ISOLATED'),
    runInTab(tab.id, collectGlobals, 'MAIN'),
    chrome.cookies.getAll({ url }).catch(() => []),
    fetchSecurityTxt(url),
    scanTls(tab),
    runInTab(tab.id, collectScriptSources, 'ISOLATED'),
  ]);

  // La capture n'est valable que si elle concerne le document affiché (pas une page
  // restaurée depuis le cache, ni une navigation interrompue).
  const docUrl = stripHash(dom?.docUrl || url);
  const sameDoc = net && stripHash(net.url) === docUrl;
  const captured = sameDoc && net.main ? net : null;
  const navError = sameDoc && !net.main ? net.error || null : null;

  let rawHeaders = captured ? captured.main.headers : null;
  let status = captured ? captured.main.status : null;
  let headerSource = rawHeaders ? 'capture' : null;
  if (!rawHeaders) {
    const r = await refetchHeaders(url);
    if (r) ({ headers: rawHeaders, status } = r, headerSource = 'refetch');
  }

  // IP : la connexion directe fait foi ; celle du chargement n'est gardée que si elle diffère.
  const ipNow = await stopIp();
  const ipLoad = captured?.main.ip || null;
  const ipInfo = ipNow
    ? { source: 'direct', load: ipLoad && ipLoad !== ipNow ? { ip: ipLoad, fromCache: !!captured.main.fromCache } : null }
    : { source: ipLoad && captured.main.fromCache ? 'cache' : 'load', load: null };

  // Après la lecture de l'IP : les scripts relus viendraient fausser watchIp.
  const jsSecrets = await scanJsSecrets(sources, url).catch(() => null);

  const vulns = GoaVulnDB.scan({ db: GOA_RETIRE_DB, scripts: (dom?.scripts || []).map((s) => s.src), globals: globals || {} });

  // Épingle du certificat : comparaison à la dernière visite via le service worker.
  let certPin = null;
  const leaf = tls?.status === 'ok' && tls.chain[0];
  if (leaf) {
    certPin = await chrome.runtime.sendMessage({
      type: 'pin',
      observation: { host: new URL(url).hostname, sha256: leaf.sha256, notAfter: leaf.notAfter, issuer: leaf.issuer.dn },
    }).catch(() => null);
  }

  // Mode actif (opt-in) : sondes de fichiers exposés + DNS. Jamais sans le réglage.
  const probes = state.settings?.activeMode ? await GoaProbes.run(url).catch(() => null) : null;

  return {
    vulns,
    certPin,
    probes,
    url,
    scannedAt: new Date().toISOString(),
    headers: rawHeaders ? headerMap(rawHeaders) : null,
    rawHeaders: rawHeaders || [],
    headerSource,
    status,
    ip: ipNow || ipLoad,
    ipInfo,
    jsSecrets,
    net: captured,
    navError,
    dom,
    globals,
    securityTxt,
    tls,
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

function download(text, mime, ext) {
  const { raw } = state;
  const href = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = el('a', { href, download: `goa-scan-${new URL(raw.url).hostname}-${raw.scannedAt.slice(0, 10)}.${ext}` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 5000);
}

function exportReport(fmt) {
  const { raw, report } = state;
  raw.version = chrome.runtime.getManifest().version;
  if (fmt === 'md') return download(GoaExport.buildMarkdown({ raw, report }), 'text/markdown', 'md');
  if (fmt === 'pdf') {
    // Page imprimable dans un onglet : elle appelle print(), l'utilisateur enregistre en PDF.
    const href = URL.createObjectURL(new Blob([GoaExport.buildPrintableHtml({ raw, report })], { type: 'text/html' }));
    window.open(href, '_blank');
    setTimeout(() => URL.revokeObjectURL(href), 30000);
    return;
  }
  const data = {
    tool: 'Goa Scan', version: raw.version, scannedAt: raw.scannedAt,
    url: raw.url, score: report.score, grade: report.grade, counts: report.counts,
    findings: report.findings, tech: report.tech, hosts: report.hosts, apis: report.apis, jsSecrets: raw.jsSecrets,
    status: raw.status, ip: raw.ip, ipInfo: raw.ipInfo, headerSource: raw.headerSource, headers: raw.rawHeaders,
    cookies: raw.cookies, tls: raw.tls, probes: raw.probes,
  };
  download(JSON.stringify(data, null, 2), 'application/json', 'json');
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
  const visible = TABS.filter((t) => !t.optional || state.report.findings.some((f) => t.cats.includes(f.cat)) || state.settings.activeMode);
  nav.replaceChildren(...visible.map((t) => {
    const n = t.cats ? state.report.findings.filter((f) => !f.ok && f.sev !== 'info' && t.cats.includes(f.cat)).length : 0;
    return el('button', {
      type: 'button', role: 'tab', 'aria-selected': String(state.active === t.id),
      onclick: () => { state.active = t.id; renderTabs(); renderPanel(); },
    }, t.label, n ? el('span', { class: 'n', text: n }) : null);
  }));
  // La barre défile quand tous les onglets ne tiennent pas : garder l'onglet actif visible.
  nav.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}

function renderPanel() {
  const panel = $('panel');
  const def = TABS.find((t) => t.id === state.active);
  const extras = { cert: certExtra, headers: headersExtra, cookies: cookiesExtra, content: contentExtra, active: activeExtra, api: apiExtra, network: networkExtra };
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

function ipHint(raw) {
  const info = raw.ipInfo;
  if (info?.load) {
    return `Adresse IP lue à l’instant sur une connexion directe. La page affichée venait de ${info.load.ip} : ${info.load.fromCache
      ? 'elle a été resservie par le cache du navigateur, avec l’IP de sa première connexion'
      : 'autre serveur du même domaine (CDN, plusieurs enregistrements DNS) ou proxy de préchargement'}.`;
  }
  if (info?.source === 'cache') return 'Adresse IP lue dans le cache du navigateur : c’est celle de la première connexion, elle peut avoir changé depuis.';
  return null;
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
  const ipNote = ipHint(raw);
  if (ipNote) out.push(el('p', { class: 'hint', text: ipNote }));
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
    el('p', { class: 'hint', text: 'Ces services externes reçoivent le domaine analysé. SSL Labs teste en plus toutes les suites acceptées par le serveur, ce qu’un navigateur ne voit pas.' }));
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

function certExtra() {
  const { raw } = state;
  const tls = raw.tls;
  if (!tls) return [el('div', { class: 'note', text: 'Page servie en HTTP : il n’y a aucun certificat à analyser.' })];
  if (tls.status === 'no-permission') {
    return [el('div', { class: 'note' },
      'Chrome ne donne accès au certificat qu’à travers son protocole de débogage. Goa Scan s’y attache une fraction de seconde, en local, puis se détache : Chrome affiche alors brièvement un bandeau « a commencé le débogage ».',
      el('br'),
      el('button', { type: 'button', onclick: enableCertScan, text: 'Activer l’analyse des certificats' }))];
  }
  if (tls.status !== 'ok') return [];
  if (!tls.chain.length && !tls.protocol) return [];

  const day = (t) => new Date(t).toISOString().slice(0, 10);
  const leaf = tls.chain[0];
  const out = [
    el('h2', { text: 'Connexion' }),
    facts([
      ['Protocole', tls.protocol || '—'],
      ['Échange de clés', tls.group || tls.keyExchange || '—'],
      ['Chiffrement', [tls.cipher, tls.mac].filter(Boolean).join(' / ') || '—'],
      ['Transparence', { compliant: 'conforme', 'not-compliant': 'non conforme', unknown: 'inconnue' }[tls.ct] || '—'],
      ['Validation', leaf?.validation || '—'],
      ['Émetteur', leaf ? (leaf.issuer.o || leaf.issuer.cn) : '—'],
    ]),
  ];
  if (!tls.chain.length) return out;

  out.push(el('h2', { text: `Chaîne de certification (${tls.chain.length})` }));
  tls.chain.forEach((c, i) => {
    const role = i === 0 ? 'Certificat du site' : c.selfSigned ? 'Racine' : 'Intermédiaire';
    const key = c.key.type === 'EC' ? `EC ${c.key.curve}` : `${c.key.type} ${c.key.bits} bits`;
    const rows = [
      ['Sujet', c.subject.dn || '—'],
      ['Émetteur', c.issuer.dn || '—'],
      ['Validité', `${day(c.notBefore)} → ${day(c.notAfter)}`],
      ['Clé', key],
      ['Signature', c.sigAlg],
      ['Série', c.serial],
      ['SHA-256', c.sha256],
    ];
    if (c.isCA) rows.push(['Autorité', 'oui (CA)']);
    if (i === 0) rows.push(['Transparence', c.sct ? 'SCT intégrés' : 'aucun SCT intégré']);
    const card = el('div', { class: 'certcard' },
      el('div', { class: 'role', text: role }),
      el('h3', { text: c.subject.cn || c.subject.o || c.subject.dn }),
      el('dl', { class: 'kv' }, rows.map(([k, v]) => [el('dt', { text: k }), el('dd', { text: v })])));
    if (c.san.length) {
      card.append(el('details', { class: 'san' },
        el('summary', { text: `${c.san.length} nom${c.san.length > 1 ? 's' : ''} couvert${c.san.length > 1 ? 's' : ''} (SAN)` }),
        el('ul', { class: 'items' }, c.san.slice(0, 200).map((n) => el('li', { text: n })))));
    }
    out.push(card);
  });
  return out;
}

function activeExtra() {
  const { raw } = state;
  if (!state.settings.activeMode) {
    return [el('div', { class: 'note' },
      'Le mode actif envoie de vraies requêtes vers le site pour détecter des fichiers exposés (/.git, /.env, /server-status…) et lire sa configuration DNS (CAA, DNSSEC, SPF, DMARC). Ne l’active que sur des sites qui t’appartiennent ou que tu es autorisé à tester.',
      el('br'),
      el('button', { type: 'button', onclick: () => setSetting('activeMode', true), text: 'Activer le mode actif et relancer' }))];
  }
  if (!raw.probes) return [el('p', { class: 'status', text: 'Sondes en cours ou indisponibles pour cette page.' })];
  const out = [];
  const d = raw.probes.dns;
  if (d) {
    out.push(el('h2', { text: `DNS de ${d.domain}` }));
    out.push(facts([
      ['DNSSEC', d.dnssec ? 'actif' : 'inactif'],
      ['CAA', d.caa ? 'présent' : 'absent'],
      ['SPF', d.spf ? 'présent' : 'absent'],
      ['DMARC', d.dmarc ? 'présent' : 'absent'],
    ]));
    if (d.spf) out.push(el('p', { class: 'hint', text: `SPF : ${d.spf}` }));
    if (d.dmarc) out.push(el('p', { class: 'hint', text: `DMARC : ${d.dmarc}` }));
  }
  out.push(el('h2', { text: 'Fichiers testés' }),
    el('p', { class: 'hint', text: `${raw.probes.files.length} fichier(s) accessible(s) sur ${GoaProbes.FILE_COUNT} chemins sondés, plus ${GoaProbes.API_DOC_COUNT} emplacements de documentation d’API (voir l’onglet API). Les tests sans résultat ne sont pas listés.` }));
  return out;
}

const shortType = (ct) => (ct ? ct.replace(/^(application|text)\//, '') : '—');

function apiExtra() {
  const { raw, report } = state;
  const out = [];
  if (!raw.net) {
    out.push(captureNote());
  } else {
    const apis = report.apis;
    const tag = (t) => el('span', { class: 'tag', text: ` · ${t}` });
    out.push(el('h2', { text: 'Appels d’API de la page' }), facts([
      ['Endpoints', apis.length],
      ['Appels', apis.reduce((s, a) => s + a.n, 0)],
      ['Domaines', new Set(apis.map((a) => a.host)).size],
    ]));
    if (apis.length) {
      // Chemin seul pour les appels vers la page elle-même : la colonne reste lisible dans le popup.
      const pageOrigin = new URL(raw.url).origin;
      const shown = (u) => (u.startsWith(`${pageOrigin}/`) ? u.slice(pageOrigin.length) : u.replace(/^(https?|wss?):\/\//, ''));
      const tbl = table(['Méthode', 'Endpoint', 'Appels', 'Statut', 'Réponse', 'Auth'], apis.map((a) => [
        a.ws ? 'WS' : a.method,
        el('span', { title: a.url }, shown(a.url),
          a.tracker ? tag('traqueur') : a.third ? tag('tiers') : null, a.graphql ? tag('GraphQL') : null,
          a.params.length ? el('div', { class: 'params', text: `?${a.params.join('&')}` }) : null),
        a.n,
        a.statuses.join(' ') || a.error || '—',
        shortType(a.ctype),
        a.auth || '—',
      ]));
      tbl.firstChild.classList.add('api');
      out.push(tbl);
      if (raw.net.apisTruncated) out.push(el('p', { class: 'hint', text: `Liste tronquée à ${apis.length} endpoints.` }));
    } else {
      out.push(el('p', { class: 'hint', text: 'Aucun appel fetch, XHR ou WebSocket depuis le chargement de la page.' }));
    }
    out.push(el('p', { class: 'hint', text: 'Les identifiants dans les chemins deviennent :id, :uuid, :hash ou :token pour regrouper les appels. Seuls les noms des paramètres et le type d’authentification sont gardés, jamais leurs valeurs. Les appels faits après l’analyse apparaissent en cliquant sur Relancer.' }));
  }

  const js = raw.jsSecrets;
  if (js) {
    const s = js.scanned;
    out.push(el('h2', { text: 'Clés et secrets dans le JavaScript' }), facts([
      ['Scripts lus', s.inline + s.external],
      ['Volume', `${(s.bytes / 1e6).toFixed(1)} Mo`],
      ['Trouvés', js.hits.length],
    ]));
    if (js.hits.length) {
      out.push(table(['Type', 'Valeur masquée', 'Source'], js.hits.map((h) => [
        el('span', {}, h.name, h.public ? el('span', { class: 'tag', text: ' · publique' }) : null),
        el('span', { class: 'nowrap', text: h.value }),
        `${h.source}${h.line > 1 ? `:${h.line}` : ''}${h.third ? ' (tiers)' : ''}`,
      ])));
    }
    out.push(el('p', { class: 'hint', text: `Recherche par formats connus (AWS, Stripe, GitHub, GitLab, OpenAI, Anthropic, Slack, Discord, Telegram, SendGrid, clés privées, JWT Supabase…) dans ${s.inline} script(s) inline et ${s.external} script(s) externe(s) relus sans cookies${s.trackers ? `, ${s.trackers} script(s) de traqueurs ignoré(s)` : ''}${s.skipped ? `, ${s.skipped} au-delà de la limite de ${JS_MAX_SCRIPTS}` : ''}. Les valeurs sont masquées et ne quittent pas le navigateur.` }));
  }

  const doc = raw.probes?.apiDoc;
  if (doc) {
    out.push(el('h2', { text: `Documentation ${doc.kind} ${doc.version}${doc.title ? ` — ${doc.title}` : ''}` }),
      el('p', { class: 'hint', text: `Trouvée sur ${doc.path} : ${doc.total} route(s)${doc.total > doc.routes.length ? `, ${doc.routes.length} affichées` : ''}.` }),
      table(['Méthode', 'Route', 'Description'], doc.routes.map((r) => [r.method, r.path, r.summary || '—'])));
  } else if (!state.settings.activeMode) {
    out.push(el('p', { class: 'hint', text: 'Le mode actif cherche aussi une documentation OpenAPI ou Swagger publique (openapi.json, swagger.json, /v3/api-docs…) et en liste les routes.' }));
  }
  return out;
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

async function setSetting(key, value) {
  state.settings = await chrome.runtime.sendMessage({ type: 'settings:set', patch: { [key]: value } }).catch(() => ({ ...state.settings, [key]: value }));
  syncToggles();
  await scan();
}

function syncToggles() {
  $('tg-auto').checked = !!state.settings.autoScan;
  $('tg-active').checked = !!state.settings.activeMode;
  $('toggles').hidden = false;
}

function wireExportMenu() {
  const list = $('exportList');
  const btn = $('export');
  const close = () => { list.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    const open = list.hidden;
    list.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
  });
  list.addEventListener('click', (e) => { const f = e.target.dataset?.fmt; if (f) { exportReport(f); close(); } });
  document.addEventListener('click', close);
}

async function main() {
  document.body.classList.toggle('full', fullPage);
  $('full').hidden = fullPage;
  $('rescan').addEventListener('click', scan);
  $('reload').addEventListener('click', reloadAndScan);
  $('full').addEventListener('click', openFull);
  wireExportMenu();
  $('tg-auto').addEventListener('change', (e) => setSetting('autoScan', e.target.checked));
  $('tg-active').addEventListener('change', (e) => setSetting('activeMode', e.target.checked));

  state.settings = await chrome.runtime.sendMessage({ type: 'settings:get' }).catch(() => state.settings) || state.settings;
  syncToggles();

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
