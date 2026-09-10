import puppeteer from 'puppeteer-core';
import fs from 'node:fs';
const SRC = new URL('../../', import.meta.url).pathname;
const EXT = '/tmp/goa-scan-ext-plus/';
const OUT = process.env.OUT || '/tmp/goa-scan-shots/';
fs.rmSync(EXT, { recursive: true, force: true });
fs.cpSync(SRC, EXT, { recursive: true, filter: (p) => !p.includes('/.git') && !p.includes('/tests') });
fs.mkdirSync(OUT, { recursive: true });
const m = JSON.parse(fs.readFileSync(EXT + 'manifest.json'));
m.permissions.push('debugger'); delete m.optional_permissions;
fs.writeFileSync(EXT + 'manifest.json', JSON.stringify(m));

const browser = await puppeteer.launch({ executablePath: process.env.CHROME || '/usr/bin/chromium', headless: true, pipe: true, enableExtensions: [EXT], args: ['--no-sandbox'] });
const errors = [];
try {
  const sw = await browser.waitForTarget((t) => t.type() === 'service_worker' && t.url().startsWith('chrome-extension://'), { timeout: 15000 });
  const extId = new URL(sw.url()).host;
  const base = `chrome-extension://${extId}/popup.html`;
  const swp = await sw.worker();
  // active le mode actif via le service worker

  const page = await browser.newPage();
  page.on('pageerror',(e)=>errors.push('page:'+e.message));
  await page.goto('http://127.0.0.1:8766/', { waitUntil: 'networkidle2' });
  await new Promise(r=>setTimeout(r,900)); // laisse l'auto-scan poser le badge
  const badge = await swp.evaluate(async () => { const t=(await chrome.tabs.query({})).find(x=>x.url&&x.url.startsWith('http://127.0.0.1:8766')); return { text: await chrome.action.getBadgeText({tabId:t.id}), title: await chrome.action.getTitle({tabId:t.id}) }; });
  console.log('BADGE', JSON.stringify(badge));

  const r = await browser.newPage();
  r.on('pageerror',(e)=>errors.push('popup:'+e.message));
  r.on('console',(m)=>{ if(m.type()==='error') errors.push('console:'+m.text()); });
  await r.goto(base);
  const tabId = await r.evaluate(async () => (await chrome.tabs.query({})).find(x=>x.url&&x.url.startsWith('http://127.0.0.1:8766'))?.id);
  await r.setViewport({ width: 460, height: 620 });
  await r.goto(`${base}?tab=${tabId}`);
  await r.waitForFunction(() => typeof state!=='undefined' && state.report && !state.busy, { timeout: 30000, polling: 250 });
  await r.evaluate(() => document.getElementById('tg-active').click());
  await r.waitForFunction(() => !state.busy && state.settings.activeMode, { timeout: 30000, polling: 250 });
  const s = await r.evaluate(() => ({
    grade: state.report.grade, activeMode: state.settings.activeMode,
    probes: state.raw.probes && { files: state.raw.probes.files.map(f=>f.path+':'+f.sev), dns: state.raw.probes.dns },
    vulns: (state.raw.vulns||[]).map(v=>v.component+'@'+v.version+'['+v.sev+']'),
    active: state.report.findings.filter(f=>f.cat==='active').map(f=>(f.ok?'ok':f.sev)+':'+f.title),
    md: GoaExport.buildMarkdown({raw:{...state.raw,version:'0.2.0'},report:state.report}).length,
  }));
  console.log('POPUP', JSON.stringify(s,null,1));
  // capture onglet Actif
  await r.evaluate(() => { state.active='active'; renderTabs(); renderPanel(); });
  await r.screenshot({ path: OUT+'plus-active.png' });
  await r.evaluate(() => { state.active='headers'; renderTabs(); renderPanel(); });
  await r.screenshot({ path: OUT+'plus-headers.png' });
  await r.evaluate(() => { document.getElementById('export').click(); });
  await r.screenshot({ path: OUT+'plus-export-menu.png' });
} finally { console.log('ERRORS', JSON.stringify(errors)); await browser.close(); }
