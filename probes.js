'use strict';
// Goa Scan — mode actif (opt-in). Envoie de vraies requêtes vers le site analysé pour
// détecter des fichiers exposés et lire sa configuration DNS publique. Désactivé par défaut.
// Chaque test est confirmé par le contenu, pour ne pas prendre un catch-all 200 pour une fuite.
(function (root) {
  const TIMEOUT = 6000;
  const signal = () => AbortSignal.timeout(TIMEOUT);

  // path → (texte du début de réponse) => preuve courte, ou null si faux positif.
  const FILES = [
    ['/.git/HEAD', 'critical', 'Dépôt Git exposé', (t) => /^ref:\s|^[0-9a-f]{40}/.test(t.trim()) && 'ref: …'],
    ['/.git/config', 'critical', 'Config Git exposée', (t) => /\[core\]|\[remote/.test(t) && '[core]'],
    ['/.env', 'critical', 'Fichier .env exposé', (t) => /(^|\n)[A-Z0-9_]{2,}\s*=/.test(t) && !/<html|<!doctype/i.test(t) && 'CLE=valeur'],
    ['/.svn/entries', 'high', 'Métadonnées SVN exposées', (t) => /^\d+|dir|svn:/.test(t.trim()) && 'entries'],
    ['/server-status', 'high', 'mod_status Apache exposé', (t) => /Apache Server Status/i.test(t) && 'Apache Server Status'],
    ['/phpinfo.php', 'high', 'phpinfo() exposé', (t) => /phpinfo\(\)|PHP Version/i.test(t) && 'PHP Version'],
    ['/.DS_Store', 'medium', 'Fichier .DS_Store exposé', (t) => t.charCodeAt(0) === 0 && t.includes('Bud1') && 'Bud1'],
    ['/.well-known/security.txt', 'ok', 'security.txt publié', (t) => /contact\s*:/i.test(t) && 'Contact:'],
    ['/robots.txt', 'info', 'robots.txt', (t) => /user-agent|disallow/i.test(t) && 'présent'],
  ];

  async function probeFile(origin, [path, sev, title, confirm]) {
    try {
      const r = await fetch(origin + path, { credentials: 'omit', cache: 'no-store', redirect: 'manual', signal: signal() });
      if (!r.ok || r.type === 'opaqueredirect' || r.status >= 300) return null;
      const evidence = confirm((await r.text()).slice(0, 4000));
      return evidence ? { path, sev, title, evidence: String(evidence).slice(0, 80), status: r.status } : null;
    } catch {
      return null;
    }
  }

  // DNS-over-HTTPS (Cloudflare), format JSON. Ne renvoie que le domaine, jamais de contenu de page.
  async function doh(name, type) {
    try {
      const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1`, {
        headers: { accept: 'application/dns-json' }, signal: signal(),
      });
      if (!r.ok) return null;
      return await r.json();
    } catch {
      return null;
    }
  }

  const txtValues = (res) => (res?.Answer || []).filter((a) => a.type === 16).map((a) => a.data.replace(/^"|"$/g, '').replace(/" "/g, ''));

  async function probeDns(hostname) {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.endsWith('.local')) return null;
    // Domaine enregistrable approché (dernier label + suffixe courant).
    const parts = hostname.split('.');
    const domain = parts.length > 2 ? parts.slice(-2).join('.') : hostname;
    const [caa, root, dmarc] = await Promise.all([doh(domain, 'CAA'), doh(domain, 'TXT'), doh(`_dmarc.${domain}`, 'TXT')]);
    if (!root && !caa && !dmarc) return null;
    return {
      domain,
      dnssec: root?.AD === true || caa?.AD === true,
      caa: (caa?.Answer || []).some((a) => a.type === 257),
      spf: txtValues(root).find((t) => /^v=spf1/i.test(t)) || null,
      dmarc: txtValues(dmarc).find((t) => /^v=DMARC1/i.test(t)) || null,
    };
  }

  async function run(url) {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    const [files, dns] = await Promise.all([
      Promise.all(FILES.map((f) => probeFile(u.origin, f))).then((r) => r.filter(Boolean)),
      probeDns(u.hostname),
    ]);
    return { ranAt: Date.now(), files, dns };
  }

  const api = { run, probeDns };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaProbes = api;
})(globalThis);
