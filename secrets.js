'use strict';
// Goa Scan — clés et secrets dans le JavaScript servi au navigateur.
// Reconnaissance par format (préfixes connus) plutôt que par entropie : moins de faux positifs.
// Fonctions pures, testables sous Node. Une valeur trouvée ne sort d'ici que masquée.
(function (root) {
  const PLACEHOLDER = /x{4,}|your|example|placeholder|changeme|dummy|sample|fake|\*{3,}|\$\{|\{\{|<|>/i;

  function b64url(s) {
    const b = s.replace(/-/g, '+').replace(/_/g, '/');
    return atob(b + '='.repeat((4 - (b.length % 4)) % 4));
  }

  // Un JWT codé en dur n'est grave que s'il donne des droits : service_role Supabase.
  function classifyJwt(v, rule) {
    let p;
    try { p = JSON.parse(b64url(v.split('.')[1])); } catch { return null; }
    if (!p || typeof p !== 'object') return null;
    if (p.role === 'service_role') return { id: 'supabase-service-role', name: 'Clé service_role Supabase', sev: 'critical' };
    if (p.role === 'anon') return { id: 'supabase-anon', name: 'Clé anon Supabase', sev: 'info', public: true };
    return rule;
  }

  // public : clé faite pour être servie au navigateur — à restreindre, pas à révoquer.
  const RULES = [
    { id: 'private-key', name: 'Clé privée', sev: 'critical', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
    { id: 'aws-access-key', name: 'Clé d’accès AWS', sev: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
    { id: 'aws-secret', name: 'Clé secrète AWS', sev: 'critical', re: /aws.{0,20}?(?:secret|private).{0,20}?["'`]([A-Za-z0-9/+=]{40})["'`]/gi, group: 1 },
    { id: 'stripe-secret', name: 'Clé secrète Stripe (live)', sev: 'critical', re: /\b[sr]k_live_[0-9a-zA-Z]{20,}\b/g },
    { id: 'stripe-test', name: 'Clé secrète Stripe (test)', sev: 'low', re: /\b[sr]k_test_[0-9a-zA-Z]{20,}\b/g },
    { id: 'stripe-public', name: 'Clé publique Stripe', sev: 'info', public: true, re: /\bpk_(?:live|test)_[0-9a-zA-Z]{20,}\b/g },
    { id: 'github-token', name: 'Jeton GitHub', sev: 'critical', re: /\b(?:gh[pousr]_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{60,})\b/g },
    { id: 'gitlab-token', name: 'Jeton GitLab', sev: 'critical', re: /\bglpat-[0-9A-Za-z_-]{20}\b/g },
    { id: 'openai-key', name: 'Clé OpenAI', sev: 'critical', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}T3BlbkFJ[A-Za-z0-9_-]{16,}|\bsk-proj-[A-Za-z0-9_-]{40,}/g },
    { id: 'anthropic-key', name: 'Clé Anthropic', sev: 'critical', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g },
    { id: 'google-oauth-secret', name: 'Secret client OAuth Google', sev: 'high', re: /\bGOCSPX-[0-9A-Za-z_-]{28}\b/g },
    { id: 'google-api-key', name: 'Clé d’API Google', sev: 'info', public: true, re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { id: 'slack-token', name: 'Jeton Slack', sev: 'high', re: /\bxox[abposr]-[0-9A-Za-z-]{10,}/g },
    { id: 'slack-webhook', name: 'Webhook Slack', sev: 'high', re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Z]+\/B[0-9A-Z]+\/[0-9A-Za-z]+/g },
    { id: 'discord-webhook', name: 'Webhook Discord', sev: 'high', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+/g },
    { id: 'discord-bot', name: 'Jeton de bot Discord', sev: 'high', re: /\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b/g },
    { id: 'telegram-bot', name: 'Jeton de bot Telegram', sev: 'high', re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g },
    { id: 'sendgrid', name: 'Clé SendGrid', sev: 'high', re: /\bSG\.[\w-]{22}\.[\w-]{43}\b/g },
    { id: 'twilio', name: 'Clé d’API Twilio', sev: 'high', re: /\bSK[0-9a-f]{32}\b/g },
    { id: 'mailgun', name: 'Clé Mailgun', sev: 'high', re: /\bkey-[0-9a-z]{32}\b/g },
    { id: 'mailchimp', name: 'Clé Mailchimp', sev: 'high', re: /\b[0-9a-f]{32}-us\d{1,2}\b/g },
    { id: 'npm-token', name: 'Jeton npm', sev: 'critical', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
    { id: 'huggingface', name: 'Jeton Hugging Face', sev: 'high', re: /\bhf_[A-Za-z]{34}\b/g },
    { id: 'shopify', name: 'Jeton Shopify', sev: 'critical', re: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g },
    { id: 'digitalocean', name: 'Jeton DigitalOcean', sev: 'critical', re: /\bdo[por]_v1_[a-f0-9]{64}\b/g },
    { id: 'mapbox-secret', name: 'Jeton secret Mapbox', sev: 'high', re: /\bsk\.eyJ[\w-]{20,}\.[\w-]{10,}/g },
    {
      id: 'url-credentials', name: 'Identifiants dans une URL', sev: 'high',
      re: /\b(?:https?|ftp|mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp):\/\/[^\s/:@'"`<>]{1,64}:[^\s/@'"`<>]{3,64}@[\w.-]+/g,
      check: (v) => !/:(pass(word)?|pwd|secret|\*+|x+)@/i.test(v) && !PLACEHOLDER.test(v.split('@')[0]),
      mask: (v) => v.replace(/:([^:@/]+)@/, ':••••@'),
    },
    { id: 'jwt', name: 'JWT codé en dur', sev: 'info', re: /\beyJ[\w-]{10,}\.eyJ[\w-]{10,}\.[\w-]{10,}/g, classify: classifyJwt },
  ];

  // Affectation à un nom évocateur, sans format connu : « à vérifier ».
  const GENERIC = /["']?\b(api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token|private[_-]?key|password|passwd)\b["']?\s*[:=]\s*["'`]([^"'`\s]{16,200})["'`]/gi;
  // Un UUID nu est un identifiant (clé publique de SDK, id de projet), pas un secret.
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  const looksSecret = (v) => /[a-z]/i.test(v) && /\d/.test(v) && !PLACEHOLDER.test(v) && !/^(https?:)?\/\//.test(v) && !UUID.test(v);

  function mask(v) {
    if (v.startsWith('-----BEGIN')) return v;
    const keep = Math.min(8, Math.floor(v.length / 4));
    return `${v.slice(0, keep)}…${v.slice(-3)}`;
  }

  function lineOf(text, index) {
    let n = 1;
    for (let i = text.indexOf('\n'); i !== -1 && i < index; i = text.indexOf('\n', i + 1)) n++;
    return n;
  }

  // → [{ id, name, sev, public, value (masquée), source, line }]
  function scan(text, source, { max = 50, perRule = 10 } = {}) {
    const hits = [];
    const seen = new Set();
    const add = (r, v, index, maskFn) => {
      if (seen.has(v) || hits.length >= max) return false;
      seen.add(v);
      hits.push({ id: r.id, name: r.name, sev: r.sev, public: !!r.public, value: (maskFn || mask)(v), source, line: lineOf(text, index) });
      return true;
    };
    for (const rule of RULES) {
      let n = 0;
      for (const m of text.matchAll(rule.re)) {
        const v = m[rule.group || 0];
        if (!v || (rule.check && !rule.check(v))) continue;
        const r = rule.classify ? rule.classify(v, rule) : rule;
        if (r && add(r, v, m.index, rule.mask) && ++n >= perRule) break;
      }
    }
    let n = 0;
    for (const m of text.matchAll(GENERIC)) {
      const v = m[2];
      if (!looksSecret(v) || [...seen].some((s) => s.includes(v) || v.includes(s))) continue;
      if (add({ id: 'generic', name: `Secret potentiel (${m[1]})`, sev: 'info' }, v, m.index) && ++n >= perRule) break;
    }
    return hits;
  }

  // ── Endpoints cités dans le code (à la LinkFinder) ─────────────
  // Chaînes entre guillemets qui ressemblent à une adresse : URL absolue, chemin absolu,
  // ou chemin d'API relatif (api/…, v1/…). Les fichiers statiques et les URL d'espaces de
  // noms (w3.org…) sont écartés. Plafond : faux positifs possibles (routes de pages).
  const QUOTED = /["'`]((?:https?:)?\/\/[^"'`\s<>\\]{3,300}|\/[A-Za-z0-9_$~.-][^"'`\s<>\\]{1,300}|(?:api|v\d+|graphql|rest|rpc)\/[^"'`\s<>\\]{1,300})["'`]/g;
  const ASSET = /\.(m?js|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|txt|md|html?)$/i;
  const NOISE_HOST = /(^|\.)(w3\.org|schema\.org|ogp\.me|purl\.org|xmlns\.com|apache\.org|opensource\.org|creativecommons\.org)$/i;

  function endpoints(text, { max = 300 } = {}) {
    const out = [];
    const seen = new Set();
    // Les correspondances arrivent dans l'ordre : on compte les lignes au fil de l'eau.
    let line = 1;
    let pos = 0;
    for (const m of text.matchAll(QUOTED)) {
      let p = m[1].replace(/\$\{[^}]*\}/g, ':param');
      if (p.startsWith('//')) p = `https:${p}`;
      if (seen.has(p) || !/[a-z]{2}/i.test(p) || ASSET.test(p.split(/[?#]/)[0])) continue;
      if (/^https?:/.test(p)) {
        let host;
        try { host = new URL(p).hostname; } catch { continue; }
        if (NOISE_HOST.test(host)) continue;
      } else if (p.includes('//')) {
        continue;
      }
      seen.add(p);
      for (let i = text.indexOf('\n', pos); i !== -1 && i < m.index; i = text.indexOf('\n', i + 1)) { line++; pos = i + 1; }
      out.push({ path: p, line });
      if (out.length >= max) break;
    }
    return out;
  }

  // ── Noms de paramètres cités dans le code (surface de fuzzing) ──
  // (a) clés des query strings dans les chaînes ; (b) accès explicites searchParams/FormData
  // et objets params/query/data. Un nom de paramètre est court, sans espace, pas une phrase.
  const PARAM_NAME = /^[\w.[\]-]{1,40}$/;
  const QUERY = /[?&]([\w.[\]-]{1,40})=/g;
  const ACCESS = /\b(?:searchParams|urlSearchParams|queryParams|formData|params|query)\s*\.\s*(?:get|set|append|has|getAll|delete)\s*\(\s*["'`]([^"'`]{1,40})["'`]/gi;
  // Littéral de paramètres : params/query = { a: …, "b-c": … }. Pas data/body : trop d'objets
  // internes (validation, Sentry) y passent, mesuré sur des sites réels.
  const OBJ = /\b(?:params|queryParams|searchParams)\s*[:=]\s*\{([^{}]{0,600})\}/gi;
  const OBJ_KEY = /(?:^|,)\s*["'`]?([\w.[\]-]{1,40})["'`]?\s*:/g;

  function params(text, { max = 200 } = {}) {
    const found = new Set();
    const add = (name) => {
      const n = name.trim();
      if (n && PARAM_NAME.test(n) && !/^\d+$/.test(n) && found.size < max) found.add(n);
    };
    // Query strings : seulement dans des chaînes qui portent une URL/chemin, pas n'importe quel &.
    for (const m of text.matchAll(QUOTED)) {
      const q = m[1].indexOf('?');
      if (q === -1) continue;
      for (const p of m[1].slice(q).matchAll(QUERY)) add(p[1]);
    }
    for (const m of text.matchAll(ACCESS)) add(m[1]);
    for (const m of text.matchAll(OBJ)) for (const k of m[1].matchAll(OBJ_KEY)) add(k[1]);
    return [...found];
  }

  const api = { scan, mask, endpoints, params, RULES };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaSecrets = api;
})(globalThis);
