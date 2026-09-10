'use strict';
// Goa Scan — règles d'analyse. Fonctions pures, sans API Chrome : testables sous Node.
(function (root) {
  const WEIGHT = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };
  const ORDER = ['critical', 'high', 'medium', 'low', 'info'];

  // Suffixes publics à deux étiquettes les plus courants. Le calcul du « site » reste
  // une approximation : la Public Suffix List complète pèserait plus que l'extension.
  const MULTI_SUFFIXES = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp',
    'co.in', 'co.za', 'com.br', 'com.cn', 'com.tr', 'com.mx', 'gouv.fr', 'asso.fr',
    'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev',
    'herokuapp.com', 'web.app', 'firebaseapp.com', 'azurewebsites.net', 'cloudfront.net',
    'blogspot.com', 'appspot.com', 'onrender.com', 'fly.dev',
  ]);

  const TRACKER_SITES = new Set([
    'doubleclick.net', 'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com',
    'googleadservices.com', 'facebook.net', 'hotjar.com', 'clarity.ms', 'segment.io', 'segment.com',
    'mixpanel.com', 'amplitude.com', 'criteo.com', 'criteo.net', 'taboola.com', 'outbrain.com',
    'scorecardresearch.com', 'quantserve.com', 'adnxs.com', 'rubiconproject.com', 'pubmatic.com',
    'amazon-adsystem.com', 'ads-twitter.com', 'licdn.com', 'hs-analytics.net', 'fullstory.com',
    'mouseflow.com', 'crazyegg.com', 'adsrvr.org', 'smartadserver.com', 'teads.tv', 'yieldlove.com',
  ]);
  const TRACKER_HOSTS = new Set(['bat.bing.com', 'analytics.tiktok.com', 'px.ads.linkedin.com', 'mc.yandex.ru']);

  const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[');

  function siteOf(host) {
    const h = String(host).toLowerCase().replace(/\.$/, '');
    if (isIp(h)) return h;
    const parts = h.split('.');
    if (parts.length <= 2) return h;
    return MULTI_SUFFIXES.has(parts.slice(-2).join('.')) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
  }

  const isTracker = (host) => TRACKER_HOSTS.has(host) || TRACKER_SITES.has(siteOf(host));

  function cmpVer(a, b) {
    const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
    const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
    for (let i = 0; i < 3; i++) {
      if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) < (pb[i] || 0) ? -1 : 1;
    }
    return 0;
  }

  // Une virgule sépare plusieurs politiques, un point-virgule les directives d'une politique.
  function parseCsp(value) {
    if (!value) return [];
    return String(value).split(',').map((policy) => {
      const d = new Map();
      for (const part of policy.split(';')) {
        const toks = part.trim().split(/\s+/).filter(Boolean);
        if (toks.length && !d.has(toks[0].toLowerCase())) d.set(toks[0].toLowerCase(), toks.slice(1).map((t) => t.toLowerCase()));
      }
      return d;
    }).filter((d) => d.size);
  }

  function hostOf(u) {
    try { return new URL(u).hostname; } catch { return ''; }
  }

  function gradeOf(score) {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 45) return 'D';
    if (score >= 30) return 'E';
    return 'F';
  }

  function analyze(input) {
    const findings = [];
    const add = (f) => findings.push({ sev: 'info', ok: false, detail: '', fix: '', items: [], ...f });

    const page = new URL(input.url);
    const https = page.protocol === 'https:';
    const pageSite = siteOf(page.hostname);
    const h = input.headers;
    const dom = input.dom;
    const net = input.net;
    const g = input.globals || {};

    // ── Transport ─────────────────────────────────────────────
    if (https) add({ cat: 'transport', id: 'https', ok: true, title: 'Connexion chiffrée (HTTPS)' });
    else {
      add({
        cat: 'transport', id: 'https', sev: 'critical', title: 'Page servie en HTTP clair',
        detail: 'Tout ce qui transite (formulaires, cookies, contenu) peut être lu ou modifié par quiconque se trouve sur le chemin réseau.',
        fix: 'Servir le site en HTTPS et rediriger HTTP vers HTTPS (301).',
      });
    }
    if (net?.redirects?.some((r) => r.from.startsWith('http:') && r.to.startsWith('https:'))) {
      add({ cat: 'transport', id: 'redirect', ok: true, title: 'Redirection HTTP → HTTPS observée' });
    }

    if (https && h) {
      const hsts = h['strict-transport-security'];
      if (!hsts) {
        add({
          cat: 'transport', id: 'hsts', sev: 'medium', title: 'HSTS absent',
          detail: 'Sans HSTS, un attaquant sur le réseau peut forcer une première connexion en HTTP (SSL stripping).',
          fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        });
      } else {
        const age = Number((/max-age\s*=\s*"?(\d+)/i.exec(hsts) || [])[1] || 0);
        if (age < 15552000) {
          add({
            cat: 'transport', id: 'hsts', sev: 'low', title: `HSTS trop court (max-age=${age})`,
            detail: 'Une durée inférieure à 6 mois réduit la protection entre deux visites.',
            fix: 'max-age=31536000 (1 an) au minimum.',
          });
        } else {
          const extra = [/includesubdomains/i.test(hsts) && 'includeSubDomains', /preload/i.test(hsts) && 'preload'].filter(Boolean);
          add({ cat: 'transport', id: 'hsts', ok: true, title: `HSTS actif (${Math.round(age / 86400)} jours${extra.length ? ', ' + extra.join(', ') : ''})` });
        }
      }
    }

    if (https) {
      const ACTIVE_DOM = new Set(['script', 'stylesheet', 'iframe', 'object']);
      const ACTIVE_NET = new Set(['script', 'stylesheet', 'sub_frame', 'object', 'xmlhttprequest', 'websocket']);
      const active = new Set();
      const passive = new Set();
      for (const m of dom?.mixed || []) (ACTIVE_DOM.has(m.kind) ? active : passive).add(m.url);
      for (const m of net?.insecure || []) (ACTIVE_NET.has(m.type) ? active : passive).add(m.url);
      for (const u of active) passive.delete(u);
      if (active.size) {
        add({
          cat: 'transport', id: 'mixed-active', sev: 'high', title: `Contenu mixte actif (${active.size})`,
          detail: 'Scripts, styles, cadres ou connexions chargés en clair depuis une page HTTPS : un attaquant réseau peut les remplacer. Chrome en bloque une partie, ce qui casse aussi la page.',
          fix: 'Charger toutes les ressources en https:// (ou en URL relative au protocole du site).',
          items: [...active].slice(0, 15),
        });
      }
      if (passive.size) {
        add({
          cat: 'transport', id: 'mixed-passive', sev: 'low', title: `Contenu mixte passif (${passive.size})`,
          detail: 'Images ou médias référencés en http://. Chrome les passe en HTTPS automatiquement, mais la page reste mal configurée.',
          fix: 'Réécrire ces URL en https://.',
          items: [...passive].slice(0, 15),
        });
      }
      if (!active.size && !passive.size && (dom || net)) add({ cat: 'transport', id: 'mixed', ok: true, title: 'Aucun contenu mixte détecté' });
    }

    // ── En-têtes de sécurité ──────────────────────────────────
    if (!h) {
      add({
        cat: 'headers', id: 'no-headers', title: 'En-têtes de réponse indisponibles',
        detail: 'Ni la capture au chargement ni la requête de secours n’ont abouti. Rechargez la page puis relancez l’analyse.',
      });
    } else {
      const headerPolicies = parseCsp(h['content-security-policy']);
      const policies = headerPolicies.concat((dom?.metaCsp || []).flatMap(parseCsp));
      const scriptSrc = (p) => p.get('script-src') || p.get('default-src');

      if (!policies.length) {
        const ro = !!h['content-security-policy-report-only'];
        add({
          cat: 'headers', id: 'csp', sev: 'medium',
          title: ro ? 'CSP en mode Report-Only uniquement' : 'Content-Security-Policy absente',
          detail: ro
            ? 'La politique est seulement observée : elle signale les violations sans rien bloquer.'
            : 'La CSP est la principale défense en profondeur contre le XSS : elle limite les scripts que la page peut exécuter.',
          fix: "Point de départ : default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self' — puis ajouter les origines nécessaires.",
        });
      } else {
        const relevant = policies.filter(scriptSrc);
        if (!relevant.length) {
          add({
            cat: 'headers', id: 'csp-scripts', sev: 'medium', title: 'La CSP ne restreint pas les scripts',
            detail: 'Ni script-src ni default-src : les scripts restent autorisés depuis n’importe où.',
            fix: "Ajouter script-src (ou default-src), par exemple script-src 'self'.",
          });
        } else {
          const strict = (l) => l.includes("'strict-dynamic'");
          const nonceOrHash = (l) => l.some((s) => /^'(nonce-|sha(256|384|512)-)/.test(s));
          // Une source n'est permise que si toutes les politiques la permettent.
          const inline = relevant.every((p) => { const l = scriptSrc(p); return l.includes("'unsafe-inline'") && !nonceOrHash(l) && !strict(l); });
          const unsafeEval = relevant.every((p) => scriptSrc(p).includes("'unsafe-eval'"));
          const wide = relevant.every((p) => { const l = scriptSrc(p); return !strict(l) && l.some((s) => ['*', 'http:', 'https:', 'data:'].includes(s)); });
          if (inline) {
            add({
              cat: 'headers', id: 'csp-inline', sev: 'medium', title: "CSP : scripts inline autorisés ('unsafe-inline')",
              detail: 'Un script injecté dans la page s’exécutera : la CSP ne protège plus contre le XSS.',
              fix: "Remplacer 'unsafe-inline' par des nonces ou des hashes, idéalement avec 'strict-dynamic'.",
            });
          }
          if (unsafeEval) {
            add({
              cat: 'headers', id: 'csp-eval', sev: 'low', title: "CSP : 'unsafe-eval' autorisé",
              detail: 'eval(), new Function() et consorts restent utilisables par un attaquant.',
              fix: "Retirer 'unsafe-eval' et supprimer les appels dynamiques du code.",
            });
          }
          if (wide) {
            add({
              cat: 'headers', id: 'csp-wide', sev: 'medium', title: 'CSP : sources de scripts trop larges',
              detail: 'Des jokers comme *, https: ou data: autorisent des scripts depuis presque n’importe quelle origine.',
              fix: 'Lister les origines précises, ou passer à des nonces avec strict-dynamic.',
            });
          }
          if (!inline && !wide) add({ cat: 'headers', id: 'csp', ok: true, title: 'CSP qui restreint les scripts' });
        }
        if (!policies.some((p) => p.has('object-src') || p.has('default-src'))) {
          add({
            cat: 'headers', id: 'csp-object', sev: 'low', title: 'CSP : object-src non restreint',
            fix: "Ajouter object-src 'none'.",
          });
        }
        if (!policies.some((p) => p.has('base-uri'))) {
          add({
            cat: 'headers', id: 'csp-base', sev: 'low', title: 'CSP : base-uri non défini',
            detail: 'Une balise <base> injectée peut détourner toutes les URL relatives de la page.',
            fix: "Ajouter base-uri 'self' (ou 'none').",
          });
        }
      }

      const xfo = (h['x-frame-options'] || '').toLowerCase();
      const fa = headerPolicies.find((p) => p.has('frame-ancestors'))?.get('frame-ancestors');
      const faOk = fa && !fa.includes('*');
      if (faOk || /deny|sameorigin/.test(xfo)) {
        add({ cat: 'headers', id: 'framing', ok: true, title: `Protection anti-clickjacking (${faOk ? 'frame-ancestors' : 'X-Frame-Options'})` });
      } else {
        add({
          cat: 'headers', id: 'framing', sev: 'medium', title: 'Page intégrable dans une iframe (clickjacking)',
          detail: 'Un site tiers peut afficher cette page en transparence et piéger les clics de l’utilisateur.',
          fix: "Content-Security-Policy: frame-ancestors 'self' (ou X-Frame-Options: DENY).",
        });
      }

      if ((h['x-content-type-options'] || '').toLowerCase().includes('nosniff')) {
        add({ cat: 'headers', id: 'nosniff', ok: true, title: 'X-Content-Type-Options: nosniff' });
      } else {
        add({
          cat: 'headers', id: 'nosniff', sev: 'low', title: 'X-Content-Type-Options absent',
          detail: 'Le navigateur peut « deviner » le type d’un fichier et exécuter comme script un contenu déposé par un utilisateur.',
          fix: 'X-Content-Type-Options: nosniff',
        });
      }

      const rp = (h['referrer-policy'] || dom?.metaReferrer || '').toLowerCase();
      if (!rp) {
        add({
          cat: 'headers', id: 'referrer', sev: 'low', title: 'Referrer-Policy absente',
          detail: 'Chrome applique strict-origin-when-cross-origin par défaut, mais d’autres navigateurs peuvent transmettre l’URL complète aux sites tiers.',
          fix: 'Referrer-Policy: strict-origin-when-cross-origin',
        });
      } else if (/unsafe-url|no-referrer-when-downgrade/.test(rp)) {
        add({
          cat: 'headers', id: 'referrer', sev: 'low', title: `Referrer-Policy permissive (${rp})`,
          detail: 'L’URL complète, paramètres compris, part vers les sites tiers.',
          fix: 'Referrer-Policy: strict-origin-when-cross-origin',
        });
      } else {
        add({ cat: 'headers', id: 'referrer', ok: true, title: `Referrer-Policy: ${rp}` });
      }

      if (h['permissions-policy']) add({ cat: 'headers', id: 'permissions', ok: true, title: 'Permissions-Policy définie' });
      else {
        add({
          cat: 'headers', id: 'permissions', sev: 'low', title: 'Permissions-Policy absente',
          detail: 'Caméra, micro, géolocalisation… restent demandables par la page et ses iframes.',
          fix: 'Permissions-Policy: camera=(), microphone=(), geolocation=()',
        });
      }

      if (h['cross-origin-opener-policy']) add({ cat: 'headers', id: 'coop', ok: true, title: `Cross-Origin-Opener-Policy: ${h['cross-origin-opener-policy']}` });
      else {
        add({
          cat: 'headers', id: 'coop', sev: 'low', title: 'Cross-Origin-Opener-Policy absente',
          detail: 'Une fenêtre ouverte par un site tiers garde une référence vers celle-ci (fuites inter-sites, XS-Leaks).',
          fix: 'Cross-Origin-Opener-Policy: same-origin',
        });
      }

      if ((h['access-control-allow-origin'] || '').trim() === '*') {
        add({
          cat: 'headers', id: 'cors', sev: 'low', title: 'CORS ouvert à toutes les origines',
          detail: 'Access-Control-Allow-Origin: * sur le document : n’importe quel site peut lire cette réponse.',
          fix: 'Restreindre à une liste d’origines de confiance, ou retirer l’en-tête.',
        });
      }
      if (/^\s*1/.test(h['x-xss-protection'] || '')) {
        add({
          cat: 'headers', id: 'xxss', title: 'X-XSS-Protection activé (obsolète)',
          detail: 'Le filtre XSS a été retiré des navigateurs et pouvait lui-même introduire des failles. La CSP le remplace.',
          fix: 'X-XSS-Protection: 0, ou retirer l’en-tête.',
        });
      }

      // ── Exposition ──────────────────────────────────────────
      const server = h.server || '';
      if (/\d/.test(server)) {
        add({
          cat: 'exposure', id: 'server-version', sev: 'low', title: 'Version du serveur exposée',
          detail: 'Connaître la version exacte permet de cibler directement ses CVE.',
          fix: 'Masquer la version (nginx : server_tokens off ; Apache : ServerTokens Prod).',
          items: [`Server: ${server}`],
        });
      }
      const leaky = ['x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version', 'x-generator', 'x-runtime', 'x-drupal-cache']
        .filter((n) => h[n]).map((n) => `${n}: ${h[n]}`);
      if (leaky.length) {
        add({
          cat: 'exposure', id: 'stack-headers', sev: 'low', title: 'En-têtes révélant la pile technique',
          fix: 'Retirer ces en-têtes côté serveur ou reverse proxy.',
          items: leaky,
        });
      }
      if (!/\d/.test(server) && !leaky.length) add({ cat: 'exposure', id: 'stack-headers', ok: true, title: 'Aucune version divulguée dans les en-têtes' });
    }

    if (dom?.generator && /\d/.test(dom.generator)) {
      add({
        cat: 'exposure', id: 'generator', sev: 'low', title: 'Version du CMS exposée',
        fix: 'Retirer la balise <meta name="generator">.',
        items: [dom.generator],
      });
    }

    const libs = [
      { key: 'jquery', name: 'jQuery', bad: (v) => cmpVer(v, '3.5.0') < 0, sev: 'medium', why: 'XSS via la manipulation HTML (CVE-2020-11022, CVE-2020-11023).', fixV: '3.5.0' },
      { key: 'jqueryUI', name: 'jQuery UI', bad: (v) => cmpVer(v, '1.13.0') < 0, sev: 'low', why: 'XSS dans plusieurs options (CVE-2021-41182 à 41184).', fixV: '1.13.0' },
      { key: 'angularjs', name: 'AngularJS', bad: () => true, sev: 'medium', why: 'Branche en fin de vie depuis janvier 2022 : les failles découvertes depuis ne sont plus corrigées.', fixV: 'Angular moderne' },
      { key: 'bootstrap', name: 'Bootstrap', bad: (v) => (cmpVer(v, '4.0.0') < 0 ? cmpVer(v, '3.4.1') < 0 : cmpVer(v, '4.3.1') < 0), sev: 'low', why: 'XSS via data-template et data-content (CVE-2019-8331).', fixV: '3.4.1 / 4.3.1' },
      { key: 'lodash', name: 'Lodash', bad: (v) => cmpVer(v, '4.17.21') < 0, sev: 'low', why: 'Pollution de prototype et injection via template (CVE-2020-8203, CVE-2021-23337).', fixV: '4.17.21' },
      { key: 'moment', name: 'Moment.js', bad: (v) => cmpVer(v, '2.29.4') < 0, sev: 'low', why: 'Déni de service par expression régulière (CVE-2022-31129).', fixV: '2.29.4' },
    ];
    for (const lib of libs) {
      const v = g[lib.key];
      if (v && lib.bad(v)) {
        add({
          cat: 'exposure', id: `lib-${lib.key}`, sev: lib.sev, title: `${lib.name} ${v} vulnérable`,
          detail: lib.why, fix: `Mettre à jour vers ${lib.fixV} ou plus récent.`,
        });
      }
    }

    if (input.securityTxt === true) add({ cat: 'exposure', id: 'security-txt', ok: true, title: 'security.txt publié' });
    else if (input.securityTxt === false) {
      add({
        cat: 'exposure', id: 'security-txt', sev: 'low', title: 'Pas de security.txt',
        detail: 'Aucun contact publié pour signaler une vulnérabilité de façon responsable.',
        fix: 'Publier /.well-known/security.txt (RFC 9116) avec Contact: et Expires:.',
      });
    }

    // ── Cookies ───────────────────────────────────────────────
    const cookies = input.cookies || [];
    const sensitive = (c) => /sess|sid|token|auth|jwt|login|remember|identity|account/i.test(c.name) && !/csrf|xsrf/i.test(c.name);
    if (!cookies.length) add({ cat: 'cookies', id: 'cookies', ok: true, title: 'Aucun cookie pour cette page' });
    else {
      let issues = 0;
      const noSecure = https ? cookies.filter((c) => !c.secure) : [];
      if (noSecure.length) {
        issues++;
        const sens = noSecure.some(sensitive);
        add({
          cat: 'cookies', id: 'cookie-secure', sev: sens ? 'high' : 'low', title: `Cookies sans attribut Secure (${noSecure.length})`,
          detail: sens
            ? 'Des cookies qui ressemblent à des jetons de session peuvent partir en clair sur une requête HTTP.'
            : 'Ces cookies peuvent être envoyés sur une connexion non chiffrée.',
          fix: 'Ajouter Secure à tous les cookies d’un site HTTPS.',
          items: noSecure.map((c) => c.name),
        });
      }
      const readable = cookies.filter((c) => !c.httpOnly && sensitive(c));
      if (readable.length) {
        issues++;
        add({
          cat: 'cookies', id: 'cookie-httponly', sev: 'high', title: `Cookies de session lisibles en JavaScript (${readable.length})`,
          detail: 'Sans HttpOnly, un XSS suffit à voler la session.',
          fix: 'Ajouter HttpOnly aux cookies d’authentification.',
          items: readable.map((c) => c.name),
        });
      }
      const cross = cookies.filter((c) => c.sameSite === 'no_restriction');
      if (cross.length) {
        issues++;
        add({
          cat: 'cookies', id: 'cookie-samesite', sev: 'low', title: `Cookies envoyés en cross-site (SameSite=None) (${cross.length})`,
          detail: 'Ils accompagnent les requêtes venues d’autres sites, ce qui ouvre la porte au CSRF et au pistage.',
          fix: 'SameSite=Lax par défaut, Strict pour les cookies d’authentification.',
          items: cross.map((c) => c.name),
        });
      }
      if (!issues) add({ cat: 'cookies', id: 'cookies', ok: true, title: `Attributs des ${cookies.length} cookies corrects` });
    }

    // ── Contenu de la page ────────────────────────────────────
    if (dom) {
      if (dom.passwordFields && !https) {
        add({
          cat: 'content', id: 'password-http', sev: 'critical', title: 'Mot de passe saisi sur une page non chiffrée',
          detail: 'Le mot de passe sera lisible par quiconque intercepte le trafic.',
          fix: 'Servir la page de connexion et sa cible en HTTPS.',
        });
      }
      const httpForms = https ? dom.forms.filter((f) => f.action.startsWith('http:')) : [];
      if (httpForms.length) {
        add({
          cat: 'content', id: 'form-http', sev: 'high', title: 'Formulaire envoyé en HTTP clair',
          detail: 'La page est chiffrée mais les données saisies partent en clair.',
          fix: 'Faire pointer l’attribut action vers une URL https://.',
          items: httpForms.map((f) => `${f.method.toUpperCase()} ${f.action}`),
        });
      }
      const crossForms = dom.forms.filter((f) => /^https?:/.test(f.action) && siteOf(hostOf(f.action)) !== pageSite);
      if (crossForms.length) {
        add({
          cat: 'content', id: 'form-cross', title: 'Formulaires envoyés vers un autre site',
          detail: 'À vérifier : les données saisies quittent le domaine de la page.',
          items: crossForms.map((f) => `${f.method.toUpperCase()} ${f.action}`),
        });
      }

      const thirdScripts = dom.scripts.filter((s) => /^https?:/.test(s.src) && siteOf(hostOf(s.src)) !== pageSite);
      const noSri = thirdScripts.filter((s) => !s.integrity);
      if (noSri.length) {
        add({
          cat: 'content', id: 'sri', sev: 'low', title: `Scripts tiers sans SRI (${noSri.length})`,
          detail: 'Si le fournisseur est compromis, le script modifié s’exécute avec tous les droits de la page (attaque de la chaîne d’approvisionnement).',
          fix: 'Ajouter integrity="sha384-…" et crossorigin="anonymous" aux scripts de version figée.',
          items: noSri.map((s) => s.src).slice(0, 20),
        });
      } else if (thirdScripts.length) {
        add({ cat: 'content', id: 'sri', ok: true, title: 'Scripts tiers protégés par SRI' });
      }

      const thirdFrames = dom.iframes.filter((f) => /^https?:/.test(f.src) && siteOf(hostOf(f.src)) !== pageSite && !f.sandbox);
      if (thirdFrames.length) {
        add({
          cat: 'content', id: 'iframes', title: `Iframes tierces sans sandbox (${thirdFrames.length})`,
          fix: 'Ajouter l’attribut sandbox avec les seules permissions nécessaires.',
          items: thirdFrames.map((f) => f.src).slice(0, 15),
        });
      }

      if (dom.storage.flagged.length) {
        add({
          cat: 'content', id: 'storage-tokens', sev: 'medium', title: 'Jetons stockés dans le Web Storage',
          detail: 'localStorage et sessionStorage sont lisibles par tout script de la page : un XSS suffit à exfiltrer ces jetons.',
          fix: 'Préférer un cookie HttpOnly; Secure; SameSite pour les jetons d’authentification.',
          items: dom.storage.flagged.map((s) => `${s.area}Storage · ${s.key}${s.jwt ? ' (JWT)' : ''}`),
        });
      }
      if (dom.comments.flagged.length) {
        add({
          cat: 'content', id: 'comments', sev: 'low', title: 'Commentaires HTML sensibles',
          detail: 'Des commentaires livrés au navigateur évoquent des secrets ou des identifiants.',
          fix: 'Retirer les commentaires du HTML servi en production.',
          items: dom.comments.flagged,
        });
      }
      if (dom.emails.length) {
        add({
          cat: 'content', id: 'emails', title: `Adresses e-mail visibles (${dom.emails.length})`,
          detail: 'Collectables par les robots de spam et utiles pour du phishing ciblé.',
          items: dom.emails,
        });
      }
      if (dom.inlineScripts || dom.inlineHandlers) {
        add({
          cat: 'content', id: 'inline', title: `${dom.inlineScripts} scripts inline, ${dom.inlineHandlers} gestionnaires on*`,
          detail: 'À garder en tête pour une CSP stricte : chaque bloc inline devra recevoir un nonce ou un hash.',
        });
      }
    }

    // ── Réseau ────────────────────────────────────────────────
    const hosts = Object.entries(net?.hosts || {}).map(([host, v]) => ({
      host, n: v.n, types: v.types, third: siteOf(host) !== pageSite, tracker: isTracker(host),
    })).sort((a, b) => b.n - a.n);
    const trackers = hosts.filter((x) => x.tracker);
    if (trackers.length) {
      add({
        cat: 'network', id: 'trackers', title: `Traqueurs connus contactés (${trackers.length})`,
        detail: 'Domaines de publicité ou de mesure d’audience appelés par la page.',
        items: trackers.map((x) => x.host),
      });
    } else if (net) {
      add({ cat: 'network', id: 'trackers', ok: true, title: 'Aucun traqueur connu contacté' });
    }

    // ── Score ─────────────────────────────────────────────────
    let score = 100 - findings.filter((f) => !f.ok).reduce((s, f) => s + WEIGHT[f.sev], 0);
    if (!https) score = Math.min(score, 40);
    score = Math.max(0, score);

    const counts = Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => !f.ok && f.sev === s).length]));
    findings.sort((a, b) => (a.ok - b.ok) || (ORDER.indexOf(a.sev) - ORDER.indexOf(b.sev)));

    return { score, grade: gradeOf(score), counts, findings, hosts, tech: detectTech(input), https };
  }

  function detectTech(input) {
    const h = input.headers || {};
    const dom = input.dom;
    const g = input.globals || {};
    const tech = [];
    const push = (name, version, source) => {
      if (!name || tech.some((t) => t.name.toLowerCase() === name.toLowerCase())) return;
      tech.push({ name, version: version || '', source });
    };
    // « Apache/2.4.29 (Ubuntu), nginx » → Apache 2.4.29
    const product = (v) => { const m = /^\s*([^/,\s]+)(?:\/([^\s,;]+))?/.exec(v) || []; return [m[1], m[2]]; };

    if (h.server) push(...product(h.server), 'en-tête Server');
    if (h['x-powered-by']) push(...product(h['x-powered-by']), 'X-Powered-By');
    const edge = [
      ['cf-ray', 'Cloudflare'], ['x-vercel-id', 'Vercel'], ['x-amz-cf-id', 'Amazon CloudFront'],
      ['x-nf-request-id', 'Netlify'], ['x-github-request-id', 'GitHub'], ['x-shopify-stage', 'Shopify'],
      ['x-wix-request-id', 'Wix'], ['x-litespeed-cache', 'LiteSpeed Cache'], ['x-drupal-cache', 'Drupal'],
    ];
    for (const [hdr, name] of edge) if (h[hdr]) push(name, '', hdr);
    if (/varnish/i.test(h.via || '') || h['x-varnish']) push('Varnish', '', 'Via');
    if (/^cache-/.test(h['x-served-by'] || '')) push('Fastly', '', 'X-Served-By');

    if (dom) {
      if (dom.generator) push(dom.generator.replace(/\s[\d.]+.*$/, ''), (dom.generator.match(/\s([\d.]+)/) || [])[1], 'meta generator');
      if (dom.hints.wordpress) push('WordPress', '', 'wp-content');
      if (dom.hints.nextjs) push('Next.js', g.next, 'DOM');
      if (dom.hints.nuxt) push('Nuxt', '', 'DOM');
      if (dom.hints.angular) push('Angular', dom.hints.angular, 'ng-version');
      if (dom.hints.shopify) push('Shopify', '', 'DOM');
      if (dom.hints.drupal) push('Drupal', '', 'DOM');
      if (dom.serviceWorker) push('Service Worker', '', 'navigator');
    }
    const names = { jquery: 'jQuery', jqueryUI: 'jQuery UI', angularjs: 'AngularJS', react: 'React', vue: 'Vue', bootstrap: 'Bootstrap', lodash: 'Lodash', moment: 'Moment.js' };
    for (const [k, name] of Object.entries(names)) if (g[k]) push(name, g[k], 'variable globale');
    return tech;
  }

  const api = { analyze, detectTech, parseCsp, siteOf, isTracker, cmpVer, gradeOf };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaChecks = api;
})(globalThis);
