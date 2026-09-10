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

  const CERT_ERRORS = {
    ERR_CERT_DATE_INVALID: 'certificat expiré ou pas encore valide',
    ERR_CERT_COMMON_NAME_INVALID: 'le certificat ne couvre pas ce nom de domaine',
    ERR_CERT_AUTHORITY_INVALID: 'autorité inconnue ou certificat auto-signé',
    ERR_CERT_REVOKED: 'certificat révoqué par son autorité',
    ERR_CERT_WEAK_SIGNATURE_ALGORITHM: 'signature faible (SHA-1 ou MD5)',
    ERR_CERT_WEAK_KEY: 'clé trop courte',
    ERR_CERT_VALIDITY_TOO_LONG: 'durée de validité trop longue',
    ERR_CERT_SYMANTEC_LEGACY: 'ancienne PKI Symantec, retirée des navigateurs',
    ERR_CERTIFICATE_TRANSPARENCY_REQUIRED: 'certificat absent des journaux Certificate Transparency',
    ERR_SSL_VERSION_OR_CIPHER_MISMATCH: 'protocole ou chiffrement trop ancien',
    ERR_SSL_PROTOCOL_ERROR: 'erreur de protocole TLS',
    ERR_SSL_OBSOLETE_VERSION: 'version de TLS obsolète',
  };

  const isIp = (h) => /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.startsWith('[');

  function siteOf(host) {
    const h = String(host).toLowerCase().replace(/\.$/, '');
    if (isIp(h)) return h;
    const parts = h.split('.');
    if (parts.length <= 2) return h;
    return MULTI_SUFFIXES.has(parts.slice(-2).join('.')) ? parts.slice(-3).join('.') : parts.slice(-2).join('.');
  }

  const isTracker = (host) => TRACKER_HOSTS.has(host) || TRACKER_SITES.has(siteOf(host));

  // ── Appels d'API ─────────────────────────────────────────────
  // Noms de paramètres qui portent un secret, et ceux qui portent une clé d'API (souvent publique).
  const SECRET_PARAM = /^(access[_-]?token|id[_-]?token|refresh[_-]?token|token|auth|authorization|secret|client[_-]?secret|password|passwd|pwd|pass|session(id)?|sid|jwt|bearer)$/i;
  const KEY_PARAM = /^(api[_-]?key|apikey|key|app[_-]?key|access[_-]?key|x-api-key)$/i;

  // Regroupe /users/123 et /users/456 sous /users/:id.
  function normSegment(s) {
    if (/^\d+$/.test(s)) return ':id';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s)) return ':uuid';
    if (/^[0-9a-f]{16,}$/i.test(s)) return ':hash';
    if (s.length > 32 && /^[\w-]+$/.test(s)) return ':token';
    return s;
  }

  // Endpoint d'un appel : méthode + URL sans valeurs. Les valeurs ne servent qu'à repérer un
  // secret (longueur, JWT) et ne sont jamais renvoyées.
  function apiEndpoint(method, url) {
    const u = url instanceof URL ? url : new URL(url);
    const path = u.pathname.split('/').map(normSegment).join('/').slice(0, 160) || '/';
    const params = [], secrets = [], keys = [];
    const push = (arr, v) => { if (!arr.includes(v) && arr.length < 12) arr.push(v); };
    for (const [k, v] of u.searchParams) {
      const name = k.slice(0, 40);
      push(params, name);
      if (v.length >= 8 && (SECRET_PARAM.test(k) || /^eyJ[\w-]+\.[\w-]+\./.test(v))) push(secrets, name);
      else if (v.length >= 8 && KEY_PARAM.test(k)) push(keys, name);
    }
    const m = String(method || 'GET').toUpperCase();
    const base = `${u.protocol}//${u.host}${path}`;
    return { key: `${m} ${base}`, method: m, url: base, params, secrets, keys };
  }

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

  // Un joker ne couvre qu'une seule étiquette : *.exemple.fr couvre a.exemple.fr, pas a.b.exemple.fr.
  function hostMatches(host, names) {
    const h = String(host).toLowerCase().replace(/^\[|\]$/g, '');
    return names.some((raw) => {
      const n = String(raw).toLowerCase();
      if (!n.startsWith('*.')) return n === h;
      const rest = n.slice(1);
      return h.endsWith(rest) && h.length > rest.length && !h.slice(0, -rest.length).includes('.');
    });
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

    // ── Certificat ────────────────────────────────────────────
    const tls = input.tls;
    const navError = /CERT|SSL/.test(input.navError || '') ? input.navError : null;
    if (navError) {
      const reason = CERT_ERRORS[navError.replace(/^net::/, '')] || 'la connexion sécurisée a échoué';
      add({
        cat: 'certificate', id: 'cert-error', sev: 'critical', title: 'Certificat refusé par Chrome',
        detail: `Motif : ${reason}. Le visiteur voit une page d’avertissement au lieu du site ; le reste de l’analyse est impossible.`,
        fix: 'Corriger le certificat côté serveur (renouvellement, noms couverts, chaîne complète, autorité reconnue).',
        items: [navError],
      });
    }
    if (https && tls?.status === 'ok') {
      const now = input.now ?? Date.now();
      const day = (t) => new Date(t).toISOString().slice(0, 10);
      const leaf = tls.chain[0];
      if (leaf) {
        const days = Math.floor((leaf.notAfter - now) / 86400000);
        if (now > leaf.notAfter) {
          add({
            cat: 'certificate', id: 'cert-expiry', sev: 'critical', title: `Certificat expiré le ${day(leaf.notAfter)}`,
            fix: 'Renouveler le certificat et vérifier le renouvellement automatique (certbot, Traefik…).',
          });
        } else if (now < leaf.notBefore) {
          add({ cat: 'certificate', id: 'cert-expiry', sev: 'critical', title: `Certificat pas encore valide (à partir du ${day(leaf.notBefore)})`, fix: 'Vérifier l’horloge du serveur qui l’a émis.' });
        } else if (days < 14) {
          add({
            cat: 'certificate', id: 'cert-expiry', sev: 'high', title: `Certificat expirant dans ${days} jour${days > 1 ? 's' : ''}`,
            fix: 'Renouveler maintenant : le renouvellement automatique semble en échec.',
          });
        } else if (days < 30) {
          add({
            cat: 'certificate', id: 'cert-expiry', sev: 'low', title: `Certificat expirant dans ${days} jours`,
            detail: 'Les autorités automatisées renouvellent en général 30 jours avant l’échéance.',
            fix: 'Vérifier que le renouvellement automatique tourne.',
          });
        } else {
          add({ cat: 'certificate', id: 'cert-expiry', ok: true, title: `Certificat valide jusqu’au ${day(leaf.notAfter)} (${days} jours)` });
        }

        const names = leaf.san.length ? leaf.san : [leaf.subject.cn];
        if (hostMatches(page.hostname, names)) add({ cat: 'certificate', id: 'cert-name', ok: true, title: 'Le certificat couvre ce domaine' });
        else {
          add({
            cat: 'certificate', id: 'cert-name', sev: 'critical', title: 'Le certificat ne couvre pas ce domaine',
            detail: `${page.hostname} n’apparaît pas dans les noms du certificat.`,
            fix: 'Émettre un certificat qui inclut ce nom dans ses Subject Alternative Names.',
            items: names.slice(0, 12),
          });
        }

        if (leaf.selfSigned && tls.chain.length === 1) {
          add({
            cat: 'certificate', id: 'cert-self', sev: 'high', title: 'Certificat auto-signé',
            detail: 'Aucune autorité reconnue ne l’a émis : impossible de distinguer ce serveur d’un imposteur.',
            fix: 'Utiliser un certificat d’une autorité publique (Let’s Encrypt) ou d’une PKI interne déployée sur les postes.',
          });
        }

        if (/md5|sha1/i.test(leaf.sigAlg)) {
          add({
            cat: 'certificate', id: 'cert-sig', sev: 'high', title: 'Signature du certificat faible',
            detail: 'MD5 et SHA-1 permettent de forger des collisions : un certificat frauduleux peut hériter de la signature.',
            fix: 'Réémettre le certificat signé en SHA-256 ou plus.',
            items: [leaf.sigAlg],
          });
        }

        const k = leaf.key;
        const weakKey = (k.type === 'RSA' && k.bits < 2048) || (k.type === 'EC' && k.bits < 256);
        const keyLabel = k.type === 'EC' ? `EC ${k.curve}` : `${k.type} ${k.bits} bits`;
        if (weakKey) {
          add({
            cat: 'certificate', id: 'cert-key', sev: 'high', title: `Clé trop courte (${keyLabel})`,
            fix: 'Générer une clé RSA 2048 bits minimum, ou mieux ECDSA P-256.',
          });
        } else {
          add({ cat: 'certificate', id: 'cert-key', ok: true, title: `Clé ${keyLabel}, signature ${leaf.sigAlg}` });
        }

        if ((leaf.notAfter - leaf.notBefore) / 86400000 > 398) {
          add({
            cat: 'certificate', id: 'cert-lifetime', sev: 'low', title: 'Durée de validité supérieure à 398 jours',
            detail: 'Les navigateurs refusent les certificats publics de plus de 398 jours ; toléré seulement pour une PKI interne.',
            fix: 'Réduire la durée de vie et automatiser le renouvellement.',
          });
        }
        if (leaf.san.some((n) => n.startsWith('*.'))) {
          add({
            cat: 'certificate', id: 'cert-wildcard', title: 'Certificat wildcard',
            detail: 'La même clé couvre tous les sous-domaines : compromise sur un seul serveur, elle les expose tous.',
          });
        }
        const pin = input.certPin;
        if (pin?.changed && !pin.benign) {
          add({
            cat: 'certificate', id: 'cert-pin', sev: 'high', title: 'Le certificat a changé depuis la dernière visite',
            detail: 'Nouvelle empreinte, émetteur ou clé différents d’un simple renouvellement. Sur un réseau non maîtrisé (Wi-Fi public, proxy d’entreprise), cela peut trahir une interception ; sinon, c’est un changement d’autorité à confirmer.',
            fix: 'Vérifier que ce changement est attendu ; dans le doute, ne rien saisir de sensible et recharger depuis un autre réseau.',
            items: pin.previous ? [`Ancien émetteur : ${pin.previous.issuer || '—'}`, `Vu le ${new Date(pin.previous.seenAt).toISOString().slice(0, 10)}`] : undefined,
          });
        } else if (pin?.changed && pin.benign) {
          add({ cat: 'certificate', id: 'cert-pin', title: 'Certificat renouvelé depuis la dernière visite', detail: 'Même autorité, expiration repoussée : renouvellement normal.' });
        } else if (pin && !pin.changed && tls.chain.length) {
          add({ cat: 'certificate', id: 'cert-pin', ok: true, title: 'Certificat identique à la dernière visite' });
        }

        const staleCa = tls.chain.slice(1).filter((c) => now > c.notAfter);
        if (staleCa.length) {
          add({
            cat: 'certificate', id: 'cert-chain', sev: 'high', title: 'Certificat intermédiaire expiré',
            fix: 'Mettre à jour la chaîne servie par le serveur.',
            items: staleCa.map((c) => c.subject.cn || c.subject.dn),
          });
        }
      }

      if (/^TLS 1(\.[01])?$/.test(tls.protocol)) {
        add({
          cat: 'certificate', id: 'tls-protocol', sev: 'high', title: `Protocole obsolète (${tls.protocol})`,
          fix: 'N’accepter que TLS 1.2 et TLS 1.3.',
        });
      } else if (tls.protocol) {
        add({ cat: 'certificate', id: 'tls-protocol', ok: true, title: `Protocole ${tls.protocol}` });
      }
      // Échange RSA statique = pas de confidentialité persistante ; hors GCM/ChaCha20 = CBC, sans AEAD.
      const oldKex = tls.keyExchange === 'RSA';
      const oldCipher = !!tls.cipher && !/GCM|CHACHA20|POLY1305/i.test(tls.cipher);
      if (oldKex || oldCipher) {
        add({
          cat: 'certificate', id: 'tls-cipher', sev: 'medium', title: 'Suite de chiffrement obsolète',
          detail: oldKex
            ? 'Échange de clés RSA statique : une clé privée volée plus tard déchiffre tout le trafic enregistré.'
            : 'Chiffrement en mode CBC, sans AEAD : historiquement exposé aux attaques par oracle de padding.',
          fix: 'Privilégier ECDHE avec AES-GCM ou ChaCha20-Poly1305.',
          items: [tls.keyExchange, tls.cipher].filter(Boolean),
        });
      }
      if (tls.ct === 'not-compliant') {
        add({
          cat: 'certificate', id: 'tls-ct', sev: 'medium', title: 'Certificat non conforme à Certificate Transparency',
          detail: 'Le certificat n’a pas été publié dans assez de journaux publics : un certificat frauduleux passerait inaperçu.',
          fix: 'Réémettre le certificat auprès d’une autorité qui journalise (toutes les autorités publiques le font).',
        });
      }
    } else if (https && tls?.status === 'error' && !navError) {
      add({ cat: 'certificate', id: 'cert-unavailable', title: 'Certificat non analysé', detail: tls.error || '' });
    }

    // ── En-têtes de sécurité ──────────────────────────────────
    if (!h && !navError) {
      add({
        cat: 'headers', id: 'no-headers', title: 'En-têtes de réponse indisponibles',
        detail: 'Ni la capture au chargement ni la requête de secours n’ont abouti. Rechargez la page puis relancez l’analyse.',
      });
    } else if (h) {
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

    // Bibliothèques vulnérables : résultats de la base retire.js, calculés par l'appelant.
    for (const lib of input.vulns || []) {
      const cves = lib.cves.slice(0, 6);
      const more = lib.count - 1;
      add({
        cat: 'exposure', id: `lib-${lib.component}`, sev: lib.sev,
        title: `${lib.component} ${lib.version} — ${lib.count} vulnérabilité${lib.count > 1 ? 's' : ''} connue${lib.count > 1 ? 's' : ''}`,
        detail: (lib.summaries[0] || 'Version affectée par des vulnérabilités publiées.') + (more > 0 ? ` (+${more} autre${more > 1 ? 's' : ''})` : '') + ` — détecté via ${lib.source}.`,
        fix: 'Mettre à jour vers la dernière version corrigée.',
        items: cves.length ? cves : undefined,
      });
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

    // ── Mode actif (sondes opt-in) ────────────────────────────
    if (input.probes) {
      const { files = [], dns } = input.probes;
      for (const f of files) {
        if (f.sev === 'ok') { add({ cat: 'active', id: `file-${f.path}`, ok: true, title: f.title }); continue; }
        if (f.sev === 'info') continue;
        add({
          cat: 'active', id: `file-${f.path}`, sev: f.sev, title: f.title,
          detail: `Accessible publiquement sur ${f.path} (HTTP ${f.status}). Un fichier de ce type expose du code source, des identifiants ou la structure interne du site.`,
          fix: `Bloquer l’accès à ${f.path} au niveau du serveur ou retirer le fichier de la racine web.`,
          items: [`${f.path} → ${f.evidence}`],
        });
      }
      if (dns) {
        if (dns.dmarc) add({ cat: 'active', id: 'dns-dmarc', ok: true, title: 'DMARC publié' });
        else add({ cat: 'active', id: 'dns-dmarc', sev: 'low', title: 'Pas d’enregistrement DMARC', detail: `Aucun _dmarc.${dns.domain} : le domaine est plus facilement usurpable pour du phishing.`, fix: 'Publier un TXT sur _dmarc, au moins v=DMARC1; p=none; puis durcir vers quarantine/reject.' });
        if (dns.spf) add({ cat: 'active', id: 'dns-spf', ok: true, title: 'SPF publié' });
        else add({ cat: 'active', id: 'dns-spf', sev: 'low', title: 'Pas d’enregistrement SPF', detail: 'Aucun TXT v=spf1 : rien ne dit quels serveurs peuvent envoyer du courrier pour ce domaine.', fix: 'Publier un TXT v=spf1 … -all.' });
        if (dns.caa) add({ cat: 'active', id: 'dns-caa', ok: true, title: 'CAA publié' });
        else add({ cat: 'active', id: 'dns-caa', sev: 'low', title: 'Pas d’enregistrement CAA', detail: 'Sans CAA, n’importe quelle autorité peut émettre un certificat pour ce domaine.', fix: 'Publier un CAA limitant l’émission aux autorités utilisées (ex. letsencrypt.org).' });
        if (dns.dnssec) add({ cat: 'active', id: 'dns-dnssec', ok: true, title: 'DNSSEC actif' });
        else add({ cat: 'active', id: 'dns-dnssec', sev: 'low', title: 'DNSSEC inactif', detail: 'Les réponses DNS ne sont pas signées : elles peuvent être falsifiées (empoisonnement de cache).', fix: 'Activer DNSSEC chez l’hébergeur DNS et publier l’enregistrement DS chez le registrar.' });
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

    // ── API ───────────────────────────────────────────────────
    const apis = Object.values(net?.apis || {}).map((a) => {
      const host = hostOf(a.url);
      return { ...a, host, third: siteOf(host) !== pageSite, tracker: isTracker(host), graphql: /\/graphql\b/i.test(a.url) };
    }).sort((a, b) => (a.third - b.third) || (b.n - a.n));
    const line = (a, names) => `${a.ws ? 'WS' : a.method} ${a.url}${names ? ` ?${names.join(', ')}` : ''}`;

    const withSecrets = apis.filter((a) => a.secrets?.length);
    if (withSecrets.length) {
      add({
        cat: 'api', id: 'api-url-secrets', sev: 'medium', title: `Jetons ou mots de passe dans l’URL d’appels API (${withSecrets.length})`,
        detail: 'Une URL finit dans l’historique, les journaux des serveurs et des proxys, et parfois dans l’en-tête Referer. Goa Scan n’a gardé que le nom des paramètres.',
        fix: 'Passer le jeton dans l’en-tête Authorization, ou dans le corps d’une requête POST.',
        items: withSecrets.map((a) => line(a, a.secrets)).slice(0, 15),
      });
    } else if (apis.length) {
      add({ cat: 'api', id: 'api-url-secrets', ok: true, title: 'Aucun jeton dans l’URL des appels API' });
    }
    const withKeys = apis.filter((a) => a.keys?.length);
    if (withKeys.length) {
      add({
        cat: 'api', id: 'api-url-keys', title: `Clés d’API visibles dans l’URL (${withKeys.length})`,
        detail: 'Normal pour une clé publique restreinte par domaine (Google Maps, recherche Algolia…). Une clé sans restriction est réutilisable par n’importe qui.',
        items: withKeys.map((a) => line(a, a.keys)).slice(0, 15),
      });
    }
    const basic = apis.filter((a) => /^basic$/i.test(a.auth || ''));
    if (basic.length) {
      add({
        cat: 'api', id: 'api-basic', sev: 'low', title: 'Authentification HTTP Basic sur des API',
        detail: 'L’identifiant et le mot de passe partent à chaque requête, simplement encodés en base64, et restent accessibles au JavaScript de la page.',
        fix: 'Échanger les identifiants contre un jeton à durée de vie courte (OAuth 2, session HttpOnly).',
        items: basic.map((a) => line(a)).slice(0, 15),
      });
    }
    const failing5xx = apis.filter((a) => a.statuses?.some((s) => s >= 500));
    if (failing5xx.length) {
      add({
        cat: 'api', id: 'api-5xx', title: `API en erreur serveur (${failing5xx.length})`,
        detail: 'Une erreur 5xx trahit parfois une trace de pile ou une version dans la réponse.',
        items: failing5xx.map((a) => `${line(a)} → ${a.statuses.join(', ')}`).slice(0, 15),
      });
    }
    // Clés et secrets dans le JavaScript (valeurs déjà masquées par secrets.js).
    const js = input.jsSecrets;
    if (js) {
      const where = (x) => `${x.value} — ${x.source}${x.line > 1 ? `:${x.line}` : ''}${x.third ? ' (tiers)' : ''}`;
      const groups = new Map();
      for (const x of js.hits.filter((y) => !y.public && y.sev !== 'info')) {
        if (!groups.has(x.id)) groups.set(x.id, []);
        groups.get(x.id).push(x);
      }
      for (const [id, xs] of groups) {
        add({
          cat: 'api', id: `js-${id}`, sev: xs[0].sev, title: `${xs[0].name} dans le JavaScript${xs.length > 1 ? ` (${xs.length})` : ''}`,
          detail: 'Tout ce qui est servi au navigateur est public : n’importe quel visiteur peut lire cette clé dans le code source et s’en servir.',
          fix: 'Révoquer la clé tout de suite, puis la sortir du code client : les appels qui en ont besoin passent par le serveur.',
          items: xs.map(where).slice(0, 15),
        });
      }
      const toCheck = js.hits.filter((x) => !x.public && x.sev === 'info');
      if (toCheck.length) {
        add({
          cat: 'api', id: 'js-to-check', title: `Secrets potentiels dans le JavaScript (${toCheck.length})`,
          detail: 'Chaînes qui ressemblent à un secret (nom de variable évocateur, JWT codé en dur) sans format connu : à vérifier à la main.',
          items: toCheck.map((x) => `${x.name} · ${where(x)}`).slice(0, 15),
        });
      }
      const pub = js.hits.filter((x) => x.public);
      if (pub.length) {
        add({
          cat: 'api', id: 'js-public-keys', title: `Clés publiques dans le JavaScript (${pub.length})`,
          detail: 'Clés faites pour être servies au navigateur (Google Maps/Firebase, Stripe pk_, Supabase anon). Sans risque si elles sont restreintes : domaines autorisés, quotas, règles d’accès côté serveur.',
          items: pub.map((x) => `${x.name} · ${where(x)}`).slice(0, 15),
        });
      }
      if (!groups.size) {
        add({ cat: 'api', id: 'js-secrets', ok: true, title: `Aucun secret reconnu dans le JavaScript (${js.scanned.inline + js.scanned.external} scripts)` });
      }
    }

    const doc = input.probes?.apiDoc;
    if (doc) {
      add({
        cat: 'api', id: 'api-doc', sev: 'low', title: `Documentation d’API publique (${doc.kind} ${doc.version})`,
        detail: `${doc.path} décrit ${doc.total} route(s) : la surface d’attaque se lit directement. Normal pour une API publique, à éviter pour une API interne.`,
        fix: 'Protéger la documentation (authentification, réseau interne) ou ne pas la publier en production.',
        items: [doc.path],
      });
    }

    // ── Score ─────────────────────────────────────────────────
    let score = 100 - findings.filter((f) => !f.ok).reduce((s, f) => s + WEIGHT[f.sev], 0);
    if (!https) score = Math.min(score, 40);
    if (navError) score = Math.min(score, 20);
    score = Math.max(0, score);

    const counts = Object.fromEntries(ORDER.map((s) => [s, findings.filter((f) => !f.ok && f.sev === s).length]));
    findings.sort((a, b) => (a.ok - b.ok) || (ORDER.indexOf(a.sev) - ORDER.indexOf(b.sev)));

    return { score, grade: gradeOf(score), counts, findings, hosts, apis, tech: detectTech(input), https };
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

  const api = { analyze, detectTech, parseCsp, siteOf, isTracker, cmpVer, gradeOf, hostMatches, apiEndpoint };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.GoaChecks = api;
})(globalThis);
