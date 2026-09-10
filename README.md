# Goa Scan

Extension Chrome (Manifest V3) qui analyse la sécurité de la page web active et
affiche tout ce qu'elle révèle, en un clic : note de A à F, constats classés par
gravité, correctif pour chacun.

**100 % local.** Aucune donnée ne quitte le navigateur. En analyse passive, les seules
requêtes émises vont vers le site analysé lui-même (`/.well-known/security.txt` et, au
besoin, une requête de secours pour les en-têtes). Le mode actif (opt-in) ajoute des
sondes vers ce même site et des requêtes DNS-over-HTTPS. Les liens « Aller plus loin »
(SSL Labs, VirusTotal…) n'envoient le domaine qu'au clic.

## Ce qui a été ajouté en 0.4.0

- **Clés et secrets dans le JavaScript** (onglet API) : scripts inline et scripts externes,
  y compris ceux chargés dynamiquement, relus sans cookies (80 scripts, 3 Mo chacun, 25 Mo
  en tout, traqueurs ignorés). Une trentaine de formats reconnus par préfixe : AWS, Stripe,
  GitHub, GitLab, OpenAI, Anthropic, Google OAuth, Slack, Discord, Telegram, SendGrid,
  Twilio, Mailgun, Mailchimp, npm, Hugging Face, Shopify, DigitalOcean, Mapbox, clés
  privées, identifiants dans une URL, JWT (`service_role` Supabase = critique).
- Les clés **publiques** par conception (Google Maps/Firebase `AIza`, Stripe `pk_`,
  Supabase `anon`) sont classées à part, en info. Les affectations suspectes
  (`client_secret: "…"`) sont « à vérifier ». Dans les scripts tiers, seuls les formats de
  secrets connus comptent.
- Les valeurs sont **masquées** dès la détection (`AKIAQ…XKD`), jamais stockées en clair.
  Aucun faux positif mesuré sur GitHub, Wikipédia, Stripe, Le Monde, leboncoin, Doctolib.

## Ce qui a été ajouté en 0.3.0

- **Onglet API** : chaque appel fetch, XHR ou WebSocket de la page, regroupé par endpoint
  (`/users/123` et `/users/456` → `/users/:id`), avec méthode, nombre d'appels, statuts,
  type de réponse et schéma d'authentification (Bearer, Basic, clé API). Seuls les *noms*
  des paramètres sont gardés, jamais les valeurs ni les jetons.
- Constats : jeton ou mot de passe dans l'URL (moyenne), clé d'API dans l'URL (info),
  HTTP Basic (faible), API en 5xx (info).
- **Mode actif** : recherche d'une spécification OpenAPI/Swagger publique sur 8 chemins
  courants (`/openapi.json`, `/v3/api-docs`…), confirmée par le contenu, et liste de ses routes.
- IP du serveur lue sur une connexion directe (0.2.1) : une page resservie par le cache
  affichait l'IP de sa première connexion.

## Ce qui a été ajouté en 0.2.0

- **Note automatique sur l'icône** et alerte si le **certificat d'un site change**
  entre deux visites (détection d'interception). Réglable, activé par défaut.
- **Base de vulnérabilités retire.js embarquée** (~75 composants, ~485 CVE) : détection
  par variable globale *et* par URL/nom de fichier de script, sans aucun appel externe.
- **Mode actif** (opt-in) : sondes de fichiers exposés (`/.git`, `/.env`, `/server-status`…)
  confirmées par le contenu, et audit DNS (CAA, DNSSEC, SPF, DMARC) via DoH.
- **Export Markdown et PDF imprimable**, en plus du JSON.

## Ce qui est analysé

| Onglet | Contrôles |
|---|---|
| **Certificat** | chaîne complète décodée (sujet, émetteur, validité, clé, signature, n° de série, empreinte SHA-256, SAN, niveau DV/OV/EV, SCT), expiration (expiré, < 14 j, < 30 j), nom de domaine couvert (jokers compris), auto-signé, signature SHA-1/MD5, clé RSA < 2048 / EC < 256, durée > 398 jours, intermédiaire expiré, wildcard ; connexion : protocole (TLS 1.0/1.1 obsolètes), échange de clés, chiffrement (RSA statique, CBC), conformité Certificate Transparency ; certificat refusé par Chrome (`ERR_CERT_*`) |
| **Transport** | HTTPS, redirection HTTP → HTTPS, HSTS (durée, includeSubDomains, preload), contenu mixte actif/passif (DOM + requêtes), WebSocket en clair |
| **En-têtes** | CSP (absente, Report-Only, `unsafe-inline`, `unsafe-eval`, jokers, `object-src`, `base-uri`, politiques multiples), anti-clickjacking (`frame-ancestors` / X-Frame-Options), `nosniff`, Referrer-Policy, Permissions-Policy, COOP, CORS `*`, X-XSS-Protection obsolète — plus la liste brute des en-têtes et des redirections |
| **Exposition** | version du serveur, `X-Powered-By` & co, `meta generator`, bibliothèques JS vulnérables (jQuery, jQuery UI, AngularJS, Bootstrap, Lodash, Moment), `security.txt` |
| **Cookies** | Secure, HttpOnly sur les cookies de session, SameSite — tableau complet, **sans jamais lire les valeurs** |
| **Contenu** | mot de passe sur page HTTP, formulaire posté en clair ou vers un autre site, scripts tiers sans SRI, iframes tierces sans sandbox, jetons (JWT…) dans localStorage/sessionStorage (noms de clés seulement), commentaires HTML sensibles, e-mails exposés, scripts inline et gestionnaires `on*` |
| **API** | appels fetch/XHR/WebSocket (méthode, endpoint regroupé en `:id`, statut, type de réponse, schéma d'auth), jetons ou clés dans l'URL, HTTP Basic, erreurs 5xx ; clés et secrets dans le code JavaScript (valeurs masquées) ; en mode actif, documentation OpenAPI/Swagger publique et ses routes |
| **Réseau** | requêtes émises par la page, domaines contactés, tiers, traqueurs connus, IP du serveur |

Technologies détectées : serveur, CDN (Cloudflare, CloudFront, Fastly, Vercel,
Netlify…), CMS (WordPress, Drupal, Shopify), frameworks (Next.js, Nuxt, Angular,
React, Vue) et bibliothèques avec leur version.

**Note** : 100 moins une pénalité par constat (critique 25, haute 12, moyenne 6,
faible 2, info 0), plafonnée à 40 pour une page en HTTP. A ≥ 90, B ≥ 75, C ≥ 60,
D ≥ 45, E ≥ 30, F en dessous.

## Installation

1. `chrome://extensions` → activer le **mode développeur**.
2. **Charger l'extension non empaquetée** → sélectionner ce dossier.
3. Épingler Goa Scan, ouvrir un site, cliquer sur l'icône.

**Rapport complet** ouvre la même analyse en pleine page ; **Exporter JSON**
télécharge le rapport (constats, en-têtes, cookies sans valeurs, domaines).

## Permissions

| Permission | Pourquoi |
|---|---|
| `webRequest` + `<all_urls>` | lire les en-têtes de réponse du document et compter les requêtes de la page (lecture seule, rien n'est bloqué ni modifié) |
| `scripting` | inspecter le DOM de l'onglet au moment de l'analyse |
| `cookies` | lire les attributs des cookies (Secure, HttpOnly, SameSite) |
| `storage` | capture réseau par onglet (`storage.session`) et empreintes de certificats épinglées (`storage.local`) |
| `debugger` *(optionnelle)* | lire le certificat — demandée au premier clic sur *Activer l'analyse des certificats* |

L'analyse automatique (badge) et le mode actif se règlent depuis les deux cases en haut du popup.

### Pourquoi `debugger` pour le certificat

Chrome n'expose pas le certificat aux extensions (pas d'équivalent au
`getSecurityInfo` de Firefox), et le domaine `Security` du protocole DevTools leur
est fermé. Goa Scan passe donc par le domaine `Network`, qui leur est ouvert :

1. `chrome.debugger.attach` sur l'onglet, le temps de l'analyse (~0,5 s) ;
2. `Network.getCertificate` → la chaîne en DER, décodée localement par `cert.js`
   (décodeur ASN.1 minimal, sans dépendance) ;
3. une requête sonde `HEAD` vers la même origine, sans cookies, dont on lit
   `securityDetails` (protocole, échange de clés, chiffrement, conformité CT) ;
4. détachement.

Pendant l'attachement, Chrome affiche un bandeau « Goa Scan a commencé le débogage
de ce navigateur » qui disparaît aussitôt. La permission est optionnelle : sans
elle, tout le reste de l'analyse fonctionne.

## Limites

- **Certificat refusé** (expiré, auto-signé…) : Chrome affiche sa page d'erreur, à laquelle
  rien ne peut s'attacher ; seul le code `ERR_CERT_*` est connu, la note tombe à F.
- **Paramètres TLS** : si la CSP de la page bloque la requête sonde (`connect-src`),
  seule la chaîne est affichée.
- **Page chargée avant l'extension** (ou restaurée du cache) : les requêtes n'ont pas
  été vues et les en-têtes viennent d'une requête de secours sans cookies. Le bouton
  *Recharger la page* corrige les deux.
- **Pages protégées** (Chrome Web Store, `chrome://`, visionneuse PDF) : contenu non inspectable.
- Le « site » d'un domaine (tiers ou non) est estimé sans la Public Suffix List complète.
- Les applications monopage qui changent d'URL sans recharger gardent la capture du
  document initial.

## Développement

Vanilla JS, aucune dépendance, aucun build.

```
manifest.json        déclaration MV3
background.js        service worker : capture réseau, analyse auto + badge, épinglage cert
collector.js         fonctions injectées dans la page (DOM, variables globales)
cert.js              décodeur X.509 (DER) : sujet, émetteur, clé, SAN, politiques, SCT
vulndb.js            détection retire.js (version → CVE), fonctions pures
vendor/vulndb-data.js base retire.js embarquée (générée par tools/build-vulndb.mjs)
probes.js            mode actif : sondes de fichiers + DNS-over-HTTPS
export.js            rapport Markdown + HTML imprimable, fonctions pures
checks.js            règles d'analyse, fonctions pures (testables sous Node)
popup.*              interface — popup et rapport complet (popup.html?tab=<id>)
```

Régénérer la base de vulnérabilités :

```bash
node tools/build-vulndb.mjs   # refetch retire.js → vendor/vulndb-data.js
```

```bash
node --test tests/*.test.js        # règles, décodeur X.509, signature des polices
```

Les certificats de test (`tests/fixtures/*.b64`) sont générés par openssl (RSA 2048,
EC P-256 wildcard, RSA 1024 SHA-1) plus la chaîne réelle de github.com.

Test de bout en bout dans un vrai Chromium (page piège locale + sites réels, captures
dans `/tmp/goa-scan-shots/`) :

```bash
python3 tests/e2e/fixture.py &
npm i --no-save puppeteer-core && node tests/e2e/e2e.mjs
node tests/e2e/e2e-cert.mjs   # copie avec « debugger » obligatoire : github.com + badssl.com
node tests/e2e/e2e-ip.mjs     # IP juste après un rechargement depuis le cache et un retour arrière
python3 tests/e2e/fixture-active.py &
node tests/e2e/e2e-api.mjs    # onglet API : appels capturés, Bearer/Basic, secrets dans l'URL, doc OpenAPI
```
