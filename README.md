# Goa Scan

Extension Chrome (Manifest V3) qui analyse la sécurité de la page web active et
affiche tout ce qu'elle révèle, en un clic : note de A à F, constats classés par
gravité, correctif pour chacun.

**100 % local.** Aucune donnée ne quitte le navigateur. Les seules requêtes émises
par l'extension vont vers le site analysé lui-même (`/.well-known/security.txt`, et
une requête de secours pour les en-têtes si besoin). Les liens « Aller plus loin »
(SSL Labs, VirusTotal…) n'envoient le domaine qu'au clic.

## Ce qui est analysé

| Onglet | Contrôles |
|---|---|
| **Transport** | HTTPS, redirection HTTP → HTTPS, HSTS (durée, includeSubDomains, preload), contenu mixte actif/passif (DOM + requêtes), WebSocket en clair |
| **En-têtes** | CSP (absente, Report-Only, `unsafe-inline`, `unsafe-eval`, jokers, `object-src`, `base-uri`, politiques multiples), anti-clickjacking (`frame-ancestors` / X-Frame-Options), `nosniff`, Referrer-Policy, Permissions-Policy, COOP, CORS `*`, X-XSS-Protection obsolète — plus la liste brute des en-têtes et des redirections |
| **Exposition** | version du serveur, `X-Powered-By` & co, `meta generator`, bibliothèques JS vulnérables (jQuery, jQuery UI, AngularJS, Bootstrap, Lodash, Moment), `security.txt` |
| **Cookies** | Secure, HttpOnly sur les cookies de session, SameSite — tableau complet, **sans jamais lire les valeurs** |
| **Contenu** | mot de passe sur page HTTP, formulaire posté en clair ou vers un autre site, scripts tiers sans SRI, iframes tierces sans sandbox, jetons (JWT…) dans localStorage/sessionStorage (noms de clés seulement), commentaires HTML sensibles, e-mails exposés, scripts inline et gestionnaires `on*` |
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
| `storage` | garder la capture réseau par onglet (`storage.session`, vidé à la fermeture du navigateur) |

## Limites

- **Certificat TLS** : Chrome ne l'expose pas aux extensions. Le lien SSL Labs le détaille.
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
manifest.json   déclaration MV3
background.js   service worker : capture en-têtes + requêtes par onglet
collector.js    fonctions injectées dans la page (DOM, variables globales)
checks.js       règles d'analyse, fonctions pures (testables sous Node)
popup.*         interface — popup et rapport complet (popup.html?tab=<id>)
```

```bash
node --test tests/*.test.js        # règles d'analyse + signature des polices
```

Test de bout en bout dans un vrai Chromium (page piège locale + sites réels, captures
dans `/tmp/goa-scan-shots/`) :

```bash
python3 tests/e2e/fixture.py &
npm i --no-save puppeteer-core && node tests/e2e/e2e.mjs
```
