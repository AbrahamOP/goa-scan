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
| **Certificat** | chaîne complète décodée (sujet, émetteur, validité, clé, signature, n° de série, empreinte SHA-256, SAN, niveau DV/OV/EV, SCT), expiration (expiré, < 14 j, < 30 j), nom de domaine couvert (jokers compris), auto-signé, signature SHA-1/MD5, clé RSA < 2048 / EC < 256, durée > 398 jours, intermédiaire expiré, wildcard ; connexion : protocole (TLS 1.0/1.1 obsolètes), échange de clés, chiffrement (RSA statique, CBC), conformité Certificate Transparency ; certificat refusé par Chrome (`ERR_CERT_*`) |
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
| `debugger` *(optionnelle)* | lire le certificat — demandée au premier clic sur *Activer l'analyse des certificats* |

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
manifest.json   déclaration MV3
background.js   service worker : capture en-têtes + requêtes par onglet
collector.js    fonctions injectées dans la page (DOM, variables globales)
cert.js         décodeur X.509 (DER) : sujet, émetteur, clé, SAN, politiques, SCT
checks.js       règles d'analyse, fonctions pures (testables sous Node)
popup.*         interface — popup et rapport complet (popup.html?tab=<id>)
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
```
