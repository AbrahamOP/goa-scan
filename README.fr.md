<p align="center">
  <img src="store/banner.png" alt="Goa Scan — extension Chrome qui note de A à F la sécurité de la page consultée" width="100%">
</p>

<p align="center">
  <a href="https://github.com/AbrahamOP/goa-scan/actions/workflows/ci.yml"><img src="https://github.com/AbrahamOP/goa-scan/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/Manifest-V3-1D9E75" alt="Manifest V3">
  <img src="https://img.shields.io/badge/Chrome-116%2B-534AB7" alt="Chrome 116+">
  <img src="https://img.shields.io/badge/d%C3%A9pendances-0-1D9E75" alt="Zéro dépendance">
  <img src="https://img.shields.io/badge/t%C3%A9l%C3%A9m%C3%A9trie-aucune-1D9E75" alt="Aucune télémétrie">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-534AB7" alt="Licence MIT"></a>
</p>

<p align="center">
  <a href="README.md">English</a> · <b>Français</b>
</p>

**Goa Scan** est une extension de navigateur qui audite la sécurité de n'importe quelle
page web en un clic. Elle lit le certificat TLS, les en-têtes de sécurité, les cookies,
les appels d'API et le JavaScript que la page embarque, puis lui donne une note de
**A à F**, chaque constat classé par gravité avec son correctif.

Tout se passe **dans votre navigateur**. Pas de compte, pas de serveur, pas de mouchard.

- **Développeurs** : vérifier son propre site avant une mise en production — CSP absente,
  cookies mal protégés, secret oublié dans un bundle.
- **Chasseurs de bug bounty et pentesteurs** : une reconnaissance passive offerte —
  endpoints, paramètres et clés cachés dans le JavaScript, bibliothèques vulnérables,
  documentation d'API exposée.
- **Utilisateurs curieux** : voir d'un coup d'œil si le site auquel on s'apprête à faire
  confiance est bien configuré, et être prévenu si son certificat change brusquement.

<p align="center">
  <img src="store/screenshots/1-synthese.png" alt="Onglet Synthèse : note F, constats classés par gravité" width="49%">
  <img src="store/screenshots/2-certificat.png" alt="Onglet Certificat : chaîne décodée, TLS 1.3, échange de clés et chiffrement" width="49%">
  <img src="store/screenshots/3-code-js.png" alt="Onglet Code JS : clés AWS, Stripe et Supabase trouvées dans les scripts, valeurs masquées" width="49%">
  <img src="store/screenshots/4-api.png" alt="Onglet API : appels fetch et XHR regroupés par endpoint avec schéma d'authentification" width="49%">
</p>

## Fonctionnalités

| | Ce que Goa Scan contrôle |
|---|---|
| 🔒 **Certificat TLS** | Chaîne complète décodée localement (sujet, émetteur, validité, clé, signature, empreinte SHA-256, SAN, DV/OV/EV, SCT). Expiration, nom de domaine couvert (jokers compris), auto-signé, SHA-1/MD5, clés RSA/EC faibles, durée > 398 jours. Connexion : version TLS, échange de clés, chiffrement, Certificate Transparency. **Alerte si le certificat d'un site change** entre deux visites sans ressembler à un renouvellement. |
| 🧱 **En-têtes de sécurité** | Content-Security-Policy (absente, Report-Only, `unsafe-inline`, `unsafe-eval`, jokers, `object-src`, `base-uri`), HSTS (durée, includeSubDomains, preload), anti-clickjacking (`frame-ancestors` / X-Frame-Options), `nosniff`, Referrer-Policy, Permissions-Policy, COOP, CORS `*`. En-têtes bruts et chaîne de redirections inclus. |
| 🍪 **Cookies** | `Secure`, `HttpOnly` sur les cookies de session, `SameSite` — **les valeurs ne sont jamais lues**. |
| 📄 **Contenu** | Contenu mixte, mot de passe sur page HTTP, formulaire posté en clair ou vers un autre site, scripts tiers sans SRI, iframes sans sandbox, jetons dans localStorage/sessionStorage, commentaires HTML sensibles, e-mails exposés. |
| 🔌 **Appels d'API** | Chaque appel fetch, XHR et WebSocket de la page, regroupé par endpoint (`/users/123` → `/users/:id`), avec méthode, statut, type de réponse et schéma d'authentification (Bearer, Basic, clé API). Jetons ou mots de passe dans l'URL, erreurs 5xx. |
| 🔑 **Secrets dans le JavaScript** | Une trentaine de formats de clés repérés dans les scripts inline et externes, chunks chargés à la demande compris : AWS, Stripe, GitHub, GitLab, OpenAI, Anthropic, Google, Slack, Discord, Twilio, SendGrid, npm, Hugging Face, clés privées, JWT (`service_role` Supabase = critique). Les clés publiques par conception sont classées à part. **Valeurs masquées dès la détection.** |
| 🧭 **Endpoints et paramètres dans le JS** | URL, chemins et gabarits (`` `/api/x/${id}` ``) cités dans le code, recoupés avec les appels réellement émis — le reste est la surface que la navigation n'a pas touchée. Noms de paramètres de requête et de formulaire, triés par fréquence. |
| 📦 **Bibliothèques vulnérables** | Base [retire.js](https://github.com/RetireJS/retire.js) embarquée (~75 composants, ~485 CVE), par variable globale et par URL de script. Aucun appel réseau. |
| 🛰️ **Réseau et technologies** | Requêtes, domaines tiers, traqueurs connus, IP du serveur. Détection du serveur, CDN, CMS et frameworks avec leur version. |
| 🧪 **Mode actif** *(opt-in)* | Fichiers exposés (`/.git`, `/.env`, `/server-status`…) confirmés par le contenu, documentation OpenAPI/Swagger publique et ses routes, audit DNS (CAA, DNSSEC, SPF, DMARC) en DNS-over-HTTPS. |

En plus : **note automatique sur l'icône**, rapport en pleine page, et **export Markdown,
HTML imprimable/PDF ou JSON**.

## Confidentialité

Goa Scan n'a pas de serveur. En analyse passive, les seules requêtes émises vont **vers
le site analysé** (`/.well-known/security.txt`, une requête de secours pour les en-têtes,
la relecture de ses scripts sans cookies). Rien n'est envoyé à l'auteur ni à un tiers.

- Les valeurs des cookies et les secrets trouvés sont masqués, jamais exportés en clair.
- Les liens « Aller plus loin » (SSL Labs, securityheaders.com, VirusTotal…) n'envoient
  le domaine **qu'au clic**.
- Le mode actif est désactivé par défaut ; activé, il sonde le site analysé et interroge
  ses enregistrements DNS publics via le DoH de Cloudflare.

Politique complète : [PRIVACY.md](PRIVACY.md).

## Installation

**Depuis les sources** (en attendant la fiche Chrome Web Store) :

1. Télécharger ou cloner ce dépôt.
2. Ouvrir `chrome://extensions` et activer le **mode développeur**.
3. **Charger l'extension non empaquetée** → sélectionner le dossier.
4. Épingler Goa Scan, ouvrir un site, cliquer sur l'icône.

Fonctionne sur Chrome, Edge, Brave, Opera et les autres navigateurs Chromium (116+).

## Calcul de la note

Note = 100 moins une pénalité par constat : critique 25, haute 12, moyenne 6, faible 2,
info 0. Une page servie en HTTP est plafonnée à 40.
**A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 45 · **E** ≥ 30 · **F** en dessous.

## Permissions

| Permission | Pourquoi |
|---|---|
| `webRequest` + `<all_urls>` | Lire les en-têtes de réponse de la page et lister ses requêtes. Lecture seule : rien n'est bloqué ni modifié. |
| `scripting` | Inspecter le DOM de l'onglet au moment de l'analyse. |
| `cookies` | Lire les attributs des cookies (`Secure`, `HttpOnly`, `SameSite`), pas leur valeur. |
| `storage` | Capture réseau par onglet (`storage.session`) et empreintes de certificats épinglées (`storage.local`). |
| `debugger` *(optionnelle)* | Seul moyen par lequel Chrome expose le certificat TLS à une extension. Demandée au premier usage. |

<details>
<summary><b>Pourquoi la permission <code>debugger</code> pour le certificat ?</b></summary>

Chrome n'expose pas le certificat aux extensions (pas d'équivalent au `getSecurityInfo`
de Firefox), et le domaine `Security` du protocole DevTools leur est fermé. Goa Scan passe
donc par le domaine `Network`, qui leur est ouvert :

1. `chrome.debugger.attach` sur l'onglet, le temps de l'analyse (~0,5 s) ;
2. `Network.getCertificate` → la chaîne en DER, décodée localement par `cert.js`
   (décodeur ASN.1 minimal, sans dépendance) ;
3. une requête sonde `HEAD` vers la même origine, sans cookies, dont on lit
   `securityDetails` (protocole, échange de clés, chiffrement, conformité CT) ;
4. détachement.

Chrome affiche brièvement un bandeau « Goa Scan a commencé le débogage de ce
navigateur ». Sans cette permission, tout le reste de l'analyse fonctionne.
</details>

## FAQ

**Est-ce un scanner de vulnérabilités ?** Par défaut c'est un analyseur passif : il lit
ce que la page envoie déjà à votre navigateur. Le mode actif émet quelques requêtes vers
le site consulté. À n'utiliser que sur des sites qui vous appartiennent ou que vous êtes
autorisé à tester.

**Est-ce que ça ralentit la navigation ?** La note automatique est calculée une fois par
chargement, page terminée. Elle se désactive depuis le popup.

**Pourquoi pas de version Firefox ?** Le certificat et la capture des requêtes reposent
sur des API Chromium. Un portage est possible ; les contributions sont bienvenues.

## Limites

- **Certificat refusé** (expiré, auto-signé…) : Chrome affiche sa page d'erreur, à
  laquelle rien ne peut s'attacher ; seul le code `ERR_CERT_*` est connu, la note tombe à F.
- **Paramètres TLS** : si la CSP de la page bloque la requête sonde (`connect-src`), seule
  la chaîne est affichée.
- **Page chargée avant l'extension** ou restaurée du cache : les requêtes n'ont pas été
  vues. Le bouton *Recharger* corrige.
- **Pages protégées** (`chrome://`, Chrome Web Store, visionneuse PDF) : non inspectables.
- Les applications monopage qui changent d'URL sans recharger gardent la capture du
  document initial.

## Développement

Vanilla JS, aucune dépendance, aucun build.

```
manifest.json         déclaration MV3
background.js         service worker : capture réseau, note auto sur l'icône, épinglage cert
collector.js          fonctions injectées dans la page (DOM, variables globales)
cert.js               décodeur X.509 (DER) : sujet, émetteur, clé, SAN, politiques, SCT
checks.js             règles d'analyse, fonctions pures (testées sous Node)
secrets.js            extraction des secrets, endpoints et paramètres du JS
vulndb.js             détection retire.js (version → CVE)
vendor/vulndb-data.js base retire.js embarquée (générée par tools/build-vulndb.mjs)
probes.js             mode actif : sondes de fichiers + DNS-over-HTTPS
export.js             rapports Markdown et HTML imprimable
popup.*               interface — popup et rapport complet (popup.html?tab=<id>)
```

```bash
node --test tests/*.test.js     # règles, décodeur X.509, secrets, retire.js, exports
node tools/build-vulndb.mjs     # régénérer la base retire.js
node tools/package.mjs          # → dist/goa-scan-<version>.zip, vérifié selon les règles du store
```

Les tests de bout en bout pilotent un vrai Chromium avec Puppeteer, sur une page piège
locale et des sites réels — voir [`tests/e2e/`](tests/e2e) et
[CONTRIBUTING.md](CONTRIBUTING.md). Publication sur le Chrome Web Store :
[`docs/chrome-store.md`](docs/chrome-store.md).

## Contribuer

Rapports de bug, faux positifs et nouveaux contrôles sont bienvenus. Lire
[CONTRIBUTING.md](CONTRIBUTING.md) ; les failles de sécurité passent par
[SECURITY.md](SECURITY.md). Historique des versions : [CHANGELOG.md](CHANGELOG.md).

## Licence

[MIT](LICENSE). La base de vulnérabilités embarquée est dérivée de
[RetireJS/retire.js](https://github.com/RetireJS/retire.js) (Apache-2.0).

<p align="center"><sub>Conçu par GoaCloud — <i>le studio des outils souverains.</i></sub></p>
