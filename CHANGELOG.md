# Changelog

Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/), versions
selon [SemVer](https://semver.org/lang/fr/).

## [0.6.2] — 2026-09-10

### Ajouté
- Paquet Chrome Web Store (`tools/package.mjs`) : allowlist des fichiers exécutés,
  vérification des contraintes du store, artefact produit par la CI.
- Politique de confidentialité (`PRIVACY.md`), fiche et marche à suivre de soumission
  (`docs/`), captures 1280×800 (`tools/store-shots.mjs`).

## [0.6.1] — 2026-09-10

### Modifié
- Deux onglets séparés : *API* (appels capturés + documentation OpenAPI) et *Code JS*
  (secrets, endpoints, paramètres) — l'onglet unique devenait trop chargé. La barre
  d'onglets défile.

## [0.6.0] — 2026-09-10

### Ajouté
- **Paramètres cités dans le JavaScript** : clés des query strings (`?a=&b=`),
  `searchParams`/`URLSearchParams`/`FormData` (`.get('x')`, `.append('x')`…) et objets
  `params`/`query = { … }`. Surface d'entrée à tester, triée par nombre d'occurrences.
  Export Markdown et JSON.

## [0.5.0] — 2026-09-10

### Ajouté
- **Endpoints cités dans le JavaScript**, à la LinkFinder : URL absolues, `/chemin`,
  `api/…`, gabarits `` `/api/x/${id}` `` → `/api/x/:param`. Fichiers statiques et URL
  d'espaces de noms écartés, identifiants regroupés comme pour les appels.
- Chaque endpoint est **recoupé** avec les appels vus pendant la visite ; les chemins
  sensibles (`/admin`, `/internal`, `/debug`, `/actuator`, `/swagger`…) sont signalés.

## [0.4.0] — 2026-09-10

### Ajouté
- **Clés et secrets dans le JavaScript** : scripts inline et externes, y compris chargés
  dynamiquement, relus sans cookies (80 scripts, 3 Mo chacun, 25 Mo en tout, traqueurs
  ignorés). Une trentaine de formats reconnus par préfixe, JWT décodés (`service_role`
  Supabase = critique).
- Clés **publiques** par conception (Google `AIza`, Stripe `pk_`, Supabase `anon`)
  classées à part ; affectations suspectes « à vérifier » ; dans les scripts tiers,
  seuls les formats de secrets connus comptent.
- Valeurs **masquées** dès la détection, jamais stockées en clair.

## [0.3.0] — 2026-09-10

### Ajouté
- **Onglet API** : appels fetch, XHR et WebSocket regroupés par endpoint
  (`/users/:id`), méthode, statuts, type de réponse, schéma d'authentification. Seuls
  les *noms* des paramètres sont gardés.
- Constats : jeton ou mot de passe dans l'URL, clé d'API dans l'URL, HTTP Basic, API en 5xx.
- Mode actif : recherche d'une spécification OpenAPI/Swagger publique sur 8 chemins
  courants, confirmée par le contenu, et liste de ses routes.

## [0.2.1] — 2026-09-10

### Corrigé
- IP du serveur lue sur une connexion directe : une page resservie par le cache ou le
  bfcache affichait l'IP de sa première connexion.

## [0.2.0] — 2026-09-10

### Ajouté
- **Note automatique sur l'icône** et alerte si le **certificat d'un site change** entre
  deux visites (détection d'interception). Réglable, activé par défaut.
- **Base de vulnérabilités retire.js embarquée** (~75 composants, ~485 CVE), détection
  par variable globale et par URL de script.
- **Mode actif** (opt-in) : sondes de fichiers exposés confirmées par le contenu, audit
  DNS (CAA, DNSSEC, SPF, DMARC) via DoH.
- **Export Markdown et PDF imprimable**, en plus du JSON.

## [0.1.0] — 2026-09-10

### Ajouté
- Première version : note A–F de la page active, onglets Synthèse, Certificat, En-têtes,
  Cookies, Contenu, Réseau ; rapport pleine page et export JSON.
- Analyse du certificat et de la connexion TLS via `chrome.debugger` (permission
  optionnelle) et décodeur X.509 maison.
