# Fiche Chrome Web Store — textes prêts à coller

## Nom

Goa Scan

## Description courte (≤ 132 caractères)

Analyse la sécurité de la page active : certificat, en-têtes, cookies, secrets et appels d'API. Note A–F, 100 % local.

## Catégorie

Outils de développement (ou Productivité).

## Description longue

Goa Scan note de A à F la sécurité de la page que vous consultez et en dresse un
rapport clair, sans rien envoyer nulle part : tout est analysé dans votre
navigateur.

En un coup d'œil :

• **Certificat TLS** — chaîne complète, algorithme, expiration, transparence,
  alerte si l'empreinte d'un site change entre deux visites.
• **En-têtes de sécurité** — HSTS, CSP, anti-clickjacking, nosniff,
  Referrer-Policy, COOP, CORS.
• **Cookies** — attributs Secure, HttpOnly, SameSite (les valeurs ne sont jamais
  lues).
• **Contenu** — formulaires en clair, scripts tiers sans SRI, jetons dans le
  stockage, bibliothèques JavaScript vulnérables (base retire.js embarquée).
• **API** — appels fetch/XHR/WebSocket de la page, regroupés par endpoint, avec
  statut et schéma d'authentification ; jetons ou clés exposés dans les URL.
• **Code JavaScript** — clés et secrets codés en dur (AWS, Stripe, GitHub,
  Google…), endpoints et paramètres cités dans le code. Les valeurs sont
  masquées.

Une note s'affiche automatiquement sur l'icône, et le rapport complet s'ouvre en
pleine page. Export en Markdown, PDF ou JSON.

100 % local, zéro mouchard, zéro dépendance externe. Un mode actif optionnel
(sondes de fichiers exposés et vérification DNS) reste désactivé par défaut.

## Version anglaise (fiche localisée `en`)

Le store indexe le nom et les descriptions : c'est là que se jouent les mots-clés
(il n'y a pas de champ dédié). Ajouter une fiche **English** dans le tableau de bord
double la surface de recherche.

**Description courte** (≤ 132) :

Grades the security of any web page A–F: TLS certificate, headers, cookies, API calls and secrets in JS. 100% local.

**Description longue** :

Goa Scan audits the security of the page you are on and grades it from A to F, with
every finding ranked by severity and explained with a fix. Everything runs in your
browser: no account, no server, no telemetry.

What it checks:

• TLS / SSL certificate — full chain, expiry, hostname, key strength, signature,
  Certificate Transparency, TLS version and cipher. Alerts you when a site's
  certificate changes between two visits.
• Security headers — Content-Security-Policy (CSP), HSTS, X-Frame-Options /
  frame-ancestors (clickjacking), X-Content-Type-Options, Referrer-Policy,
  Permissions-Policy, COOP, CORS.
• Cookies — Secure, HttpOnly, SameSite. Cookie values are never read.
• Page content — mixed content, insecure forms, scripts without Subresource
  Integrity (SRI), tokens in localStorage, vulnerable JavaScript libraries
  (embedded retire.js database, ~485 CVEs).
• API calls — every fetch, XHR and WebSocket request grouped by endpoint, with
  status and authentication scheme; tokens or API keys leaked in URLs.
• JavaScript code — hardcoded API keys and secrets (AWS, Stripe, GitHub, Google,
  OpenAI, Supabase…), endpoints and parameters found in the bundles. Values are
  masked.

Grade on the toolbar icon, full-page report, export to Markdown, PDF or JSON.
Optional active mode: exposed files (.git, .env), public OpenAPI/Swagger docs,
DNS checks (CAA, DNSSEC, SPF, DMARC).

For developers, security engineers, pentesters and bug bounty hunters. Use active
mode only on sites you own or are authorised to test.

## Visuels

- Tuile promo (obligatoire) : `store/promo-small.png` (440×280).
- Bannière marquee (facultative) : `store/promo-marquee.png` (1400×560).
- Captures : `store/screenshots/*.png` (1280×800).
- Régénération : `node tools/brand-assets.mjs` et `node tools/store-shots.mjs`.

## Champ de saisie unique / justification

Voir `docs/chrome-store.md`.

## Politique de confidentialité (URL)

Renseigner l'URL où `PRIVACY.md` est hébergé.
