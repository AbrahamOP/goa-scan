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

## Champ de saisie unique / justification

Voir `docs/chrome-store.md`.

## Politique de confidentialité (URL)

Renseigner l'URL où `PRIVACY.md` est hébergé.
