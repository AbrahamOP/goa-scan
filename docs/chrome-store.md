# Soumission au Chrome Web Store — Goa Scan

Tout est prêt côté code. Cette fiche rassemble le paquet et les textes à
coller dans le formulaire du store. Visibilité retenue à l'étape Distribution :
**« Public »** (« Non répertorié » reste possible pour un test par lien direct).

## 1. Construire le paquet

```bash
node tools/package.mjs        # → dist/goa-scan-<version>.zip
```

Le script vérifie les contraintes du store (longueur de description, icônes,
version, absence de code distant) et n'embarque que les fichiers exécutés
(pas les tests, ni `tools/`, ni la doc).

## 2. Compte développeur

- Compte Chrome Web Store Developer : celui qui publie déjà GoaBlockAD suffit.
  La soumission est **manuelle**, sur https://chrome.google.com/webstore/devconsole.
- Créer un article, téléverser le zip.

## 3. Objet unique (_single purpose_)

> Analyser la sécurité de la page web active et en présenter un rapport local
> (note A–F, certificat TLS, en-têtes, cookies, contenu, appels d'API, secrets
> et endpoints dans le code JavaScript).

## 4. Justification des permissions

| Permission | Justification à coller |
|---|---|
| `host_permissions` `<all_urls>` | L'utilisateur peut analyser n'importe quelle page qu'il consulte ; l'extension doit donc pouvoir lire la page active quel que soit son domaine. Lecture seule. |
| `webRequest` | Lire, pour l'onglet actif, les en-têtes de réponse, un résumé des requêtes, l'adresse IP du serveur et les erreurs de certificat. Observation seule, aucune requête n'est bloquée ni modifiée. |
| `cookies` | Lire les attributs de sécurité des cookies du site (`Secure`, `HttpOnly`, `SameSite`). La valeur des cookies n'est jamais lue. |
| `scripting` | Injecter des fonctions de lecture du DOM et des versions de bibliothèques dans la page analysée, au moment de l'analyse. |
| `storage` | Conserver les réglages et les empreintes de certificat par site (alerte en cas de changement), en local. |
| `debugger` (optionnelle) | Seul moyen par lequel Chrome expose le certificat TLS à une extension. Attachement de ~0,5 s à l'onglet, sur action explicite de l'utilisateur, puis détachement. Demandée seulement au premier usage. |

## 5. Code distant

**Aucun.** Tout le code est embarqué dans le paquet. La base de vulnérabilités
(retire.js) est une **donnée** embarquée (`vendor/vulndb-data.js`), pas du code
exécuté à distance. Répondre « Non » à « utilise-t-il du code distant ».

## 6. Confidentialité des données

- Politique de confidentialité (onglet Confidentialité) :
  https://github.com/AbrahamOP/goa-scan/blob/main/PRIVACY.md
- Déclaration d'usage des données : **ne collecte aucune donnée utilisateur**.
  Cocher les trois engagements (pas de vente, usage conforme à l'objet unique,
  pas de transfert hors objet).

## 7. Fiche (listing)

Voir `docs/store-listing.md` pour la description courte et longue, et
`store/screenshots/` pour les captures (format 1280×800).

## 8. Après acceptation

Tant que la visibilité reste « Non répertorié » / « Privé », l'extension n'est
pas trouvable dans le store : l'installation se fait par le lien direct (non
répertorié) ou par la liste d'e-mails autorisés (privé).
