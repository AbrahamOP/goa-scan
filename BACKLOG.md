# Backlog

Ce qui reste à faire, par ordre de priorité. L'historique de ce qui est livré est dans
`CHANGELOG.md`.

## Avant le passage en public

- [ ] Nettoyer les fixtures de test (`tests/fixtures/*.b64`, `tests/cert.test.js`) :
      remplacer les noms de domaine et adresses réels par des valeurs d'exemple
      (`example.com`, `203.0.113.x`), puis repartir d'un historique propre.
- [ ] Trancher le conflit de nom avec l'ancien dépôt public archivé `GoaScan`
      (scanner d'images Docker) : le renommer (`GoaScan-legacy`) ou le supprimer.
- [ ] Téléverser `store/social-preview.png` (Settings → Social preview, pas d'API).
- [ ] Activer le *private vulnerability reporting* (Settings → Security), sans quoi le
      lien de `SECURITY.md` ne mène nulle part.
- [ ] Vérifier que le badge CI s'affiche (il ne rend rien tant que le dépôt est privé).

## Chrome Web Store

- [ ] Créer le compte développeur (5 USD, manuel) et soumettre `dist/goa-scan-<v>.zip`
      en visibilité « Non répertorié ».
- [ ] Héberger `PRIVACY.md` à une URL publique pour le formulaire.
- [ ] Ajouter la fiche anglaise (`docs/store-listing.md`) en plus de la française.
- [ ] Une fois publiée : lien et badge du store dans le README, passage en « Public ».

## Produit

- [ ] **Interface en anglais** : `_locales/en` + `_locales/fr`, `default_locale`,
      `chrome.i18n` dans le popup. Débloque aussi le nom et la description du manifeste
      traduits dans la recherche du store.
- [ ] Transparence : la connexion affiche « inconnue » alors que la chaîne dit « SCT
      intégrés » (vu sur github.com) — aligner les deux ou expliquer l'écart.
- [ ] Applications monopage : relancer la capture sur changement d'URL
      (`webNavigation.onHistoryStateUpdated`).
- [ ] Public Suffix List complète pour distinguer tiers et premier plan.
- [ ] Portage Firefox (certificat via `webRequest.getSecurityInfo`, pas de `debugger`).
- [ ] GIF de démonstration pour le README (clic → note → onglets).
