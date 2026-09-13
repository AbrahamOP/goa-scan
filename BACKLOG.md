# Backlog

Ce qui reste à faire, par ordre de priorité. L'historique de ce qui est livré est dans
`CHANGELOG.md`.

## Dépôt public

- [ ] Téléverser `store/social-preview.png` (Settings → Social preview, pas d'API).

## Chrome Web Store

- [ ] Soumettre `dist/goa-scan-<v>.zip` en visibilité « Public » depuis le compte
      développeur existant (celui de GoaBlockAD). Politique de confidentialité :
      https://github.com/AbrahamOP/goa-scan/blob/main/PRIVACY.md
- [ ] Ajouter la fiche anglaise (`docs/store-listing.md`) en plus de la française.
- [ ] Une fois acceptée : lien et badge du store dans le README.

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
