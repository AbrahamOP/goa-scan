# Politique de confidentialité — Goa Scan

_Dernière mise à jour : 2026-09-10_

Goa Scan est une extension d'analyse de sécurité **entièrement locale**. Elle
n'a pas de serveur, pas de compte, pas de mouchard.

## Données collectées

**Aucune.** Goa Scan ne collecte, ne stocke à distance et ne transmet à son
éditeur **aucune** donnée personnelle ou de navigation. Toute l'analyse se fait
dans votre navigateur.

## Ce que l'extension lit, et où cela reste

Quand vous ouvrez Goa Scan (ou lors de l'analyse automatique de l'onglet actif),
l'extension lit, **localement**, des informations sur la page consultée :
en-têtes de réponse, cookies (uniquement leurs attributs `Secure` / `HttpOnly` /
`SameSite`, **jamais leur valeur**), contenu du DOM, scripts, et — sur demande
explicite — le certificat TLS. Ces informations servent à produire la note et le
rapport, puis restent en mémoire ou dans le stockage local du navigateur
(`chrome.storage`). Elles ne quittent pas votre machine.

Sont conservés dans le stockage **local** du navigateur, sur votre appareil
seulement : vos réglages, et une empreinte de certificat par site visité (pour
vous alerter si elle change). Vous pouvez les effacer à tout moment en
supprimant les données du site de l'extension.

## Requêtes réseau émises par l'extension

- **Analyse standard** : l'extension peut relire, sans cookies, le document, le
  fichier `/.well-known/security.txt` et les scripts **du site que vous
  analysez**, pour lire ses en-têtes et y chercher des secrets. Aucune de ces
  requêtes ne part vers un tiers.
- **Liens « Aller plus loin »** : ils n'ouvrent un service externe (SSL Labs,
  securityheaders.com, Mozilla Observatory, VirusTotal, crt.sh, Shodan) que si
  **vous cliquez**. Ce service reçoit alors le nom de domaine analysé, selon sa
  propre politique de confidentialité.
- **Mode actif** (désactivé par défaut, à activer explicitement) : envoie des
  requêtes de sonde vers le site analysé et des requêtes DNS-over-HTTPS à
  Cloudflare (`cloudflare-dns.com`) pour lire sa configuration DNS publique. Seul
  le nom de domaine est transmis, jamais de contenu de page.

## Valeurs sensibles

Les **valeurs** des cookies et les **secrets** trouvés dans le code sont
**masqués** dès leur détection : ils ne sont ni affichés en clair ni inclus dans
les exports.

## Permissions

Chaque permission Chrome demandée sert uniquement à cette analyse locale ; le
détail et la justification figurent dans `docs/chrome-store.md`. La permission
`debugger` est **optionnelle** et n'est demandée qu'au premier usage de l'analyse
de certificat.

## Contact

Questions : ouvrir une issue sur le dépôt du projet.
