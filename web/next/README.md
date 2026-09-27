# Console « Parc serveurs » — nouvelle couche d'interface

Prototype **fonctionnel et isolé**. Il ne modifie ni ne charge aucun fichier de
l'interface actuelle : `web/app.js`, `web/style.css` et les autres scripts
restent intacts. Rien n'est cassé si ce dossier est supprimé.

## Essayer

Démarrer OpsControl normalement, puis ouvrir :

    http://127.0.0.1:8000/next/

La console tape sur la vraie API (`/api/overview`, `/api/refresh`,
`/api/hosts/{key}/refresh`, `/api/monitoring`) — aucune donnée simulée.

## Ce que ce prototype démontre

| Problème de l'interface actuelle | Réponse ici |
|---|---|
| `render` enveloppé 5 fois, ordre des `<script>` à documenter à la main | Modules ES : les `import` imposent l'ordre, plus aucune variable globale |
| 17 écouteurs délégués sur `#content`, empilés par 6 fichiers | Un dispatcher `data-action` par type d'événement, lisible d'un bloc |
| `innerHTML` reconstruit tout le tableau toutes les 2 s | Réconciliation par clé : les nœuds sont réutilisés, le focus survit |
| `esc()` à ne pas oublier à chaque interpolation | `textContent` uniquement : l'échappement ne peut plus être oublié |
| Jauges bloquées par la CSP, contournées par 21 classes `.w0…w100` | `style.setProperty` depuis le script : autorisé par la CSP, valeur exacte |
| 7 lignes visibles en 1440×900 | 11 lignes (mesuré), barre d'outils et en-tête collants |
| Pas de raccourci clavier | `/` rechercher, flèches parcourir, `Entrée` ouvrir, `Échap` effacer |
| Filtres perdus au rechargement | Filtres, tri et densité persistés (`localStorage`, avec repli) |

## Fichiers

| Fichier | Rôle | Dépend de |
|---|---|---|
| `format.js` | Vocabulaire et formatage. Aucune dépendance. | — |
| `dom.js` | Construction et mise à jour du DOM, délégation d'événements. | — |
| `store.js` | État, préférences, appels API, sondage adaptatif. | — |
| `parc-view.js` | Le composant. Ne connaît ni `fetch` ni `localStorage`. | `dom`, `format` |
| `main.js` | Câblage : branche les actions de la vue sur le store. | tous |
| `next.css` | Style de la console. Réutilise les jetons de `/style.css`. | — |

La règle de dépendance est unidirectionnelle : `main → parc-view → dom/format`,
et `main → store`. La vue n'a aucun accès au réseau ; le store aucun au DOM.

## Adopter

Le prototype couvre la vue Parc. Pour basculer l'application dessus, la voie
sûre est page par page : porter une vue, la servir sous `/next/`, comparer,
puis remplacer l'entrée correspondante dans `web/index.html`. La dernière vue
portée permet de supprimer la chaîne de `render` enveloppés — pas avant.

Voir la feuille de route dans la réponse d'analyse pour l'ordre recommandé.
