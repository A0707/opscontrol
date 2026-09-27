/**
 * Point d'entrée de la console « Parc serveurs ».
 *
 * Chargé en <script type="module"> : l'ordre de chargement est déduit des
 * imports par le navigateur. Il n'y a plus d'ordre de balises <script> à
 * documenter ni à maintenir, et plus aucune variable globale partagée entre
 * fichiers — c'est le remplacement direct de la chaîne de `render` enveloppés
 * de l'interface actuelle.
 */
import { state, subscribe, loadOverview, refreshAll, refreshHost, setPreference, resetFilters, setInterval_, startPolling } from './store.js';
import { mountParcView } from './parc-view.js';

const root = document.getElementById('app');

/**
 * Actions offertes à la vue. La vue ne connaît ni `fetch`, ni le stockage
 * local, ni la navigation : elle appelle une intention, le bootstrap décide.
 */
const view = mountParcView(root, {
  refreshAll: () => refreshAll().catch(report),
  audit: (key) => refreshHost(key).catch(report),
  setInterval: (seconds) => setInterval_(seconds).catch(report),
  setPreference,
  resetFilters,
  isBusy: () => state.job.running,
  open(key) {
    // L'application historique sert le détail d'un serveur ; on y renvoie
    // plutôt que de dupliquer cette vue ici.
    window.location.href = `/#serveur=${encodeURIComponent(key)}`;
  },
});

function report(exception) {
  state.error = exception.message;
  view.update(state);
}

// La vue se réaffiche à chaque notification du store, et à rien d'autre.
subscribe((next) => view.update(next));

// Thème : repris de la préférence déjà posée par l'application historique.
try {
  document.documentElement.dataset.theme = localStorage.getItem('opscontrol-theme') || 'dark';
} catch {
  document.documentElement.dataset.theme = 'dark';
}

loadOverview();
const stopPolling = startPolling();

// Sondage suspendu quand l'onglet est caché : inutile de solliciter le serveur
// et tout le parc pour un écran que personne ne regarde.
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) loadOverview();
});
window.addEventListener('pagehide', stopPolling);
