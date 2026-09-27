/**
 * État applicatif et accès réseau.
 *
 * Séparation stricte : ce module ne connaît pas le DOM, les vues ne connaissent
 * pas `fetch`. Les vues s'abonnent et reçoivent un instantané ; elles ne
 * modifient jamais l'état directement, elles appellent une action.
 */

/** Préférences persistées côté poste. Jamais de données d'audit ici. */
const STORAGE_KEY = 'opscontrol.parc.preferences';

const listeners = new Set();

export const state = {
  hosts: [],
  counts: {},
  job: { running: false, completed: 0, total: 0, error: null },
  monitoring: { interval: 0, next_at: null },
  /** Erreur de la dernière requête, affichée dans la bannière. */
  error: null,
  /** Vrai entre l'envoi et la réponse du premier chargement. */
  pending: true,
  /** Préférences d'affichage : filtres, tri, densité. */
  preferences: loadPreferences(),
};

function loadPreferences() {
  const defaults = {
    query: '', status: '', environment: '', role: '',
    sortKey: 'status', sortDirection: 1,
    density: 'compact',
  };
  try {
    return { ...defaults, ...JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}') };
  } catch {
    // Navigation privée, stockage bloqué, JSON corrompu : on repart des défauts.
    return defaults;
  }
}

function savePreferences() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.preferences));
  } catch {
    // La persistance est un confort, jamais une condition de fonctionnement.
  }
}

/** Abonne une vue aux changements. Renvoie la fonction de désabonnement. */
export function subscribe(listener) {
  listeners.add(listener);
  listener(state);
  return () => listeners.delete(listener);
}

function notify() {
  for (const listener of listeners) listener(state);
}

/** Modifie une préférence, la persiste et notifie. */
export function setPreference(key, value) {
  if (state.preferences[key] === value) return;
  state.preferences[key] = value;
  savePreferences();
  notify();
}

export function resetFilters() {
  Object.assign(state.preferences, { query: '', status: '', environment: '', role: '' });
  savePreferences();
  notify();
}

async function request(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`Erreur ${response.status} : ${await response.text()}`);
  return response.json();
}

/**
 * POST vers l'API. L'en-tête X-Cockpit-Request est exigé par le middleware
 * `guard` de app.py : c'est la protection CSRF de la plateforme.
 */
export function post(url, body) {
  return request(url, {
    method: 'POST',
    headers: { 'X-Cockpit-Request': '1', 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
}

/** Une seule collecte d'état en vol à la fois : évite d'empiler les requêtes. */
let inFlight = null;

export function loadOverview() {
  if (inFlight) return inFlight;
  inFlight = request('/api/overview')
    .then((data) => {
      Object.assign(state, data, { error: null, pending: false });
    })
    .catch((exception) => {
      state.error = exception.message;
      state.pending = false;
    })
    .finally(() => {
      inFlight = null;
      notify();
    });
  return inFlight;
}

/** Lance un audit SSH de tout le parc, puis rafraîchit l'état affiché. */
export async function refreshAll() {
  await post('/api/refresh');
  return loadOverview();
}

/** Lance l'audit d'un seul serveur. */
export async function refreshHost(key) {
  await post(`/api/hosts/${encodeURIComponent(key)}/refresh`);
  return loadOverview();
}

/** Programme (ou arrête) l'actualisation périodique côté serveur. */
export async function setInterval_(seconds) {
  await post('/api/monitoring', { interval: Number(seconds) });
  return loadOverview();
}

/**
 * Cadence de sondage adaptative : rapide pendant une collecte, lente au repos.
 * Renvoie une fonction d'arrêt (utile en test et en cas de démontage de vue).
 */
export function startPolling() {
  let timer = null;
  const tick = () => {
    const delay = state.job.running ? 2000 : 30000;
    timer = setTimeout(async () => {
      if (!document.hidden) await loadOverview();
      tick();
    }, delay);
  };
  tick();
  return () => clearTimeout(timer);
}
