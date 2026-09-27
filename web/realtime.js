// Abonnement temps réel au flux /api/events (Server-Sent Events).
//
// Principe : le serveur ne pousse PAS les données, seulement le fait qu'elles
// ont changé. L'interface décide ensuite quoi recharger — c'est ce qui permet
// de garder un seul chemin de rendu, déjà éprouvé, au lieu d'en maintenir deux.
//
// Le sondage périodique d'app.js reste en place et sert de filet : si le flux
// n'est pas disponible (proxy qui coupe, serveur ancien, onglet restauré),
// l'interface continue de fonctionner exactement comme avant. Un temps réel qui
// tombe ne doit jamais laisser un écran figé sans que personne le sache.

let realtimeSource = null;
let realtimeConnected = false;

// Repli exponentiel borné : un serveur arrêté ne doit pas être bombardé de
// tentatives, mais un redémarrage doit être rattrapé en quelques secondes.
let realtimeBackoff = 1000;
const REALTIME_BACKOFF_MAX = 30000;

function realtimeStatus(connected) {
  realtimeConnected = connected;
  const cible = $('#progress');
  if (!cible) return;
  cible.dataset.realtime = connected ? 'on' : 'off';
  cible.title = connected
    ? 'Flux temps réel actif : les changements arrivent sans attendre.'
    : 'Flux temps réel indisponible — actualisation périodique de secours.';
}

function realtimeConnect() {
  if (realtimeSource || typeof EventSource === 'undefined') return;
  let source;
  try {
    source = new EventSource('/api/events');
  } catch {
    realtimeStatus(false);
    return;
  }
  realtimeSource = source;

  source.addEventListener('ready', () => {
    realtimeBackoff = 1000;
    realtimeStatus(true);
    loadAlerts(); // Also resynchronize after a disconnect or a hidden tab.
  });

  // Un changement d'état côté serveur : on recharge par le chemin habituel.
  source.addEventListener('state', () => {
    realtimeStatus(true);
    loadAlerts(); // Critical incidents bypass the slower overview/source reload.
    // load() porte déjà sa propre garde (onglet caché, chargement en cours) :
    // on ne la contourne pas, sinon on rétablirait le trafic qu'on supprime.
    load();
  });

  // Voie rapide : ici le serveur pousse l'ÉTAT lui-même (serveurs critiques,
  // quelques Ko), pas un signal. critical.js l'affiche sans aucun rechargement.
  source.addEventListener('tier0', e => {
    realtimeStatus(true);
    try { window.dispatchEvent(new CustomEvent('opscontrol:tier0', { detail: JSON.parse(e.data) })); } catch { /* message illisible : ignoré */ }
  });

  source.onerror = () => {
    // EventSource se reconnecte seul, mais pas si le serveur a disparu : on
    // ferme et on replanifie nous-mêmes pour garder la main sur la cadence.
    source.close();
    if (realtimeSource === source) realtimeSource = null;
    realtimeStatus(false);
    setTimeout(realtimeConnect, realtimeBackoff);
    realtimeBackoff = Math.min(realtimeBackoff * 2, REALTIME_BACKOFF_MAX);
  };
}

// Le flux est inutile tant que personne ne regarde : on le coupe avec l'onglet,
// au même titre que la garde document.hidden de load().
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    if (realtimeSource) { realtimeSource.close(); realtimeSource = null; }
    realtimeStatus(false);
  } else {
    realtimeBackoff = 1000;
    realtimeConnect();
  }
});

if (!document.hidden) realtimeConnect();
