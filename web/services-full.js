// Page Services : liste COMPLÈTE des unités, chargée à la demande (/api/services).
//
// /api/overview n'envoie plus que les unités non actives (payload_slim.py) : la
// liste du parc n'en compte que les échecs. Seule cette page a
// besoin de tout ; elle le charge elle-même, puis toutes les 60 s tant qu'elle
// est affichée.
let servicesComplets = null, servicesCharges = 0, servicesEnCours = false;

async function chargerServicesComplets() {
  if (servicesEnCours) return;
  servicesEnCours = true;
  try {
    servicesComplets = await api('/api/services');
    servicesCharges = Date.now();
    if (page === 'Services' && !selected) render();
  } catch (e) {
    $('#error').textContent = e.message;
  } finally {
    servicesEnCours = false;
  }
}

const serviceViewAllegee = serviceView;
serviceView = function () {
  if (!servicesComplets || Date.now() - servicesCharges > 60000) chargerServicesComplets();
  if (!servicesComplets) return '<div class="panel">Chargement de la liste complète des services…</div>';
  // La vue d'origine lit h.all_services : on lui rend la liste complète.
  (state?.hosts || []).forEach(h => { if (servicesComplets[h.key]) h.all_services = servicesComplets[h.key]; });
  return serviceViewAllegee();
};
