// Page « Partages » : chaque dossier partagé (NFS, CIFS/Samba) avec son
// serveur, son occupation et TOUS ses clients observés, à partir de /api/shares.
navGroups[1][1].splice(2, 0, ['Partages', 'backup']);
subtitles.Partages = 'Dossiers partagés NFS et Samba : occupation, accessibilité depuis chaque client, exports déclarés.';

let shareData = null, shareQuery = '', shareState = '';
const shareLabels = { critical: 'Critique', warning: 'Majeur', preventive: 'Préventif', ok: 'OK', unknown: 'Non mesuré' };

function shareClients(p) {
  if (!p.clients.length) return '<span class="note">Aucun client audité</span>';
  const resume = p.clients_count + ' client(s)' + (p.stale_clients ? ' · <b class="text-critical">' + p.stale_clients + ' injoignable(s)</b>' : '') +
    (p.read_only_clients ? ' · ' + p.read_only_clients + ' en lecture seule' : '');
  return '<details><summary>' + resume + '</summary><ul class="alert-targets">' + p.clients.map(c =>
    '<li><button class="link" data-host="' + esc(c.key) + '">' + esc(c.name) + '</button> <small>' + esc(c.mount) + ' · ' +
    (c.status === 'stale' ? 'injoignable' : 'accessible') + ' · ' + (c.access === 'read-only' ? 'lecture seule' : 'lecture-écriture') +
    (c.stale ? ' · mesure ancienne' : '') + '</small></li>').join('') + '</ul></details>';
}

function shareUse(p) {
  if (p.use_pct == null) return '<span class="metric-label">Non mesuré</span>';
  const cls = p.use_pct >= shareData.thresholds.critical ? 'critical' : p.use_pct >= shareData.thresholds.warning ? 'warning' :
    p.use_pct >= shareData.thresholds.preventive ? 'preventive' : '';
  return '<span class="metric-label">' + p.use_pct + ' %</span><div class="meter ' + cls + '"><i data-pct="' + p.use_pct + '"></i></div>';
}

function shareExport(p) {
  if (!p.export) return '<span class="note">Non relevé</span>';
  return esc(p.protocol) + ' · ' + esc(p.export.clients || p.export.name || 'déclaré');
}

function shareMarkup() {
  if (!shareData) return '<div class="panel">Chargement des partages…</div>';
  const q = shareQuery.trim().toLowerCase(), n = shareData.counts;
  const lignes = shareData.shares.filter(p => (!shareState || p.status === shareState) &&
    (!q || (p.key + ' ' + (p.server_host?.name || '') + ' ' + p.clients.map(c => c.name).join(' ')).toLowerCase().includes(q)));
  return '<div class="stats alert-stats alert-stats-5">' + ['critical', 'warning', 'preventive', 'ok', 'unknown'].map(s =>
    '<button class="card stat-card ' + s + '" data-share-state="' + s + '"><span class="stat-dot"></span>' + shareLabels[s] +
    '<strong>' + (n[s] || 0) + '</strong><small>partage(s)</small></button>').join('') + '</div>' +
    '<section class="panel"><div class="panel-head"><h2>Dossiers partagés <span class="state-count">' + lignes.length + '</span></h2></div>' +
    '<div class="filters"><input id="share-search" type="search" placeholder="Serveur, chemin ou client" value="' + esc(shareQuery) + '">' +
    '<select id="share-state"><option value="">Tous les états</option>' + Object.entries(shareLabels).map(([k, v]) => '<option value="' + k + '">' + v + '</option>').join('') + '</select></div>' +
    '<div class="table"><table><thead><tr><th>État</th><th>Partage</th><th>Serveur</th><th>Occupation</th><th>Clients</th><th>Export déclaré</th><th>Dernière preuve</th></tr></thead><tbody>' +
    lignes.map(p => '<tr><td><span class="badge ' + (p.fresh ? p.status : 'unknown') + '">' + (p.fresh ? '' : 'Ancien · ') + shareLabels[p.status] + '</span>' +
      (p.reasons.length ? '<small>' + esc(p.reasons.join(' · ')) + '</small>' : '') + '</td>' +
      '<td class="ip">' + esc(p.path) + '<small>' + esc(p.protocol || '') + '</small></td>' +
      '<td>' + (p.server_host ? '<button class="link" data-host="' + esc(p.server_host.key) + '">' + esc(p.server_host.name) + '</button><small>' + esc(p.server) + '</small>' : esc(p.server) + '<small>hors inventaire</small>') + '</td>' +
      '<td class="metric">' + shareUse(p) + '</td><td>' + shareClients(p) + '</td><td>' + shareExport(p) + '</td><td>' + stamp(p.observed_at) + '</td></tr>').join('') +
    '</tbody></table></div>' + (lignes.length ? '' : '<p class="note">Aucun partage pour ces critères.</p>') +
    '<p class="note">Politique commune : préventif à ' + shareData.thresholds.preventive + ' %, majeur à ' + shareData.thresholds.warning +
    ' %, critique à ' + shareData.thresholds.critical + ' % ou dès qu’un client ne joint plus le partage ; un cran de moins au-delà de 50 Gio libres. ' + esc(shareData.scope) + '</p></section>';
}

function shareDraw() {
  const target = $('#share-data');
  if (!target) return;
  const focus = document.activeElement?.id === 'share-search';
  target.innerHTML = shareMarkup();
  if ($('#share-state')) $('#share-state').value = shareState;
  // CSP style-src 'self' : largeur posée par CSSOM, jamais par attribut style.
  target.querySelectorAll('[data-pct]').forEach(i => i.style.setProperty('width', Math.min(100, Number(i.dataset.pct)) + '%'));
  if (focus) { const input = $('#share-search'); input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
}

async function loadShares() {
  try {
    shareData = await api('/api/shares');
  } catch (e) {
    if ($('#share-data')) $('#share-data').textContent = e.message;
    return;
  }
  if (page === 'Partages' && !selected) shareDraw();
}

const renderBeforeShares = render;
render = function () {
  renderBeforeShares();
  if (page !== 'Partages' || selected) return;
  $('#content').innerHTML = '<div id="share-data"></div>';
  shareDraw();
  loadShares();
};

$('#content').addEventListener('input', e => { if (e.target.id === 'share-search') { shareQuery = e.target.value; shareDraw(); } });
$('#content').addEventListener('change', e => { if (e.target.id === 'share-state') { shareState = e.target.value; shareDraw(); } });
$('#content').addEventListener('click', e => {
  const b = e.target.closest('[data-share-state]');
  if (!b) return;
  shareState = shareState === b.dataset.shareState ? '' : b.dataset.shareState;
  shareDraw();
});
