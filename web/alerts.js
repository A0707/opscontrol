// Centre d'alertes : toutes les sources, regroupées par cause (/api/alerts).
//
// Trois canaux d'alerte, du plus discret au plus intrusif :
//   1. le compteur dans la navigation et le titre de l'onglet ;
//   2. un bandeau sur TOUTES les pages quand une alerte critique récente est
//      nouvelle pour cet opérateur ;
//   3. une notification du navigateur, uniquement si l'opérateur l'a activée.
// « Marquer comme vues » ne masque rien : l'alerte reste dans la liste tant que
// la preuve existe. Cela arrête seulement le bandeau et les notifications.
navGroups[0][1].splice(1, 0, ['Alertes', 'alert']);
subtitles.Alertes = 'Anomalies de toutes les sources, graduées par une politique commune : critique, majeur, préventif.';

let alertData = null, alertSource = '', alertLevel = '', alertFresh = '', alertQuery = '';
const ALERT_SEEN_KEY = 'opscontrol.alertes.vues';
const alertNotified = new Set();
const alertBaseTitle = document.title;
let alertLoading = false, alertReloadPending = false, alertFeedError = '', homeCriticalSignature = '';
let stripSignature = '';

function currentAlert(a) {
  const age = ageSeconds(a.observed_at);
  return {...a, fresh: Boolean(a.fresh && !alertFeedError && age !== null && age >= 0 && age <= (a.max_age_seconds ?? 900))};
}

function alertSeen() {
  try { return new Set(JSON.parse(localStorage.getItem(ALERT_SEEN_KEY) || '[]')); } catch (e) { return new Set(); }
}
function alertRemember(ids) {
  try { localStorage.setItem(ALERT_SEEN_KEY, JSON.stringify([...new Set([...alertSeen(), ...ids])].slice(-500))); } catch (e) { /* stockage indisponible : le bandeau restera affiché */ }
}
// Critiques récentes : les seules qui justifient d'interrompre un opérateur.
function alertUrgent() {
  // Une alerte chronique (ouverte depuis plus de 30 j) ou déjà prise en charge
  // par quelqu'un n'interrompt plus personne. Elle reste listée.
  return (alertData?.alerts || []).map(currentAlert).filter(a => a.severity === 'critical' && a.fresh && !a.chronic && !a.ack);
}
function alertNew() {
  const seen = alertSeen();
  return alertUrgent().filter(a => !seen.has(a.id + '@' + a.count));
}

function alertBadge(a) {
  // Gravité OpsControl (politique commune) ; une preuve ancienne reste « à confirmer ».
  return '<span class="badge ' + (a.fresh ? a.severity : 'unknown') + '">' + (a.fresh ? '' : 'À confirmer · ') +
    esc(a.severity_label || a.severity) + '</span>';
}

function alertTargets(a) {
  const items = a.targets.map(t => {
    const detail = t.detail && t.detail !== a.title ? ' <small>' + esc(t.detail) + '</small>' : '';
    const times = '<small class="target-age">' + freshnessMarkup(t.observed_at || a.observed_at,
      a.source === 'Zabbix' ? 'Lecture Zabbix' : 'Observation', a.max_age_seconds ?? 900) +
      (a.source === 'Zabbix' ? ' · ' + freshnessMarkup(t.measurement_at, 'Item le plus ancien', 30) : '') + '</small>';
    return (t.host_key
      ? '<li><button class="link" data-host="' + esc(t.host_key) + '">' + esc(t.name) + '</button>' + detail + '</li>'
      : '<li>' + esc(t.name) + detail + '</li>').replace('</li>', times + '</li>');
  }).join('');
  if (!a.targets.length) return '';
  const reste = a.truncated ? '<li class="note">… et ' + (a.count - a.targets.length) + ' autre(s)</li>' : '';
  const liste = '<ul class="alert-targets">' + items + reste + '</ul>';
  return a.count > 6 ? '<details><summary>' + a.count + ' cible(s) concernée(s)</summary>' + liste + '</details>' : liste;
}

// Début le plus ancien parmi les cibles, quand la source le donne (déclenchement
// du trigger Zabbix, mise hors service de la sonde). Sinon « début non mesuré » :
// la date d'observation n'est pas une date de début.
function alertSince(a) {
  const debuts = (a.targets || []).map(t => t.started_at).filter(Boolean)
    .map(v => /^\d+$/.test(String(v)) ? Number(v) * 1000 : Date.parse(v)).filter(Number.isFinite);
  if (!debuts.length) return '<span class="alert-since unknown">début non mesuré</span>';
  return '<span class="alert-since">depuis <b data-since="' + new Date(Math.min(...debuts)).toISOString() + '"></b></span>';
}

function alertItem(a) {
  return '<article class="alert-item ' + (a.fresh ? a.severity : 'stale') + '">' +
    '<div class="alert-head">' + alertBadge(a) + '<span class="alert-source">' + esc(a.source) + '</span>' +
    '<h3>' + esc(a.title) + '</h3>' + (a.chronic ? '<span class="badge unknown">Chronique</span>' : '') + alertSince(a) +
    '<span class="state-count">' + a.count + '</span></div>' + alertAck(a) +
    '<p class="alert-meta"><b>' + esc(a.delay || '') + '</b>' +
    (a.rule ? ' · Règle : ' + esc(a.rule) : '') +
    (a.source_severity ? ' · Gravité d’origine : ' + esc(a.source_severity) : '') + '</p>' +
    (a.evidence ? '<p class="note">' + esc(a.evidence) + '</p>' : '') +
    alertTargets(a) +
    '<p class="alert-stamp">' + freshnessMarkup(a.observed_at, a.source === 'Zabbix' ? 'Dernière lecture API' : 'Dernière preuve du groupe', a.max_age_seconds ?? 900) +
    (a.fresh ? '' : ' · état à reconfirmer') + '</p></article>';
}

// Prise en charge partagée (/api/alerts/ack) : visible par tous les postes.
function alertAck(a) {
  if (a.severity === 'info') return '';
  if (a.ack) {
    return '<p class="alert-ack">Pris en charge par <b>' + esc(a.ack.by) + '</b> il y a <b data-since="' + esc(a.ack.at) + '"></b>' +
      (a.ack.note ? ' — « ' + esc(a.ack.note) + ' »' : '') + ' · jusqu’à ' + esc(stamp(a.ack.until)) +
      ' <button class="link" data-alert-unack="' + esc(a.id) + '">Libérer</button></p>';
  }
  return a.chronic ? '' : '<p class="alert-ack"><button data-alert-ack="' + esc(a.id) + '">Prendre en charge</button></p>';
}

// Chroniques : export pour le nettoyage dans Zabbix (triggers jamais refermés).
function alertChronicCsv() {
  const lignes = [['Source', 'Gravité OpsControl', 'Gravité d’origine', 'Anomalie', 'Cible', 'Ouverte depuis', 'Jours']];
  (alertData?.alerts || []).filter(a => a.chronic).forEach(a => a.targets.forEach(t => {
    const v = t.started_at, ms = /^[0-9]+$/.test(String(v)) ? Number(v) * 1000 : Date.parse(v);
    lignes.push([a.source, a.severity_label, a.source_severity || '', a.title, t.name,
      Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : '', Number.isFinite(ms) ? Math.floor((Date.now() - ms) / 86400000) : '']);
  }));
  const csv = lignes.map(l => l.map(c => '"' + String(c).split('"').join('""') + '"').join(';')).join('\r\n');
  const url = URL.createObjectURL(new Blob(['\ufeff' + csv], { type: 'text/csv;charset=utf-8' }));
  const lien = document.createElement('a');
  lien.href = url;
  lien.download = 'opscontrol-anomalies-chroniques.csv';
  lien.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function alertChronicSection(liste) {
  if (!liste.length) return '';
  return '<details class="panel critical-old chronic-block"><summary>' + liste.length + ' anomalie(s) chronique(s) — ouvertes depuis plus de 30 jours</summary>' +
    '<p class="note">Jamais refermées dans leur source : ni incident à traiter dans l’heure, ni état réel prouvé. ' +
    'Les corriger ou les fermer dans Zabbix rend l’écran à nouveau fiable.</p>' +
    '<button data-alert-csv>Exporter pour nettoyage (CSV)</button>' + liste.map(alertItem).join('') + '</details>';
}

function homeCriticalMarkup() {
  if (!alertData) return '<section class="panel critical-home"><h2>Incidents critiques</h2><p>' +
    esc(alertFeedError || 'Chargement des incidents…') + '</p></section>';
  const tout = alertData.alerts.map(currentAlert).filter(a => a.severity === 'critical');
  const all = tout.filter(a => !a.chronic), chroniques = tout.filter(a => a.chronic);
  const current = all.filter(a => a.fresh), old = all.filter(a => !a.fresh);
  const sources = (alertData.sources || []).map(s => '<span class="source-age">' +
    freshnessMarkup(s.collected_at, s.name || s.provider, s.max_age_seconds ?? 900) +
    (s.error ? ' · ' + esc(s.error) : '') + '</span>').join('');
  return '<section class="panel critical-home"><div class="panel-head"><h2>Incidents critiques <span class="state-count">' +
    current.length + ' cause(s) récente(s)</span></h2><button data-go="Alertes">Toutes les alertes</button></div>' +
    '<p class="note">Derniers incidents observés, y compris les cibles hors inventaire. Zabbix est interrogé toutes les 10 s lorsque l’actualisation automatique est active.</p>' +
    (alertFeedError ? '<p role="alert" class="form-error">' + esc(alertFeedError) + ' Derniers incidents conservés, à reconfirmer.</p>' : '') +
    '<div class="critical-sources">' + (sources || 'Aucune source API configurée.') + '</div>' +
    (current.slice(0,6).map(alertItem).join('') || '<p class="empty">Aucun incident critique récent dans les observations disponibles. Vérifier la fraîcheur et la couverture des sources.</p>') +
    (current.length > 6 ? '<button data-go="Alertes">Voir les ' + (current.length-6) + ' autres causes critiques</button>' : '') +
    (old.length ? '<details class="critical-old"><summary>' + old.length + ' cause(s) critique(s) ancienne(s) à reconfirmer</summary>' + old.slice(0,6).map(alertItem).join('') + '<button data-go="Alertes">Consulter toutes les preuves anciennes</button></details>' : '') +
    (chroniques.length ? '<p class="note">' + chroniques.length + ' anomalie(s) critique(s) chronique(s), ouvertes depuis plus de 30 jours, ne sont pas comptées ici. <button class="link" data-go="Alertes">Voir et exporter</button></p>' : '') +
    '<p class="note">CARP : les bascules nécessitent un trigger Zabbix configuré. Une lecture API récente ne garantit pas une mesure récente de chaque item.</p></section>';
}

function renderHomeCritical() {
  const target = $('#home-critical');
  if (!target) return;
  const signature = JSON.stringify({data: alertData ? {...alertData, generated_at: undefined} : null, error: alertFeedError,
    fresh: (alertData?.alerts || []).map(a => currentAlert(a).fresh)});
  if (signature === homeCriticalSignature && target.childElementCount) return;
  const expanded = target.querySelector('.critical-old')?.open;
  target.innerHTML = homeCriticalMarkup();
  if (expanded && target.querySelector('.critical-old')) target.querySelector('.critical-old').open = true;
  homeCriticalSignature = signature;
}

function alertPolicy() {
  return '<details class="panel alert-policy"><summary>Politique de gravité OpsControl — pourquoi chaque alerte a son niveau</summary>' +
    '<div class="table"><table><thead><tr><th>Niveau</th><th>Délai d’intervention</th></tr></thead><tbody>' +
    alertData.levels.map(l => '<tr><td><span class="badge ' + l.key + '">' + esc(l.label) + '</span></td><td>' + esc(l.delay) + '</td></tr>').join('') +
    '</tbody></table></div><div class="table"><table><thead><tr><th>Domaine</th><th>Règle</th></tr></thead><tbody>' +
    alertData.policy.map(r => '<tr><td>' + esc(r.domain) + '</td><td class="wrap">' + esc(r.rule) + '</td></tr>').join('') +
    '</tbody></table></div><p class="note">La gravité d’origine (Zabbix, audit) reste affichée sur chaque alerte : ' +
    'la requalification est explicite, jamais silencieuse.</p></details>';
}

function alertMarkup() {
  if (!alertData) return '<div class="panel">Chargement des alertes…</div>';
  const n = alertData.counts, q = alertQuery.trim().toLowerCase();
  // Les informations (états voulus, triggers de test) ne s'affichent que sur demande.
  const filtrees = alertData.alerts.map(currentAlert).filter(a =>
    (alertLevel ? a.severity === alertLevel : a.severity !== 'info') && (!alertSource || a.source === alertSource) &&
    (!alertFresh || String(a.fresh) === alertFresh) &&
    (!q || (a.title + ' ' + a.targets.map(t => t.name + ' ' + (t.detail || '')).join(' ')).toLowerCase().includes(q)));
  const visibles = filtrees.filter(a => !a.chronic), chroniques = filtrees.filter(a => a.chronic);
  const sources = [...new Set(alertData.alerts.map(a => a.source))].sort();
  const muettes = alertData.sources.filter(s => !s.fresh);
  const carte = (cle, titre, cls) => '<button class="card stat-card ' + cls + '" data-alert-level="' + cle + '"><span class="stat-dot"></span>' +
    titre + '<strong>' + n[cle] + '</strong><small>' + esc(alertData.levels.find(l => l.key === cle).delay) +
    (n[cle + '_stale'] ? ' · + ' + n[cle + '_stale'] + ' à confirmer' : '') + '</small></button>';
  return '<div class="stats alert-stats alert-stats-5">' +
    carte('critical', 'Critiques confirmées', 'critical') + carte('warning', 'Majeures', 'warning') +
    carte('preventive', 'Préventives', 'preventive') +
    '<div class="card stat-card' + (muettes.length ? ' warning' : ' ok') + '"><span class="stat-dot"></span>Sources à jour<strong>' +
    (alertData.sources.length - muettes.length) + '/' + alertData.sources.length + '</strong><small>' +
    (muettes.length ? esc(muettes.map(s => s.name).join(', ')) : 'toutes récentes') + '</small></div>' +
    '<button class="card stat-card" data-alert-level="info"><span class="stat-dot"></span>Informations<strong>' + (n.info + n.info_stale) +
    '</strong><small>masquées par défaut</small></button></div>' +
    '<section class="panel"><div class="panel-head"><h2>Alertes par cause <span class="state-count">' + visibles.length + '</span></h2>' +
    '<div><button data-alert-seen>Marquer comme vues</button> ' +
    ('Notification' in window && Notification.permission !== 'granted'
      ? '<button data-alert-notify>Activer les notifications du navigateur</button>' : '') + '</div></div>' +
    '<div class="filters"><input id="alert-search" type="search" placeholder="Rechercher une cause, un serveur, un volume" value="' + esc(alertQuery) + '">' +
    '<select id="alert-source"><option value="">Toutes les sources</option>' + sources.map(s => '<option>' + esc(s) + '</option>').join('') + '</select>' +
    '<select id="alert-level"><option value="">Critique, majeur, préventif</option>' +
    alertData.levels.map(l => '<option value="' + l.key + '">' + esc(l.label) + ' seulement</option>').join('') + '</select>' +
    '<select id="alert-fresh"><option value="">Récentes et anciennes</option><option value="true">Récentes seulement</option><option value="false">À confirmer seulement</option></select></div>' +
    (visibles.map(alertItem).join('') || '<div class="empty"><span class="empty-symbol">◎</span>Aucune alerte pour ces critères.</div>') +
    '<p class="note">' + esc(alertData.scope) + '</p></section>' + alertChronicSection(chroniques) + alertPolicy();
}

// Bandeau global : présent sur toutes les pages, jamais sur une preuve ancienne.
function alertStrip() {
  let strip = $('#alert-strip');
  if (!strip) {
    strip = document.createElement('div');
    strip.id = 'alert-strip';
    strip.setAttribute('role', 'alert');
    $('#content').insertAdjacentElement('beforebegin', strip);
  }
  const nouvelles = alertNew();
  strip.hidden = !nouvelles.length || page === 'Alertes';
  const markup = nouvelles.length
    ? '<span class="badge critical">' + nouvelles.length + ' nouvelle(s) alerte(s) critique(s)</span><span>' +
      esc(nouvelles.slice(0, 2).map(a => a.title).join(' · ')) + (nouvelles.length > 2 ? ' …' : '') + '</span>' +
      '<button class="primary" data-go="Alertes">Voir les alertes</button><button data-alert-seen>Marquer comme vues</button>'
    : '';
  if (markup !== stripSignature) { strip.innerHTML = markup; stripSignature = markup; }
  const total = alertUrgent().length;
  document.title = (total ? '(' + total + ') ' : '') + alertBaseTitle;
  const count = document.querySelector('#nav [data-page="Alertes"] .nav-count');
  if (count) count.textContent = total || '';
}

function alertNotify() {
  if (!('Notification' in window) || Notification.permission !== 'granted') return;
  const nouvelles = alertNew().filter(a => !alertNotified.has(a.id + '@' + a.count));
  if (!nouvelles.length) return;
  nouvelles.forEach(a => alertNotified.add(a.id + '@' + a.count));
  const n = new Notification('OpsControl : ' + nouvelles.length + ' nouvelle(s) alerte(s) critique(s)', {
    body: nouvelles.slice(0, 3).map(a => a.source + ' — ' + a.title).join('\n'), tag: 'opscontrol-alertes',
  });
  n.onclick = () => { window.focus(); navigate('Alertes'); };
}

async function loadAlerts() {
  if (alertLoading) { alertReloadPending = true; return; }
  alertLoading = true;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    alertData = await api('/api/alerts', {signal: controller.signal});
    alertFeedError = '';
  } catch (e) {
    alertFeedError = 'Flux d’incidents indisponible.';
    const target = $('#alert-data');
    if (target) target.textContent = e.message;
  } finally {
    clearTimeout(timeout);
    alertLoading = false;
    if (alertReloadPending) { alertReloadPending = false; setTimeout(loadAlerts, 100); }
  }
  alertStrip();
  alertNotify();
  renderHomeCritical();
  const target = $('#alert-data');
  if (target && page === 'Alertes' && !selected) {
    const focus = document.activeElement?.id === 'alert-search';
    target.innerHTML = alertMarkup();
    alertSelects();
    if (focus) { const input = $('#alert-search'); input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
  }
}

function alertSelects() {
  if ($('#alert-source')) $('#alert-source').value = alertSource;
  if ($('#alert-level')) $('#alert-level').value = alertLevel;
  if ($('#alert-fresh')) $('#alert-fresh').value = alertFresh;
}

const navigationBeforeAlerts = navigation;
navigation = function () { navigationBeforeAlerts(); if (alertData) alertStrip(); };

const renderBeforeAlerts = render;
render = function () {
  renderBeforeAlerts();
  renderHomeCritical();
  if (alertData) alertStrip();
  if (page !== 'Alertes' || selected) return;
  $('#content').innerHTML = '<div id="alert-data">' + alertMarkup() + '</div>';
  alertSelects();
};

$('#content').addEventListener('input', e => {
  if (e.target.id !== 'alert-search') return;
  alertQuery = e.target.value;
  $('#alert-data').innerHTML = alertMarkup();
  alertSelects();
  const input = $('#alert-search');
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
});
$('#content').addEventListener('change', e => {
  const map = { 'alert-source': v => alertSource = v, 'alert-level': v => alertLevel = v, 'alert-fresh': v => alertFresh = v };
  if (!map[e.target.id]) return;
  map[e.target.id](e.target.value);
  $('#alert-data').innerHTML = alertMarkup();
  alertSelects();
});
document.addEventListener('click', async e => {
  const niveau = e.target.closest('[data-alert-level]');
  if (niveau) {
    alertLevel = alertLevel === niveau.dataset.alertLevel ? '' : niveau.dataset.alertLevel;
    $('#alert-data').innerHTML = alertMarkup();
    alertSelects();
  }
  const prise = e.target.closest('[data-alert-ack]');
  if (prise) {
    let qui = '';
    try { qui = localStorage.getItem('opscontrol.operateur') || ''; } catch (err) { /* stockage indisponible */ }
    qui = (prompt('Qui prend en charge ? (visible par toute l’équipe)', qui) || '').trim();
    if (!qui) return;
    const note = (prompt('Commentaire (facultatif) : action en cours, ticket…', '') || '').trim();
    try { localStorage.setItem('opscontrol.operateur', qui); } catch (err) { /* stockage indisponible */ }
    try {
      await post('/api/alerts/ack', { id: prise.dataset.alertAck, by: qui.slice(0, 60), note: note.slice(0, 300), hours: 8 });
      toast('Prise en charge enregistrée pour 8 h : bandeau et notifications arrêtés pour toute l’équipe.');
    } catch (error) { toast(error.message); }
    loadAlerts();
    return;
  }
  const liberer = e.target.closest('[data-alert-unack]');
  if (liberer) {
    try { await post('/api/alerts/unack', { id: liberer.dataset.alertUnack }); toast('Prise en charge libérée.'); } catch (error) { toast(error.message); }
    loadAlerts();
    return;
  }
  if (e.target.closest('[data-alert-csv]')) { alertChronicCsv(); return; }
  if (e.target.closest('[data-alert-seen]')) {
    alertRemember(alertUrgent().map(a => a.id + '@' + a.count));
    alertStrip();
    toast('Alertes marquées comme vues : elles restent listées tant que la preuve existe.');
  }
  if (e.target.closest('[data-alert-notify]')) {
    const choix = await Notification.requestPermission();
    toast(choix === 'granted' ? 'Notifications activées pour les nouvelles alertes critiques.' : 'Notifications refusées par le navigateur.');
    if ($('#alert-data')) $('#alert-data').innerHTML = alertMarkup();
  }
});

// Lecture seule et sans SSH : /api/alerts relit l'état déjà collecté. Il est
// interrogé même onglet caché, sinon aucune notification ne pourrait partir.
loadAlerts();
setInterval(loadAlerts, 10000);
setInterval(() => { alertStrip(); renderHomeCritical(); }, 1000);
