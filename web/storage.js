// Onglet « Stockage détaillé » du détail serveur.
//
// Pourquoi pas React/Tailwind : l'application est en JS natif avec une CSP
// stricte (style-src 'self' — aucun style en ligne), et un système de thème déjà
// en place. Introduire React pour un seul onglet imposerait un build, un second
// modèle de rendu et un second jeu de composants à maintenir, pour un gain nul.
// On reste donc dans l'idiome du projet.

subtitles['Stockage'] = 'Disques, partages distants, entrées/sorties et sécurité locale.';

const storageLabels = {
  accessible: 'Accessible', stale: 'Injoignable',
  ok: 'Sain', failed: 'En échec', unknown: 'Non mesuré',
};
const storageClasses = {
  accessible: 'ok', stale: 'critical',
  ok: 'ok', failed: 'critical', unknown: 'unknown',
};

function storageBadge(statut, stale) {
  const cls = stale ? 'unknown' : (storageClasses[statut] || 'unknown');
  return '<span class="badge ' + cls + '">' + (stale ? 'Ancien · ' : '') +
    esc(storageLabels[statut] || statut) + '</span>';
}

function storageSize(ko) {
  if (ko == null) return 'Non mesuré';
  const unites = ['Kio', 'Mio', 'Gio', 'Tio', 'Pio'];
  let v = Number(ko), i = 0;
  while (v >= 1024 && i < unites.length - 1) { v /= 1024; i++; }
  return v.toLocaleString('fr-FR', { maximumFractionDigits: 1 }) + ' ' + unites[i];
}

// Jauge d'occupation. La largeur est posée par CSSOM : la CSP interdit les
// attributs style, mais pas l'écriture depuis un script déjà chargé.
function storageGauge(pct, seuilAlerte, seuilCritique, stale = false) {
  if (pct == null) return '<span class="mini">Non mesuré</span>';
  const niveau = pct >= seuilCritique ? 'critical' : pct >= seuilAlerte ? 'warning' : '';
  return '<div class="metric' + (stale ? ' stale' : '') + '"><span class="metric-label">' +
    (stale ? 'Ancien · ' : '') + esc(pct) + ' %</span>' +
    '<div class="meter ' + (stale ? '' : niveau) + '" role="img" aria-label="' +
    (stale ? 'Ancienne occupation ' : 'Occupation ') + esc(pct) + ' %">' +
    '<i data-fill="' + esc(pct) + '"></i></div></div>';
}

function storageTable(headers, rows) {
  return '<div class="table"><table><thead><tr>' + headers.map(h => '<th>' + esc(h) + '</th>').join('') +
    '</tr></thead><tbody>' + rows.map(r => '<tr>' + r.map(c => '<td>' + (c == null ? '—' : c) + '</td>').join('') + '</tr>').join('') +
    '</tbody></table></div>' + (rows.length ? '' : '<p class="note">Aucune donnée dans cette collecte.</p>');
}

function storageView(h) {
  const d = h.storage;
  if (!d) {
    return '<div class="panel empty">Relevé détaillé non disponible pour ce serveur.<br>' +
      'Il est produit par l’audit SSH : lancer « Auditer ce serveur » puis revenir sur cet onglet.</div>';
  }
  const collectedAt = d.collected_at || h.collected_at;
  const age = Date.now() - Date.parse(collectedAt);
  const stale = Boolean(h.stale || h.audit_retained || h.configuration_changed) ||
    !Number.isFinite(age) || age < 0 || age > 900000;
  const freshness = '<p class="note">Relevé SSH : ' + esc(stamp(collectedAt)) +
    ' · ' + (stale ? 'Anciennes mesures — état actuel non confirmé.' : 'Dernières mesures collectées.') + '</p>';
  let html = '<section class="panel" role="status"><h2>Dernier relevé de stockage</h2>' + freshness +
    '<p>Les mesures de stockage sont renouvelées par l’audit SSH. L’actualisation automatique des API ne les renouvelle pas.</p>';
  if (h.audit_retained && h.last_attempt) {
    html += '<p class="instruction">Échec de la dernière collecte SSH le ' + esc(stamp(h.last_attempt.collected_at)) +
      '. Le relevé précédent est conservé.</p>' +
      (h.last_attempt.issues || []).map(issue => '<p>' + esc(issue) + '</p>').join('');
  }
  html += '<button data-audit-host="' + esc(h.key) + '" ' + (state?.job?.running ? 'disabled' : '') +
    '>Actualiser par audit SSH</button></section>';

  // Les partages distants d'abord : un montage gelé bloque déjà des processus.
  const geles = (d.remote_shares || []).filter(p => p.status === 'stale');
  if (geles.length) {
    html += '<section class="panel"><p role="alert" class="instruction">' +
      geles.length + ' partage(s) distant(s) injoignable(s) : ' +
      esc(geles.map(p => p.mount).join(', ')) +
      (stale ? '. Constat ancien : relancer l’audit pour vérifier leur état actuel.' :
        '. Les accès peuvent se bloquer. Identifier les processus concernés avant d’intervenir.') + '</p></section>';
  }

  html += '<section class="panel"><h2>Partages distants (' + (d.remote_shares || []).length + ')</h2>' + freshness +
    storageTable(['Point de montage', 'Source', 'Type', 'État', 'Droits', 'Occupation', 'Disponible'],
      (d.remote_shares || []).map(p => [
        esc(p.mount), esc(p.source), esc(p.fstype),
        storageBadge(p.status, stale),
        p.access === 'read-only' ? 'Lecture seule' : 'Lecture / écriture',
        storageGauge(p.use_pct, 85, 95, stale),
        esc(storageSize(p.available_kb)),
      ])) + '</section>';

  html += '<section class="panel"><h2>Systèmes de fichiers</h2>' + freshness +
    storageTable(['Point de montage', 'Périphérique', 'Type', 'Occupation', 'Inodes', 'Disponible', 'Total'],
      (d.filesystems || []).map(f => [
        esc(f.mount), esc(f.device), esc(f.fstype),
        storageGauge(f.use_pct, 80, 90, stale),
        storageGauge(f.inodes_use_pct, 80, 90, stale),
        esc(storageSize(f.available_kb)), esc(storageSize(f.total_kb)),
      ])) +
    '<p class="note">Les inodes se saturent indépendamment de l’espace : un disque à 40 % peut refuser toute écriture.</p></section>';

  if ((d.zfs || []).length || (d.lvm || []).length) {
    html += '<div class="waf-columns">';
    if ((d.zfs || []).length) {
      html += '<section class="panel"><h2>Pools ZFS</h2>' +
        storageTable(['Pool', 'Santé', 'Capacité', 'Fragmentation'],
          d.zfs.map(p => [esc(p.pool),
            '<span class="badge ' + (stale ? 'unknown' : p.health === 'ONLINE' ? 'ok' : 'critical') + '">' +
              (stale ? 'Ancien · ' : '') + esc(p.health) + '</span>',
            storageGauge(p.capacity_pct, 80, 90, stale), esc(p.fragmentation_pct) + ' %'])) + '</section>';
    }
    if ((d.lvm || []).length) {
      html += '<section class="panel"><h2>Volumes LVM</h2>' +
        storageTable(['Groupe', 'Volume', 'Taille', 'Attributs'],
          d.lvm.map(v => [esc(v.vg), esc(v.lv),
            esc(storageSize(v.size_bytes == null ? null : Math.round(v.size_bytes / 1024))), esc(v.attr)])) + '</section>';
    }
    html += '</div>';
  }

  html += '<div class="waf-columns"><section class="panel"><h2>Santé physique (SMART)</h2>' +
    storageTable(['Disque', 'État', 'Détail'],
      (d.smart || []).map(s => [esc(s.device), storageBadge(s.status, stale), esc(s.detail)])) +
    '<p class="note">Un état « non mesuré » signale un droit manquant, jamais un disque sain.</p></section>';

  const io = d.io || {};
  html += '<section class="panel"><h2>Entrées / sorties</h2>' +
    '<p>iowait CPU : <b>' + (io.iowait_pct == null ? 'Non mesuré' : esc(io.iowait_pct) + ' %') + '</b></p>' +
    storageTable(['Périphérique', 'Lecture', 'Écriture'],
      (io.devices || []).map(x => [esc(x.device), esc(x.read_kbps) + ' Kio/s', esc(x.write_kbps) + ' Kio/s'])) +
    '<p class="note">Échantillon d’une seconde : une pointe ponctuelle n’est pas une tendance.</p></section></div>';

  html += '<div class="waf-columns"><section class="panel"><h2>Processus les plus consommateurs</h2>' +
    storageTable(['PID', 'Commande', 'CPU', 'Mémoire'],
      (d.top_processes || []).map(p => [esc(p.pid), esc(p.command), esc(p.cpu_pct) + ' %', esc(p.mem_pct) + ' %'])) +
    '</section><section class="panel"><h2>Sécurité locale</h2>' +
    storageTable(['Contrôle', 'Relevé'], [
      ['Pare-feu', esc(d.firewall || 'Non mesuré')],
      ['Fail2ban', esc(d.fail2ban || 'Non mesuré')],
      ['Échecs SSH (24 h)', d.ssh_failed_24h == null ? 'Non mesuré' : esc(d.ssh_failed_24h)],
      ['Ports en écoute', d.listening_ports == null ? 'Non mesuré' : esc(d.listening_ports)],
    ]) + '</section></div>';

  html += '<p class="note">' + esc(d.scope) + '</p>';
  return html;
}

// Pose les largeurs de jauge après insertion : la CSP bloque les attributs
// style dans le HTML, pas l'écriture CSSOM depuis un script déjà chargé.
function storageApplyGauges() {
  document.querySelectorAll('#content .meter i[data-fill]').forEach(el => {
    const v = Math.max(0, Math.min(100, Number(el.dataset.fill) || 0));
    el.style.setProperty('width', v + '%');
  });
}

// Nouvel onglet dans le détail serveur, sans toucher au rendu existant.
const detailBeforeStorage = detailView;
detailView = function (h) {
  let html = detailBeforeStorage(h);
  const onglets = '<div class="tabs">';
  const point = html.indexOf(onglets);
  if (point >= 0) {
    const fin = html.indexOf('</div>', point) ;
    const bouton = '<button class="' + (detailTab === 'storage' ? 'active' : '') + '" data-tab="storage">Stockage détaillé</button>';
    html = html.slice(0, fin) + bouton + html.slice(fin);
  }
  if (detailTab === 'storage') html += storageView(h);
  return html;
};

const renderBeforeStorage = render;
render = function () {
  renderBeforeStorage();
  if (selected && detailTab === 'storage') storageApplyGauges();
};
