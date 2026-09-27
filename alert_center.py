"""Centre d'alertes : les anomalies de TOUTES les sources, regroupées par cause,
graduées par UNE politique commune (alert_policy).

Pourquoi un module de plus alors que chaque page affiche déjà ses anomalies :
un exploitant ne doit pas ouvrir sept pages pour savoir s'il a un incident.
Une agrégation naïve peut répéter une même cause pour plusieurs cibles ou pour
chaque occurrence historique. D'où :

1. Une alerte = une CAUSE et un NIVEAU, avec la liste des cibles touchées et
   leur nombre exact. Le même service en échec sur 6 serveurs est une ligne.
2. La gravité vient de alert_policy, pas de la source. Les mesures SSH
   (disque, inodes, mémoire, services, partages) sont graduées à partir des
   valeurs brutes ; les triggers Zabbix sont requalifiés, et un disque mesuré en
   SSH l'emporte sur le texte du trigger. La gravité d'origine reste affichée.
3. Le préventif repose sur la TENDANCE : la pente de remplissage est calculée
   sur l'historique des audits déjà conservés (audit_snapshots).
4. Chaque alerte porte la date de sa preuve. Une alerte ancienne reste affichée
   (« à confirmer ») mais n'est jamais comptée comme confirmée.

Ce module lit ce qui a déjà été collecté ; il ne déclenche aucune collecte et
n'agit sur aucun système.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

import alert_policy as policy
from asset_registry import connection_evidence
from daily_view import summarize_issue
from synchronization import fresh
from pydantic import BaseModel, ConfigDict, Field

ECHANTILLON = 25
# Au-delà, une anomalie ouverte n'est plus un incident à traiter dans l'heure :
# c'est une alerte probablement jamais refermée. Elle reste visible, à part.
CHRONIC_DAYS = 30
ACK_MAX_HOURS = 72


def _instant(valeur):
    """Epoch (Zabbix) ou ISO (sondes) -> secondes ; None si illisible."""
    if valeur in (None, ''):
        return None
    try:
        return float(valeur) if str(valeur).replace('.', '', 1).isdigit() else \
            datetime.fromisoformat(str(valeur).replace('Z', '+00:00')).timestamp()
    except (TypeError, ValueError):
        return None
# Mémoire d'hyperviseur au-delà de laquelle un nœud risque de ne plus pouvoir
# absorber une bascule.
SEUIL_MEMOIRE_NOEUD = 90
# Systèmes de fichiers sans intérêt d'exploitation, pour l'ancien relevé `df`.
PSEUDO_FS = re.compile(r'^(tmpfs|devtmpfs|udev|overlay|shm|none|efivarfs)$')
# Constats d'audit déjà gradués ici à partir de la mesure brute.
GRADUES = re.compile(r'^(disk_max|ram|cpu|inode:.*|service:.*|mount:.*|ssh)$')


class _Collecte:
    def __init__(self, now=None):
        self.alertes = {}
        self.now = (now or datetime.now(timezone.utc)).timestamp()

    def ajouter(self, source, cause, severite, titre, cible=None, preuve=None, observe=None,
                recent=False, lien=None, detail=None, regle=None, origine=None,
                measurement_at=None, started_at=None):
        """Ajoute une cible à l'alerte `source:cause:niveau`, ou la crée."""
        if severite not in policy.RANK:
            return
        # Une cible ouverte depuis plus de CHRONIC_DAYS rejoint un groupe à part :
        # une nouvelle occurrence du même problème reste, elle, un incident.
        debut = _instant(started_at)
        chronique = debut is not None and self.now - debut > CHRONIC_DAYS * 86400
        cle = f'{source}:{cause}:{severite}' + (':chronique' if chronique else '')
        a = self.alertes.get(cle)
        if a is None:
            a = self.alertes[cle] = {'id': cle, 'source': source, 'severity': severite,
                                     'severity_label': policy.LABELS[severite], 'delay': policy.DELAYS[severite],
                                     'title': titre, 'evidence': preuve, 'rule': regle,
                                     'source_severity': origine, 'targets': [], 'count': 0,
                                     'observed_at': observe, 'fresh': False, '_titres': set(),
                                     'chronic': chronique}
        a['fresh'] = a['fresh'] or bool(recent)
        a['_titres'].add(titre)
        if observe and (not a['observed_at'] or observe > a['observed_at']):
            a['observed_at'] = observe
        if cible is not None:
            a['count'] += 1
            if len(a['targets']) < ECHANTILLON:
                a['targets'].append({'name': cible, 'host_key': lien, 'detail': detail or titre,
                                     'observed_at': observe, 'fresh': bool(recent),
                                     'measurement_at': measurement_at, 'started_at': started_at})
        elif not a['count']:
            a['count'] = 1


def _cause_zabbix(description):
    """« Proxmox: VM [physical3/VM 9000 (qemu/9000)]: Not running » ×42 → une cause."""
    return re.sub(r'\[[^\]]*\]', '[…]', description or 'Trigger sans description').strip()


# --- Historique des audits : tendances disque et CPU soutenu ---------------------
_cache = {}


def historique(context):
    """{clé: {'disks': {montage: [(ts, used_kb, total_kb)]}, 'cpu': [récent d'abord]}}.

    Relit uniquement les serveurs dont un nouvel audit est apparu depuis le
    dernier appel : la page interroge cette vue chaque minute.
    """
    connect = getattr(context, 'connect', None)
    if connect is None:
        return {}
    try:
        with connect() as db:
            derniers = dict(db.execute('SELECT key, max(ts) FROM audit_snapshots GROUP BY key').fetchall())
            for cle, ts in derniers.items():
                if _cache.get(cle, (None,))[0] == ts:
                    continue
                disques, cpu = {}, []
                for date, charge in db.execute('SELECT ts, payload FROM audit_snapshots WHERE key=? ORDER BY ts DESC',
                                               (cle,)):
                    audit = json.loads(charge)
                    cpu.append(audit.get('cpu'))
                    stockage = audit.get('storage') if isinstance(audit.get('storage'), dict) else {}
                    for fs in stockage.get('filesystems') or []:
                        disques.setdefault(fs.get('mount'), []).append((date, fs.get('used_kb'), fs.get('total_kb')))
                _cache[cle] = (ts, {'disks': disques, 'cpu': cpu})
    except Exception:  # noqa: BLE001 — une base illisible prive de tendance, pas d'alertes
        return {}
    return {cle: v[1] for cle, v in _cache.items()}


def _mesures_disque(h):
    """Systèmes de fichiers locaux, du relevé détaillé si présent, sinon de df."""
    stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
    if stockage.get('filesystems'):
        return stockage['filesystems']
    return [{'mount': f.get('mount'), 'use_pct': f.get('use_pct')} for f in h.get('filesystems') or []
            if not PSEUDO_FS.match(str(f.get('fs') or '')) and not str(f.get('mount') or '').startswith(('/dev', '/run', '/sys'))]


def _ssh(c, rows, histo):
    injoignables = {}
    for h in rows:
        recent, observe = not h.get('stale', True), h.get('collected_at')
        nom, cle = h.get('name') or h['key'], h['key']
        if h.get('status') == 'unreachable':
            injoignables.setdefault(summarize_issue((h.get('issues') or [None])[0]), []).append(h)
            continue
        passe = histo.get(cle, {})
        ajout = lambda cause, niveau, titre, detail, regle: c.ajouter(
            'SSH', cause, niveau, titre, nom, None, observe, recent, cle, detail, regle)

        for fs in _mesures_disque(h):
            jours = policy.days_to_full(passe.get('disks', {}).get(fs.get('mount'), []))
            niveau, raisons = policy.disk(fs.get('use_pct'), fs.get('total_kb'), fs.get('available_kb'), jours)
            if niveau:
                ajout('disk', niveau, f'Espace disque — {policy.LABELS[niveau].lower()}',
                      f"{fs.get('mount')} : {' · '.join(raisons)}", 'Disque')
            niveau, raisons = policy.inodes(fs.get('inodes_use_pct'))
            if niveau:
                ajout('inodes', niveau, f'Inodes — {policy.LABELS[niveau].lower()}',
                      f"{fs.get('mount')} : {' · '.join(raisons)}", 'Inodes')

        niveau, raisons = policy.memory(h.get('ram'))
        if niveau:
            ajout('memory', niveau, f'Mémoire — {policy.LABELS[niveau].lower()}', ' · '.join(raisons), 'Mémoire')
        cpus = passe.get('cpu') or [h.get('cpu')]
        niveau, raisons = policy.cpu(cpus)
        if niveau:
            ajout('cpu', niveau, 'Charge CPU soutenue', ' · '.join(raisons), 'CPU')
        niveau, raisons = policy.uptime(h.get('uptime'))
        if niveau:
            ajout('uptime', niveau, 'Serveurs sans redémarrage depuis plus d’un an', ' · '.join(raisons), 'Système')

        stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
        for pool in stockage.get('zfs') or []:
            etat = str(pool.get('health') or '').upper()
            niveau = 'critical' if etat in ('FAULTED', 'UNAVAIL', 'SUSPENDED') else 'warning' if etat == 'DEGRADED' else None
            if niveau:
                ajout('zfs', niveau, 'Pool ZFS ' + etat, f"pool {pool.get('pool')}", 'ZFS / SMART')
        for d in stockage.get('smart') or []:
            if d.get('status') == 'failed':
                ajout('smart', 'critical', 'Disque physique en échec SMART', f"{d.get('device')} : {d.get('detail')}",
                      'ZFS / SMART')

        declares = set(h.get('services') or [])
        for f in h.get('findings') or []:
            ident = str(f.get('id', ''))
            if ident.startswith('service:'):
                unite = ident[len('service:'):]
                niveau, raisons = policy.service(unite, declares)
                c.ajouter('SSH', ident, niveau, f'Service {unite} en échec', nom, None, observe, recent, cle,
                          ' · '.join(raisons), 'Services', 'Audit : ' + str(f.get('severity')))
            elif not GRADUES.match(ident) and f.get('severity') in ('critical', 'warning'):
                # Constat d'audit hors grille (durcissement SSH, journaux…) : un
                # écart sans rupture de service se planifie, il ne réveille pas.
                niveau = 'critical' if f['severity'] == 'critical' else 'preventive'
                c.ajouter('SSH', ident, niveau, f.get('title') or ident, nom, None, observe, recent, cle,
                          f.get('title'), 'Constat d’audit', 'Audit : ' + f['severity'])

    for cause, hotes in injoignables.items():
        for h in hotes:
            c.ajouter('SSH', 'unreachable:' + cause, 'warning', 'Serveur injoignable en SSH — ' + cause,
                      h.get('name') or h['key'], 'Perte de visibilité : l’état réel du serveur est inconnu',
                      h.get('collected_at'), not h.get('stale', True), h['key'])


def _mesure_ssh(rows_par_cle, cle, volume):
    """Mesure SSH du volume nommé par un trigger Zabbix, local ou partage monté."""
    h = rows_par_cle.get(cle)
    if not h or not volume or h.get('stale', True):
        return None, None
    stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
    for fs in list(_mesures_disque(h)) + list(stockage.get('remote_shares') or []):
        if fs.get('mount') == volume:
            return fs, h
    return None, h


def build(context, now=None):
    now = now or datetime.now(timezone.utc)
    rows = context.rows()
    connexions = context.api_connections()
    histo = historique(context)
    c = _Collecte(now)
    par_nom, par_cle = {}, {h['key']: h for h in rows}
    for h in rows:
        for nom in (h.get('key'), h.get('name'), h.get('ip')):
            if nom:
                par_nom.setdefault(str(nom).lower().rstrip('.'), set()).add(h['key'])

    def lien(nom):
        n = str(nom or '').lower()
        matches = par_nom.get(n.rstrip('.'), set())
        return next(iter(matches)) if len(matches) == 1 else None

    _ssh(c, rows, histo)

    # --- Voie rapide : sonde directe des serveurs critiques (tier0.py) ----------
    # Preuve de moins de 5 s : toujours « récente » tant que la sonde tourne.
    sonde = getattr(context, 'tier0_snapshot', None)
    if sonde is not None:
        etat_sonde = sonde()
        obs = etat_sonde.get('observer') or {}
        if obs.get('ok') is False:
            # La sonde ne conclut rien sur les serveurs pendant ce temps : ce trou de
            # surveillance est lui-même une alerte, jamais un silence.
            c.ajouter('Sonde directe', 'observer', 'warning', 'Chemin de mesure perturbé : serveurs critiques non vérifiables',
                      None, 'La référence ' + str(obs.get('reference')) + ' ne répond pas non plus (poste, VPN ou réseau).',
                      obs.get('checked_at'), fresh(obs.get('checked_at')), regle='Voie rapide')
        for s in etat_sonde['hosts']:
            if s.get('status') == 'down':
                c.ajouter('Sonde directe', 'down', 'critical', 'Serveur critique HORS SERVICE',
                          s['name'], 'ICMP et TCP ' + str(s.get('port')) + ' sans réponse sur deux sondes consécutives',
                          s.get('checked_at'), fresh(s.get('checked_at')), s['key'],
                          'Hors service depuis ' + str(s.get('down_since')), 'Voie rapide',
                          started_at=s.get('down_since'))
            elif s.get('status') == 'degraded':
                perdu = [n for n, ok in (('ICMP', s.get('ping')), ('TCP ' + str(s.get('port')), s.get('tcp'))) if ok is not True]
                c.ajouter('Sonde directe', 'degraded', 'warning', 'Serveur critique dégradé',
                          s['name'], None, s.get('checked_at'), fresh(s.get('checked_at')), s['key'],
                          'Sans réponse : ' + ', '.join(perdu), 'Voie rapide')

    # --- Partages : un partage = une alerte, pas une par client -----------------
    from shares_view import build as partages
    for p in partages(rows)['shares']:
        if p['status'] in policy.RANK:
            c.ajouter('Partages', p['key'], p['status'], 'Partage ' + p['key'] + ' — ' + ' · '.join(p['reasons']),
                      p['key'], f"{p['clients_count']} client(s) observé(s)", p['observed_at'], p['fresh'],
                      (p.get('server_host') or {}).get('key'), regle='Partages')

    # --- Sources API --------------------------------------------------------------
    sources = []
    for conn in connexions:
        r = connection_evidence(conn)
        inv, provider = r.get('inventory') or {}, conn.get('provider')
        observe, recent = r.get('collected_at'), r.get('status') == 'observed' and fresh(r.get('collected_at'))
        if provider == 'Zabbix':
            try:
                age = (now - datetime.fromisoformat(observe)).total_seconds()
                recent = r.get('status') == 'observed' and 0 <= age <= 30
            except (TypeError, ValueError):
                recent = False
        sources.append({'key': conn.get('key'), 'name': conn.get('name'), 'provider': provider,
                        'collected_at': observe, 'fresh': recent, 'error': r.get('error'),
                        'max_age_seconds': 30 if provider == 'Zabbix' else 900})
        if r.get('error'):
            # Une source muette n'est pas une source saine : ses alertes sont anciennes.
            c.ajouter(provider, 'collection', 'warning', f"Collecte {conn.get('name')} en échec",
                      None, r.get('error'), (conn.get('last_result') or {}).get('collected_at'),
                      fresh((conn.get('last_result') or {}).get('collected_at')))

        if provider == 'Zabbix':
            for pb in inv.get('problems') or []:
                description, cause = pb.get('description'), _cause_zabbix(pb.get('description'))
                niveau, raison, requalifie = policy.zabbix(description, pb.get('severity'))
                origine = 'Zabbix : ' + str(pb.get('severity_label') or pb.get('severity'))
                for hote in pb.get('hosts') or [None]:
                    cle, niv, motif = lien(hote), niveau, raison
                    if niveau == 'disk':
                        fs, h = _mesure_ssh(par_cle, cle, policy.zabbix_volume(description))
                        if fs is not None:
                            niv, raisons = policy.disk(fs.get('use_pct'), fs.get('total_kb'), fs.get('available_kb'))
                            niv = niv or 'info'
                            motif = 'requalifié par la mesure SSH : ' + (' · '.join(raisons) or f"{fs.get('use_pct')} % occupé")
                        else:
                            # « moins de 20 % libre » = ≥ 80 % : préventif selon la grille disque.
                            niv, motif = 'preventive', 'seuil Zabbix sans mesure SSH du volume : grille disque ≥ 80 %'
                    c.ajouter('Zabbix', cause, niv, cause,
                              hote or 'Hôte non renseigné', None, observe, recent,
                              cle, motif, 'Zabbix' if requalifie else 'Zabbix (non couvert)', origine,
                              measurement_at=pb.get('measurement_at'), started_at=pb.get('last_change'))
        elif provider == 'Bacula':
            from bacula_inventory import latest_jobs
            courant = latest_jobs(inv)
            for j in courant:
                client = (j.get('client') or '').removesuffix('-fd')
                c.ajouter('Bacula', 'job:' + j['name'], j.get('severity'),
                          f"Sauvegarde {j['name']} : {j.get('status_label')} au dernier passage",
                          client or j['name'], 'Fin : ' + str(j.get('endtime') or 'non terminée'),
                          observe, recent, lien(client), regle='Sauvegardes')
        elif provider == 'Wazuh':
            for d in inv.get('daemons') or []:
                if d.get('status') == 'failed':
                    c.ajouter('Wazuh', 'daemon:' + d['name'], 'critical', 'Démon Wazuh en échec : ' + d['name'],
                              None, None, observe, recent)
            for etat in (inv.get('agents') or {}).get('states') or []:
                if etat.get('key') == 'disconnected' and etat.get('count'):
                    c.ajouter('Wazuh', 'agents:disconnected', 'warning',
                              f"{etat['count']} agent(s) Wazuh déconnecté(s)", None,
                              'Perte de visibilité sécurité sur ces serveurs', observe, recent)
        elif provider == 'Elasticsearch':
            ind = r.get('indicators') or {}
            statut = ind.get('cluster_status')
            if statut in ('red', 'yellow'):
                c.ajouter('Elastic', 'cluster', 'critical' if statut == 'red' else 'warning',
                          f"Cluster Elasticsearch {statut}", None,
                          f"{ind.get('unassigned_shards', 'N/A')} shard(s) non assigné(s) · "
                          + ('données indisponibles' if statut == 'red' else 'redondance des réplicas perdue'),
                          observe, recent)
        elif provider == 'Proxmox':
            for n in inv.get('nodes') or []:
                if n.get('status') not in (None, 'online'):
                    c.ajouter('Proxmox', 'node-offline', 'critical', 'Nœud Proxmox hors ligne',
                              n.get('name'), n.get('status'), observe, recent)
                total = n.get('memory_total_bytes')
                if total and n.get('memory_bytes') is not None:
                    pct = round(100 * n['memory_bytes'] / total)
                    if pct >= SEUIL_MEMOIRE_NOEUD:
                        c.ajouter('Proxmox', 'node-memory', 'warning',
                                  f'Mémoire hyperviseur ≥ {SEUIL_MEMOIRE_NOEUD} % : bascule compromise',
                                  f"{n.get('name')} ({pct} %)", None, observe, recent)

    alertes = sorted(c.alertes.values(),
                     key=lambda a: (a['chronic'], not a['fresh'], policy.RANK[a['severity']], -a['count'], a['title']))
    prises = acknowledgements(context, now)
    for a in alertes:
        a['max_age_seconds'] = 30 if a['source'] == 'Zabbix' else 900
        a['truncated'] = a['count'] > len(a['targets'])
        # Un même titre ne peut pas décrire des valeurs différentes : le titre
        # devient générique, la valeur reste par cible.
        if len(a.pop('_titres')) > 1:
            a['title'] = a['title'].split(' : ')[0] + ' : seuil dépassé (valeur par serveur)'
        # Prise en charge valable tant qu'elle n'a pas expiré et que l'alerte ne
        # s'est pas étendue (nouvelle cible = nouvelle information à voir).
        p = prises.get(a['id'])
        a['ack'] = p if p and a['count'] <= p['count'] else None
    # Les compteurs d'incidents excluent les chroniques : elles ont leur propre compte.
    actives = [a for a in alertes if not a['chronic']]
    compte = lambda sev, rec: sum(1 for a in actives if a['severity'] == sev and a['fresh'] == rec)
    counts = {}
    for sev in policy.LEVELS:
        counts[sev], counts[sev + '_stale'] = compte(sev, True), compte(sev, False)
    counts['targets_critical'] = sum(a['count'] for a in actives if a['severity'] == 'critical' and a['fresh'])
    counts['chronic'] = sum(1 for a in alertes if a['chronic'] and a['severity'] != 'info')
    counts['acknowledged'] = sum(1 for a in actives if a['ack'])
    return {
        'generated_at': now.isoformat(),
        'alerts': alertes,
        'counts': counts,
        'levels': [{'key': k, 'label': policy.LABELS[k], 'delay': policy.DELAYS[k]} for k in policy.LEVELS],
        'policy': policy.RULES,
        'sources': sources,
        'scope': ('Anomalies déjà collectées, regroupées par cause et graduées par la politique OpsControl '
                  '(gravité d’origine conservée à titre indicatif). Zabbix : lecture API de moins de 30 secondes ; '
                  'autres sources : preuve de moins de 15 minutes. L’âge des items Zabbix est distinct ; '
                  'une alerte ancienne reste affichée mais n’est pas comptée comme confirmée. '
                  'Aucune collecte n’est déclenchée par cette vue et aucune action n’est exécutée.'),
    }


def acknowledgements(context, now):
    """Prises en charge en cours : {id d'alerte: {...}}. Expirées = ignorées."""
    connect = getattr(context, 'connect', None)
    if connect is None:
        return {}
    try:
        with connect() as db:
            lignes = db.execute('SELECT id, count, by, note, at, until FROM alert_acks WHERE until > ?',
                                (now.isoformat(),)).fetchall()
    except Exception:  # noqa: BLE001 — table absente ou base occupée : aucune prise en charge
        return {}
    return {i: {'count': n, 'by': b, 'note': t, 'at': a, 'until': u} for i, n, b, t, a, u in lignes}


class Ack(BaseModel):
    """« Je m'en occupe » : visible par tous, arrête bandeau et notifications.

    Sans authentification dans OpsControl, « by » est déclaratif : c'est une
    coordination d'équipe, pas une preuve d'identité.
    """
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)
    by: str = Field(min_length=1, max_length=60)
    note: str = Field(default='', max_length=300)
    hours: int = Field(default=8, ge=1, le=ACK_MAX_HOURS)

class Release(BaseModel):
    model_config = ConfigDict(extra='forbid')
    id: str = Field(min_length=3, max_length=400)


def install(app, context):
    from datetime import timedelta
    from fastapi import HTTPException

    with context.connect() as db:
        db.execute('CREATE TABLE IF NOT EXISTS alert_acks(id TEXT PRIMARY KEY, count INTEGER, by TEXT, '
                   'note TEXT, at TEXT, until TEXT)')

    @app.get('/api/alerts')
    def alerts():
        return build(context)

    @app.post('/api/alerts/ack')
    def acknowledge(ack: Ack):
        now = datetime.now(timezone.utc)
        # Seule une alerte réellement présente peut être prise en charge.
        alerte = next((a for a in build(context, now)['alerts'] if a['id'] == ack.id), None)
        if alerte is None:
            raise HTTPException(404, 'Alerte inconnue ou déjà résolue')
        fin = (now + timedelta(hours=ack.hours)).isoformat()
        with context.connect() as db:
            db.execute('DELETE FROM alert_acks WHERE until <= ?', (now.isoformat(),))
            db.execute('INSERT OR REPLACE INTO alert_acks VALUES(?,?,?,?,?,?)',
                       (ack.id, alerte['count'], ack.by.strip(), ack.note.strip(), now.isoformat(), fin))
        return {'id': ack.id, 'count': alerte['count'], 'by': ack.by.strip(), 'note': ack.note.strip(),
                'at': now.isoformat(), 'until': fin}

    @app.post('/api/alerts/unack')
    def release(item: Release):
        with context.connect() as db:
            db.execute('DELETE FROM alert_acks WHERE id=?', (item.id,))
        return {'id': item.id, 'released': True}
