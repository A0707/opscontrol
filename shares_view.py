"""Vue des dossiers partagés : un partage, tous ses clients, une seule ligne.

Chaque audit SSH relève les montages NFS/CIFS du CLIENT (storage_probe) et,
depuis cette version, les exports servis par le SERVEUR. Pris serveur par
serveur, ces relevés disent « /var/nfs_share est à 80 % » neuf fois — Zabbix
levait d'ailleurs dix alertes pour un seul volume. Ici on croise les deux côtés
par la source « serveur:/chemin » : un partage plein est UN problème, et un
partage injoignable depuis 2 clients sur 9 pointe vers ces 2 clients (réseau,
montage) plutôt que vers le serveur.

Doctrine inchangée : rien n'est calculé qui n'a été mesuré. Un partage sans
mesure d'occupation reste « non mesuré », un export sans client observé n'est
pas « inutilisé » — seuls les serveurs audités par OpsControl sont visibles.
"""
from __future__ import annotations

import alert_policy as policy

# Seuils : ceux de la politique commune (alert_policy.DISK_PCT).
SEUIL_ALERTE = 90
SEUIL_CRITIQUE = 95
SEUIL_PREVENTIF = 80


def _serveur(source):
    """« 192.0.2.47:/var/nfs_share » -> (serveur, chemin). CIFS : //srv/partage."""
    if source.startswith('//'):
        serveur, _, reste = source[2:].partition('/')
        return serveur, '/' + reste
    serveur, _, chemin = source.partition(':')
    return (serveur, chemin) if chemin else ('', source)


def build(rows):
    par_ip = {h['ip']: h for h in rows if h.get('ip')}
    par_nom = {}
    for h in rows:
        for nom in (h.get('key'), h.get('name')):
            if nom:
                par_nom[nom.lower()] = h
                par_nom[nom.lower().split('.')[0]] = h

    def hote(serveur):
        s = (serveur or '').lower()
        return par_ip.get(serveur) or par_nom.get(s) or par_nom.get(s.split('.')[0])

    partages = {}

    def entree(serveur, chemin):
        proprietaire = hote(serveur)
        cle = ((proprietaire or {}).get('ip') or serveur) + ':' + chemin
        if cle not in partages:
            partages[cle] = {
                'key': cle, 'server': serveur, 'path': chemin,
                'server_host': {k: proprietaire[k] for k in ('key', 'name', 'ip')} if proprietaire else None,
                'protocol': None, 'export': None, 'clients': [],
            }
        return partages[cle]

    for h in rows:
        stockage = h.get('storage') if isinstance(h.get('storage'), dict) else {}
        mesure = {'collected_at': h.get('collected_at'), 'stale': bool(h.get('stale', True))}
        for m in stockage.get('remote_shares') or []:
            serveur, chemin = _serveur(m.get('source') or '')
            p = entree(serveur, chemin)
            p['protocol'] = p['protocol'] or (m.get('fstype') or '').upper()
            p['clients'].append({'key': h['key'], 'name': h.get('name') or h['key'], 'mount': m.get('mount'),
                                 'status': m.get('status'), 'access': m.get('access'),
                                 'use_pct': m.get('use_pct'), 'total_kb': m.get('total_kb'),
                                 'available_kb': m.get('available_kb'), **mesure})
        for e in stockage.get('exports') or []:
            p = entree(h.get('ip') or h['key'], e['path'])
            p['protocol'] = e['protocol']
            p['export'] = {'clients': e.get('clients'), 'name': e.get('name'), 'use_pct': e.get('use_pct'), **mesure}

    resultat = []
    for p in partages.values():
        clients, export = p['clients'], p['export']
        # La mesure du serveur prime : c'est le volume lui-même. À défaut, la plus
        # haute valeur vue par un client (ils lisent tous le même volume).
        mesures = [c['use_pct'] for c in clients if c['use_pct'] is not None]
        use = export['use_pct'] if export and export['use_pct'] is not None else (max(mesures) if mesures else None)
        gelés = [c for c in clients if c['status'] == 'stale']
        # Occupation graduée par la politique commune : pourcentage, espace libre
        # absolu (volume serveur ou vu d'un client) — même grille que les disques.
        libres = [c for c in clients if c.get('available_kb') is not None]
        ref = max(libres, key=lambda c: c['use_pct'] or 0) if libres else {}
        statut, raisons = policy.disk(use, ref.get('total_kb'), ref.get('available_kb'))
        raisons = ['Occupé à ' + r.removesuffix(' occupé') if r.endswith(' % occupé') else r for r in raisons]
        if gelés:
            statut = 'critical'
            raisons.insert(0, f"Injoignable depuis {len(gelés)} client(s) sur {len(clients)}")
        if use is None and not gelés:
            statut = 'unknown'
            raisons.append('Occupation non mesurée')
        statut = statut or 'ok'
        dates = [c['collected_at'] for c in clients if c['collected_at']] + ([export['collected_at']] if export and export['collected_at'] else [])
        resultat.append({
            **p, 'use_pct': use, 'status': statut, 'reasons': raisons,
            'clients_count': len(clients), 'stale_clients': len(gelés),
            'read_only_clients': sum(c['access'] == 'read-only' for c in clients),
            # Une seule mesure récente suffit à dater le partage ; aucune = ancien.
            'fresh': any(not c['stale'] for c in clients) or bool(export and not export['stale']),
            'observed_at': max(dates) if dates else None,
        })
    rang = {'critical': 0, 'warning': 1, 'preventive': 2, 'unknown': 3, 'ok': 4}
    resultat.sort(key=lambda p: (rang[p['status']], -(p['use_pct'] or 0), p['key']))
    compte = {s: sum(p['status'] == s for p in resultat) for s in rang}
    audites = sum(1 for h in rows if isinstance(h.get('storage'), dict))
    exports_connus = sum(1 for h in rows if isinstance(h.get('storage'), dict) and h['storage'].get('exports') is not None)
    return {
        'shares': resultat, 'counts': compte,
        'thresholds': {'preventive': SEUIL_PREVENTIF, 'warning': SEUIL_ALERTE, 'critical': SEUIL_CRITIQUE},
        'scope': (f'{audites} serveur(s) avec relevé de stockage, dont {exports_connus} avec relevé des exports. '
                  'Un partage n’apparaît que s’il est monté ou exporté par un serveur audité ; '
                  'les clients hors inventaire OpsControl ne sont pas visibles.'),
    }


def install(app, context):
    @app.get('/api/shares')
    def shares():
        return build(context.rows())
