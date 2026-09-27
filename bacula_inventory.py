"""Normalize Baculum/Bacularis API v2 answers into backup job evidence.

Contrat identique aux autres normaliseurs : on ne convertit jamais une absence
de mesure en résultat sain. En particulier, un job marqué « terminé sans
erreur » prouve que Bacula a fini son travail — pas que la sauvegarde est
restaurable. Le vocabulaire choisi ici ne doit jamais laisser croire l'inverse.

Réponse attendue (Baculum API v2) : {"error": 0, "output": [ {...}, ... ]}
Les réponses en erreur portent un `error` non nul et sont déjà interceptées en
amont par collect_connection.
"""

# Codes JobStatus de Bacula. Seuls ceux dont le sens est stable sont traduits ;
# tout code inconnu reste 'unknown' plutôt que d'être rangé arbitrairement.
JOB_STATUS = {
    'T': ('Terminé sans erreur', 'ok'),
    'W': ('Terminé avec avertissements', 'warning'),
    'E': ('Terminé en erreur', 'critical'),
    'f': ('Erreur fatale', 'critical'),
    'A': ('Annulé', 'warning'),
    'R': ('En cours', 'running'),
    'C': ('Créé, pas encore lancé', 'pending'),
    'B': ('Bloqué', 'warning'),
    'D': ('Vérification différée', 'pending'),
    'I': ('Incomplet', 'warning'),
}

# Familles utilisées pour les compteurs. 'unknown' n'est jamais fusionné
# avec 'ok' : un état non reconnu reste un trou de couverture.
FAMILIES = ('ok', 'warning', 'critical', 'running', 'pending', 'unknown')

# Passages conservés pour l'historique détaillé (les compteurs portent sur tous).
HISTORY_KEPT = 500


def latest_jobs(inventory):
    """Last observed passage per job AND client, including jobs outside history."""
    latest = {}
    for entry in [*(inventory.get('latest') or []), *(inventory.get('jobs') or [])]:
        identity = (entry.get('name'), entry.get('client'))
        previous = latest.get(identity)
        if previous is None or (entry.get('jobid') or 0) > (previous.get('jobid') or 0):
            latest[identity] = entry
    return list(latest.values())


def _text(value, limit=200):
    return str(value)[:limit] if value is not None else None


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        try:
            return int(value)
        except (TypeError, ValueError):
            return None
    return value


def _rows(payload):
    """Extrait la liste `output` d'une réponse Baculum, sinon lève."""
    if not isinstance(payload, dict) or not isinstance(payload.get('output'), list):
        raise ValueError('Bacula response invalid')
    return [row for row in payload['output'] if isinstance(row, dict)]


def jobs(payload):
    """Normalise /api/v2/jobs en évidences de sauvegarde exploitables."""
    rows = _rows(payload)
    counts = dict.fromkeys(FAMILIES, 0)
    entries = []
    last_success = None
    for row in rows:
        code = _text(row.get('jobstatus'), 2)
        label, family = JOB_STATUS.get(code, ('État non reconnu', 'unknown'))
        counts[family] += 1
        end = _text(row.get('endtime'), 32)
        if family == 'ok' and end and (last_success is None or end > last_success):
            last_success = end
        entries.append({
            'jobid': _number(row.get('jobid')),
            'name': _text(row.get('name')) or 'Job non nommé',
            'client': _text(row.get('client')) or _text(row.get('clientid'), 32),
            'level': _text(row.get('level'), 2),
            'status_code': code,
            'status_label': label,
            'severity': family,
            'endtime': end,
            'bytes': _number(row.get('jobbytes')),
            'files': _number(row.get('jobfiles')),
        })
    # État ACTUEL : le dernier passage de chaque job. Les compteurs ci-dessus
    # portent sur tout l'historique renvoyé par l'API, potentiellement très long,
    # peut produire des milliers d'« erreurs » alors qu'un seul job échoue encore. Afficher ce
    # total comme un état revient à fabriquer de la fatigue d'alerte.
    rank = {'critical': 0, 'warning': 1, 'unknown': 2, 'running': 3, 'pending': 4, 'ok': 5}
    latest = {}
    for entry in entries:
        identity = (entry['name'], entry['client'])
        known = latest.get(identity)
        if known is None or (entry['jobid'] or 0) > (known['jobid'] or 0):
            latest[identity] = entry
    current = sorted(latest.values(), key=lambda j: (rank.get(j['severity'], 9), j['name']))
    latest_counts = dict.fromkeys(FAMILIES, 0)
    for entry in current:
        latest_counts[entry['severity']] += 1
    ends = [j['endtime'] for j in entries if j['endtime']]
    # Historique borné aux passages les plus récents : l'interface n'en montre
    # que 500, et stocker 12 000 jobs pesait 3 Mo à chaque lecture des connexions.
    recent = sorted(entries, key=lambda j: -(j['jobid'] or 0))[:HISTORY_KEPT]
    # Les anomalies d'abord, puis le plus récent : c'est l'ordre de lecture
    # d'un exploitant qui vient vérifier ses sauvegardes de la nuit.
    recent.sort(key=lambda j: (rank.get(j['severity'], 9), -(j['jobid'] or 0)))
    return {
        'jobs': recent,
        'jobs_truncated': len(entries) - len(recent),
        'latest': current,
        'latest_counts': latest_counts,
        'history_since': min(ends) if ends else None,
        'counts': counts,
        'jobs_count': len(entries),
        'last_success': last_success,
        'scope': ('Jobs visibles par ce compte API. Un job « terminé sans erreur » prouve que Bacula a '
                  'terminé son traitement, pas que la sauvegarde est restaurable : seul un test de '
                  'restauration le démontre.'),
        'empty': not entries,
    }


def inventory(jobs_payload):
    """Assemble la vue Bacula. Une seule source pour l'instant."""
    return jobs(jobs_payload)
