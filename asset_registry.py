"""Durable enrollment, independent of a server's current reachability."""
from datetime import datetime, timezone
from ipaddress import ip_address
import hashlib


def enroll(db, assets):
    db.execute('CREATE TABLE IF NOT EXISTS registered_assets(key TEXT PRIMARY KEY, ip TEXT, first_seen TEXT)')
    known = {key: (ip, stamp) for key, ip, stamp in db.execute('SELECT key,ip,first_seen FROM registered_assets')}
    now = datetime.now(timezone.utc).isoformat()
    for host in assets:
        # Import existing production machines already successfully reached by SSH.
        admitted = host.get('active_scope') or (host.get('ssh_user') and
                    str(host.get('environment', '')).lower() in ('prod', 'production'))
        if admitted and (host['key'] not in known or known[host['key']][0] != host['ip']):
            db.execute('INSERT OR REPLACE INTO registered_assets VALUES(?,?,?)', (host['key'], host['ip'], now))
            known[host['key']] = (host['ip'], now)
        record = known.get(host['key'])
        host['registered'] = bool(record and record[0] == host['ip'])
        host['registered_at'] = record[1] if host['registered'] else None
    return assets


def names(item, fields=('key', 'name', 'fqdn')):
    return {str(item.get(k) or '').lower().rstrip('.') for k in fields} - {''}


def initial_audit_hosts(hosts):
    return [h for h in hosts if not h.get('audit_recorded') and h.get('collect_enabled', True)]


def connection_evidence(source):
    last = source.get('last_result') or {}
    prior = source.get('last_success_result')
    if last.get('status') != 'observed' and prior:
        return {**prior, 'status': 'unknown', 'error': last.get('error'),
                'last_attempt_at': last.get('collected_at')}
    return last


def discover(hosts, connections):
    """Require independent, fresh Proxmox and Zabbix evidence; never guess an IP."""
    from synchronization import fresh
    zabbix = []
    guests = []
    for source in connections:
        result = source.get('last_result') or {}
        if result.get('status') != 'observed' or not fresh(result.get('collected_at')):
            continue
        inv = result.get('inventory') or {}
        if source['provider'] == 'Zabbix':
            zabbix.extend(inv.get('hosts', []))
        if source['provider'] == 'Proxmox':
            for node in inv.get('nodes', []):
                guests.extend((g, node['name'], source['key']) for g in node.get('guests', []) if g.get('status') == 'running')
    additions, pending = [], []
    for guest, node, source in guests:
        name = str(guest.get('name') or '').lower().rstrip('.')
        if not name or any(name in names(h) for h in hosts):
            continue
        reason = None
        candidates = [z for z in zabbix if name in names(z, ('name', 'host')) and z.get('status') == 'monitored']
        addresses = candidates[0].get('addresses', []) if len(candidates) == 1 else []
        valid = set()
        for address in addresses:
            try:
                ip = ip_address(address)
                if not (ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local):
                    valid.add(str(ip))
            except ValueError:
                pass
        if len(str(guest['name'])) > 120:
            reason = 'Nom trop long pour l’inventaire'
        elif sum(1 for g, _, _ in guests if str(g.get('name') or '').lower().rstrip('.') == name) != 1:
            reason = 'Nom Proxmox ambigu'
        elif len(candidates) != 1 or len(valid) != 1:
            reason = 'Adresse unique non confirmée par Zabbix'
        elif any(h['ip'] == next(iter(valid)) for h in hosts + additions):
            reason = 'Adresse déjà associée à un autre serveur'
        if reason:
            pending.append({'name': name, 'vmid': guest.get('vmid'), 'reason': reason})
            continue
        key = 'discovered-' + hashlib.sha256(f'{source}:{guest["vmid"]}'.encode()).hexdigest()[:16]
        if any(h['key'] == key for h in hosts + additions):
            continue
        additions.append({'key': key, 'name': guest['name'], 'ip': next(iter(valid)),
                          'role': 'À renseigner', 'environment': 'À renseigner', 'services': [],
                          'criticality': 'standard', 'collect_enabled': True, 'vmid': guest['vmid'],
                          'node': node, 'discovered_from': source})
    return additions, pending


def source_details(host, hosts, connections):
    """Keep per-host evidence separate from infrastructure-wide aggregates."""
    from synchronization import fresh
    result = []
    name_owners = {}
    for asset in hosts:
        for name in names(asset):
            name_owners.setdefault(name, set()).add(asset['key'])
    for source in connections:
        r = connection_evidence(source)
        inv = r.get('inventory') or {}
        provider = source['provider']
        evidence = {}
        if provider == 'Zabbix':
            matches = [z for z in inv.get('hosts', []) if host['ip'] in z.get('addresses', []) or names(host) & names(z, ('host', 'name'))]
            if len(matches) == 1:
                z = matches[0]
                owners = [h for h in hosts if h['ip'] in z.get('addresses', []) or names(h) & names(z, ('host', 'name'))]
                if len(owners) == 1:
                    evidence = {'host': z, 'problems': [p for p in (inv.get('problems') or []) if names(z, ('host', 'name')) & {str(n).lower().rstrip('.') for n in p.get('hosts', [])}],
                                'problems_measured': isinstance(inv.get('problems'), list),
                                'problems_scope': inv.get('problems_scope'), 'problems_error': inv.get('problems_error')}
        elif provider == 'Bacula':
            from bacula_inventory import latest_jobs
            matched = []
            for job in latest_jobs(inv):
                client = str(job.get('client') or '').lower().rstrip('.')
                aliases = {client, client[:-3] if client.endswith('-fd') else client} - {''}
                owners = set().union(*(name_owners.get(alias, set()) for alias in aliases))
                if owners == {host['key']}:
                    matched.append(job)
            if matched:
                evidence = {'jobs_count': len(matched), 'latest_jobs': matched,
                            'recent_jobs': sorted(matched, key=lambda j: j.get('jobid') or 0, reverse=True)[:10]}
        elif provider == 'Wazuh':
            matched = [a for a in inv.get('agents_inventory', []) if a.get('ip') == host['ip'] or names(host) & names(a, ('name',))]
            if len(matched) == 1:
                a = matched[0]
                owners = [h for h in hosts if a.get('ip') == h['ip'] or names(h) & names(a, ('name',))]
                if len(owners) == 1:
                    evidence = {'agent': a}
        if evidence or source.get('host_key') == host['key']:
            result.append({'provider': provider, 'key': source['key'], 'collected_at': r.get('collected_at'),
                           'fresh': r.get('status') == 'observed' and fresh(r.get('collected_at')),
                           'error': r.get('error'), 'evidence': evidence,
                           'scope': 'serveur' if evidence else 'Source hébergée ; indicateurs globaux, pas une preuve de couverture de ce serveur'})
    return result


def backup_summaries(hosts, connections):
    """Compact server evidence, indexed once; a missing match is not a failed backup."""
    from bacula_inventory import latest_jobs
    from synchronization import fresh
    owners, matched = {}, {h['key']: [] for h in hosts}
    for host in hosts:
        for name in names(host):
            owners.setdefault(name, set()).add(host['key'])
    for source in connections:
        if source.get('provider') != 'Bacula':
            continue
        result = connection_evidence(source)
        recent = result.get('status') == 'observed' and fresh(result.get('collected_at'))
        for job in latest_jobs(result.get('inventory') or {}):
            client = str(job.get('client') or '').lower().rstrip('.')
            aliases = {client, client[:-3] if client.endswith('-fd') else client} - {''}
            candidates = set().union(*(owners.get(n, set()) for n in aliases))
            if len(candidates) == 1:
                matched[next(iter(candidates))].append((source['key'], result.get('collected_at'), recent, job))
    rank = {'critical': 0, 'warning': 1, 'unknown': 2, 'running': 3, 'pending': 4, 'ok': 5}
    summaries = {}
    for key, entries in matched.items():
        stamps = [e[1] for e in entries if e[1]]
        successes = [e[3].get('endtime') for e in entries if e[3].get('severity') == 'ok' and e[3].get('endtime')]
        summaries[key] = {'matched': bool(entries), 'jobs_count': len(entries),
                          'severity': min((e[3].get('severity', 'unknown') for e in entries), key=lambda s: rank.get(s, 2), default='unknown'),
                          'fresh': bool(entries) and all(e[2] for e in entries),
                          'collected_at': min(stamps) if stamps else None,
                          'last_success': max(successes) if successes else None,
                          'sources_count': len({e[0] for e in entries}),
                          'scope': 'Dernier passage connu par job et client associé sans ambiguïté. Ne prouve pas la restaurabilité ni le respect du planning.'}
    return summaries
