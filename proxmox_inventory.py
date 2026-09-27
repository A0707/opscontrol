"""Normalize Proxmox /cluster/resources into nodes and their guests."""
import math


def cluster_info(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
        return None
    item = next((x for x in payload['data'] if isinstance(x, dict) and x.get('type') == 'cluster'), None)
    if item is None:
        return None
    return {'name': str(item.get('name') or '')[:200],
            'quorate': bool(item['quorate']) if item.get('quorate') in (0, 1) else None}


def inventory(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get('data'), list):
        raise ValueError('Proxmox resources response invalid')
    nodes = {}
    counts = {'qemu': 0, 'lxc': 0, 'running': 0, 'stopped': 0, 'unknown': 0}
    ignored = 0

    def text(value):
        return str(value)[:200] if value is not None else None

    def number(value):
        return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None

    def node(name):
        return nodes.setdefault(name, {'name': name, 'status': 'unknown', 'reported': False,
                                       'cpu_pct': None, 'memory_bytes': None, 'memory_total_bytes': None,
                                       'uptime_seconds': None, 'guests': []})

    for resource in payload['data']:
        if not isinstance(resource, dict):
            ignored += 1
            continue
        kind = resource.get('type')
        if kind not in ('node', 'qemu', 'lxc'):
            continue
        name = text(resource.get('node')) or 'Nœud non renseigné'
        group = node(name)
        cpu = number(resource.get('cpu'))
        metrics = {'cpu_pct': round(cpu * 100, 2) if cpu is not None and cpu <= 1 else None,
                   'memory_bytes': number(resource.get('mem')), 'memory_total_bytes': number(resource.get('maxmem')),
                   'uptime_seconds': number(resource.get('uptime'))}
        if kind == 'node':
            group.update(metrics, reported=True, status=resource.get('status') if resource.get('status') in ('online', 'offline') else 'unknown')
        else:
            vmid = resource.get('vmid')
            if not isinstance(vmid, int) or isinstance(vmid, bool) or vmid < 1:
                ignored += 1
                continue
            status = resource.get('status') if resource.get('status') in ('running', 'stopped') else 'unknown'
            group['guests'].append({'vmid': vmid, 'name': text(resource.get('name')) or str(vmid), 'type': kind,
                                    'status': status, 'node': name, 'disk_capacity_bytes': number(resource.get('maxdisk')),
                                    'pool': text(resource.get('pool')), **metrics})
            counts[kind] += 1
            counts[status] += 1
    for group in nodes.values():
        group['guests'].sort(key=lambda guest: (guest['vmid'], guest['type']))
    return {'nodes': sorted(nodes.values(), key=lambda group: group['name']), 'counts': counts,
            'nodes_count': len(nodes), 'ignored_resources': ignored,
            'scope': 'Ressources visibles par ce compte et ce jeton ; les permissions peuvent limiter le résultat.',
            'empty': not nodes}
