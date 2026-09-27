"""Per-host SSH collection: pick a working (user, port) candidate, then read
metrics/df/services/os/uptime with that same identity."""
from datetime import datetime, timezone
from ssh import run_operation, parse_df, pretty_os
from config import candidates

def collect_metrics(host, cfg, requester):
    """Try each (user, port) candidate for `host` until one answers 'metrics'.

    The `for candidate in candidates(...): ... break` / `else:` below is not a
    typo: the `else` runs only if the loop completes without `break`, i.e. no
    candidate ever produced a usable connection. That is the "give up on this
    host" path; the `break` case falls through to the per-operation loop.
    """
    result = {'status': 'unknown', 'issues': [], 'cpu': None, 'ram': None, 'disk_max': None, 'filesystems': [], 'service_states': [], 'collected_at': datetime.now(timezone.utc).isoformat()}
    result['attempts'] = []
    if not host.get('ip') or host.get('collect_enabled') is False:
        result['issues'] = ['Collecte désactivée : adresse manquante ou inventaire ambigu']
        return result
    results = {}
    # Try a bounded list, then keep the successful identity for this collection.
    failures = []
    skip_ports = set()
    for candidate in candidates(cfg, host):
        if candidate.port in skip_ports: continue
        probe = run_operation(host['ip'], 'metrics', candidate, requester)
        result['attempts'].append({'user': candidate.user, 'port': candidate.port, 'ok': probe.rc is not None, 'error_kind': probe.error_kind, 'error': probe.stderr, 'duration_ms': probe.duration_ms})
        if probe.rc is not None:
            cfg = candidate
            results['metrics'] = probe
            result['ssh_user'], result['ssh_port'] = cfg.user, cfg.port
            break
        failures.append(probe)
        if probe.error_kind != 'auth': skip_ports.add(candidate.port)
    else:
        network = bool(failures) and all(r.error_kind == 'network' for r in failures)
        result['status'] = 'unreachable' if network else 'critical'
        result['issues'] = [('SSH/TCP inaccessible' if network else 'Accès SSH refusé ou erreur de collecte') + ': ' + '; '.join(dict.fromkeys(r.stderr for r in failures))]
        return result
    for op in ['metrics', 'df', 'services', 'os', 'uptime']:
        r = results.get(op) or run_operation(host['ip'], op, cfg, requester)
        results[op] = r
        if op == 'metrics' and not r.ok and r.rc is None:
            result['status'] = 'unreachable' if r.error_kind == 'network' else 'critical'
            result['issues'] = [('SSH/TCP inaccessible' if r.error_kind == 'network' else 'Accès SSH refusé ou erreur de collecte') + ': ' + r.stderr]
            return result
        if not r.ok: result['issues'].append('Collecte partielle : ' + op)
    try:
        lines = results['metrics'].stdout.splitlines()
        samples = [[int(n) for n in line.split()[1:9]] for line in lines if line.startswith('cpu ')]
        first, second = samples
        total = sum(second) - sum(first)
        idle = second[3] + second[4] - first[3] - first[4]
        mem = {line.split(':')[0]: int(line.split()[1]) for line in lines if ':' in line}
        values = {'cpu': 100 * (total-idle)/total, 'ram': 100 * (1 - mem['MemAvailable']/mem['MemTotal'])}
        for key in ['cpu', 'ram']:
            v = float(values[key])
            if not 0 <= v <= 100: raise ValueError('hors plage')
            result[key] = round(v, 1)
    except (ValueError, KeyError, ZeroDivisionError): result['issues'].append('Métriques CPU/RAM indisponibles')
    if results['df'].ok:
        result['filesystems'] = parse_df(results['df'].stdout)
        values = [f['use_pct'] for f in result['filesystems'] if f['use_pct'] is not None]
        result['disk_max'] = max(values) if values else None
    if result['disk_max'] is None: result['issues'].append('Mesure disque indisponible')
    units = {}
    if results['services'].ok:
        for line in results['services'].stdout.splitlines():
            p = line.split()
            if len(p) >= 4: units[p[0]] = p[2]
    for name in host.get('services', []):
        unit = name if name.endswith('.service') else name + '.service'
        state = units.get(unit, 'unknown')
        result['service_states'].append({'name': name, 'status': state})
        if state != 'active': result['issues'].append('Service ' + name + ' : ' + state)
    result['all_services'] = [{'name':name,'status':state,'configured':name in [s if s.endswith('.service') else s+'.service' for s in host.get('services',[])]} for name,state in units.items()]
    result['all_services'] += [dict(s,configured=True) for s in result['service_states'] if (s['name'] if s['name'].endswith('.service') else s['name']+'.service') not in units]
    result['os'] = pretty_os(results['os'].stdout) if results['os'].ok else None
    result['uptime'] = results['uptime'].stdout.strip() if results['uptime'].ok else None
    critical = any(s['status'] in ['failed', 'inactive'] for s in result['service_states'])
    warning = False
    for key, warn, crit in [('cpu',90,98), ('ram',90,97), ('disk_max',80,90)]:
        v = result[key]
        if v is not None and v >= warn:
            result['issues'].append(f'{key} : {v}%')
            critical |= v >= crit
            warning = True
    result['status'] = 'critical' if critical else 'warning' if warning else 'unknown' if result['issues'] else 'ok'
    return result

def collect(host, cfg, requester):
    """Full audit for one host: system metrics/checks, plus the WAF probe
    when the host's declared role identifies it as a ModSecurity WAF."""
    from audit_engine import enrich
    result = enrich(host, cfg, collect_metrics(host, cfg, requester), requester=requester)
    from waf_audit import collect_waf, is_waf_host
    if is_waf_host(host):
        result['waf'] = collect_waf(host, cfg, result, requester)
    return result
