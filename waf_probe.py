"""Fixed read-only remote probe. Sent by waf_audit via the SSH allowlist.

No external WHOIS lookup, no mutations, no arbitrary commands from the browser.
Only sanitized aggregates and selected event attributes leave the server.
"""
import collections
import datetime
import glob
import ipaddress
import json
import posixpath
import re
import shlex
import ssl
import subprocess
import time


def main():
    started = time.monotonic()
    deadline = started + 70
    sections = {}

    def run(args):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('Budget de collecte épuisé')
        p = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=min(5, remaining), text=True, errors='replace')
        if p.returncode:
            raise RuntimeError('Commande refusée ou indisponible (code %s)' % p.returncode)
        if len(p.stdout) > 800000:
            raise RuntimeError('Sortie trop volumineuse')
        return p.stdout

    def section(name, fn):
        try:
            sections[name] = {'status': 'observed', 'data': fn()}
        except Exception as e:
            sections[name] = {'status': 'unknown', 'error': str(e)[:180]}

    def integer(text):
        value = text.strip()
        if not re.fullmatch(r'-?\d+', value):
            raise ValueError('Valeur numérique absente')
        return int(value)

    def valid_ip(value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return None

    def services():
        result = []
        for unit in ('apache2', 'httpd', 'nginx', 'fail2ban', 'keepalived'):
            try:
                text = run(['systemctl', 'show', unit, '--no-pager',
                            '-p', 'LoadState', '-p', 'ActiveState', '-p', 'SubState'])
                values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                result.append({'name': unit, **values})
            except Exception:
                result.append({'name': unit, 'ActiveState': 'unknown'})
        if all(x.get('ActiveState') == 'unknown' for x in result):
            raise RuntimeError('État des services inaccessible')
        return result

    section('services', services)

    def modules():
        text = run(['sudo', '-n', 'apache2ctl', '-M'])
        return {'security_module_loaded': bool(re.search(r'\bsecurity[23]?_module\b', text)),
                'modules': re.findall(r'^\s*(\w+_module)\b', text, re.M)[:100]}

    section('apache_modules', modules)

    def vhosts():
        text = run(['sudo', '-n', 'apache2ctl', '-S'])
        return {'declarations': text.splitlines()[:80], 'scope': 'Déclarations Apache, disponibilité HTTP non testée'}

    section('vhosts', vhosts)

    def engine():
        paths = sorted({p for pattern in ('/etc/modsecurity/*.conf', '/etc/apache2/mods-enabled/*security*.conf', '/etc/apache2/sites-enabled/*') for p in glob.glob(pattern)})[:40]
        if not paths:
            raise RuntimeError('Aucune source de configuration découverte')
        declarations, unreadable = [], []
        for path in paths:
            try:
                text = run(['sudo', '-n', 'head', '-c', '65536', '--', path])
                for number, line in enumerate(text.splitlines(), 1):
                    match = re.match(r'^\s*SecRuleEngine\s+(On|Off|DetectionOnly)\s*(?:#.*)?$', line, re.I)
                    if match:
                        declarations.append({'file': path, 'line': number, 'mode': match[1]})
            except Exception:
                unreadable.append(path)
        return {'declarations': declarations, 'unreadable': unreadable,
                'scope': 'Déclarations dans les premiers 64 Ko de 40 fichiers maximum ; héritage et règles par vhost non résolus'}

    section('engine', engine)

    def certificates():
        paths = sorted({p for pattern in ('/etc/apache2/apache2.conf', '/etc/apache2/sites-enabled/*',
                                         '/etc/apache2/conf-enabled/*.conf', '/etc/apache2/mods-enabled/ssl.conf')
                        for p in glob.glob(pattern)})
        if not paths:
            raise RuntimeError('Aucune configuration Apache découverte')
        references, errors, unresolved = {}, [], []
        for path in paths[:192]:
            try:
                text = run(['sudo', '-n', 'head', '-c', '131072', '--', path])
                if len(text.encode('utf-8')) >= 131072:
                    unresolved.append({'source': path, 'reason': 'Configuration tronquée à 128 Ko'})
                for line in text.splitlines():
                    try:
                        tokens = shlex.split(line, comments=True)
                    except ValueError:
                        continue
                    if not tokens:
                        continue
                    if tokens[0].lower() == 'sslcertificatefile' and len(tokens) == 2:
                        value = tokens[1]
                        if any(x in value for x in ('$', '*', '?', '\n', '\r')) or ':' in value:
                            unresolved.append({'source': path, 'reason': 'Chemin de certificat dynamique non résolu'})
                            continue
                        value = posixpath.normpath(value if value.startswith('/') else '/etc/apache2/' + value)
                        references.setdefault(value, []).append(path)
                    elif tokens[0].lower() in ('include', 'includeoptional'):
                        unresolved.append({'source': path, 'reason': 'Inclusion non parcourue récursivement'})
            except Exception:
                errors.append(path)
        result = []
        for path, sources in list(references.items())[:96]:
            cert = {'path': path, 'sources': sources, 'status': 'unknown'}
            try:
                text = run(['sudo', '-n', 'openssl', 'x509', '-in', path, '-noout', '-startdate', '-enddate',
                            '-subject', '-issuer', '-serial', '-fingerprint', '-sha256'])
                values = dict(line.split('=', 1) for line in text.splitlines() if '=' in line)
                cert.update(not_before=datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(values['notBefore']), datetime.timezone.utc).isoformat(),
                            not_after=datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(values['notAfter']), datetime.timezone.utc).isoformat(),
                            subject=values.get('subject'), issuer=values.get('issuer'), serial=values.get('serial'),
                            fingerprint=next((v for k, v in values.items() if 'fingerprint' in k.lower()), None), status='observed')
            except Exception:
                cert['error'] = 'Certificat inaccessible, invalide ou OpenSSL indisponible'
            result.append(cert)
        return {'certificates': result, 'configs_discovered': len(paths), 'configs_limit': 192, 'certificate_limit': 96,
                'unreadable': errors, 'unresolved': unresolved,
                'partial': bool(errors or unresolved) or len(paths) > 192 or len(references) > 96,
                'scope': 'Certificats fichiers déclarés dans Apache ; pas de test TLS distant, de chaîne de confiance ou de clé privée. Inclusions et conditions Apache non résolues.'}

    section('certificates', certificates)

    def jail():
        text = run(['sudo', '-n', 'fail2ban-client', 'status', 'apache-modsecurity'])
        result = {}
        for field, title in [('currently_banned', 'Currently banned'), ('total_banned', 'Total banned'),
                             ('currently_failed', 'Currently failed'), ('total_failed', 'Total failed')]:
            match = re.search(re.escape(title) + r':\s*(\d+)', text)
            result[field] = int(match[1]) if match else None
        match = re.search(r'Banned IP list:\s*([^\n]*)', text)
        result['banned_ips'] = [ip for value in match[1].split() if (ip := valid_ip(value))][:500] if match else []
        result['list_available'] = match is not None
        result['list_limit'] = 500
        return result

    section('fail2ban', jail)
    def ignored():
        text = run(['sudo', '-n', 'fail2ban-client', 'get', 'apache-modsecurity', 'ignoreip'])
        import ipaddress
        addresses = []
        for token in re.findall(r'[0-9A-Fa-f:.]+(?:/\d+)?', text):
            if '.' not in token and ':' not in token:
                continue
            try:
                value = str(ipaddress.ip_network(token, strict=False)) if '/' in token else str(ipaddress.ip_address(token))
                if value not in addresses:
                    addresses.append(value)
            except ValueError:
                pass
        return {'addresses': addresses[:500], 'limit': 500,
                'scope': 'Exceptions IP/réseaux rapportées par Fail2ban ; les éventuels noms DNS ne sont pas analysés.'}
    section('ignoreip', ignored)
    for policy in ('maxretry', 'findtime', 'bantime'):
        section(policy, lambda policy=policy: integer(run(['sudo', '-n', 'fail2ban-client', 'get', 'apache-modsecurity', policy])))
    section('tcp', lambda: {'summary': run(['ss', '-s'])[:2000]})
    section('conntrack', lambda: integer(run(['cat', '/proc/sys/net/netfilter/nf_conntrack_count'])))
    section('conntrack_max', lambda: integer(run(['cat', '/proc/sys/net/netfilter/nf_conntrack_max'])))

    def drops():
        text = run(['sudo', '-n', 'iptables', '-L', 'INPUT', '-nvx'])
        rules = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) > 2 and parts[0].isdigit() and parts[2] in ('DROP', 'REJECT'):
                rules.append({'target': parts[2], 'packets': int(parts[0])})
        return {'packets': sum(x['packets'] for x in rules), 'rules': len(rules),
                'scope': 'Compteurs des règles DROP/REJECT de INPUT uniquement ; ni débit ni total de tous les drops'}

    section('iptables', drops)

    def samples(patterns, limit):
        files = sorted({p for pattern in patterns for p in glob.glob(pattern)})
        if not files:
            raise RuntimeError('Aucun fichier découvert pour les chemins Apache configurés')
        records, sources, errors = [], [], []
        for path in files[:96]:
            try:
                # GNU tail -c bounds the bytes before selecting the last lines locally.
                text = run(['sudo', '-n', 'tail', '-c', '131072', '--', path])
                lines = text.splitlines()
                if len(text.encode('utf-8')) >= 131072:
                    lines = lines[1:]
                lines = lines[-limit:]
                records.extend((path, line[:16000]) for line in lines)
                sources.append({'path': path, 'lines': len(lines)})
            except Exception:
                errors.append(path)
        if not sources:
            raise RuntimeError('Logs découverts mais non accessibles')
        return records, {'sources': sources, 'unreadable': errors, 'files_discovered': len(files),
                         'file_limit': 96, 'lines_per_file': limit, 'bytes_per_file': 131072,
                         'partial': bool(errors) or len(files) > 96}

    def traffic():
        rows, scope = samples(['/var/log/apache2/access.log', '/var/log/apache2/*-access_log'], 200)
        codes, urls, ips, per_file = (collections.Counter() for _ in range(4))
        times, rejected = [], 0
        for path, line in rows:
            match = re.match(r'^(\S+) .*?\[([^\]]+)\] "([A-Z]+) ([^" ]+)(?: HTTP/[^" ]+)?" ([1-5]\d\d)\b', line)
            if not match:
                rejected += 1
                continue
            address, timestamp, method, url, code = match.groups()
            codes[code] += 1
            # Paths only: no query strings, credentials, referers, cookies or bodies.
            urls[url.split('?', 1)[0].split('#', 1)[0][:160]] += 1
            ip = valid_ip(address)
            if ip:
                ips[ip] += 1
            per_file[path] += 1
            try:
                times.append(datetime.datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S %z'))
            except ValueError:
                pass
        count = sum(codes.values())
        if rows and not count:
            raise RuntimeError('Format HTTP non reconnu : adapter le parseur au LogFormat Apache')
        return {'http_codes': dict(codes), 'requests': count, 'unparsed_lines': rejected,
                'top_urls': urls.most_common(15), 'top_ips': ips.most_common(15),
                'by_file': per_file.most_common(), 'first_event': min(times).isoformat() if times else None,
                'last_event': max(times).isoformat() if times else None, 'scope': scope,
                'errors_5xx_pct': round(100 * sum(n for code, n in codes.items() if code.startswith('5')) / count, 2) if count else None}

    section('traffic', traffic)

    def modsecurity():
        rows, scope = samples(['/var/log/apache2/error.log', '/var/log/apache2/*-error_log'], 500)
        rules, clients = collections.Counter(), collections.Counter()
        events, scores = [], []
        alerts = 0
        for path, line in rows:
            if 'ModSecurity' not in line:
                continue
            alerts += 1
            ids = re.findall(r'\[id "(\d+)"\]', line)
            rules.update(ids)
            score = re.search(r'Total Score:\s*(\d+)', line)
            if score:
                scores.append(int(score[1]))
            match = re.search(r'\[client ([^\]]+)\]', line)
            ip = valid_ip(match[1]) if match else None
            if match and not ip and re.fullmatch(r'[0-9.]+:\d+', match[1]):
                ip = valid_ip(match[1].rsplit(':', 1)[0])
            if ip:
                clients[ip] += 1
            events.append({'source': path, 'rules': ids, 'client': ip,
                           'timestamp_raw': line.split(']', 1)[0].lstrip('[')[:60] if line.startswith('[') else None,
                           'action': 'deny_reported' if 'Access denied' in line else 'alert',
                           'score': int(score[1]) if score else None})
        return {'alert_lines': alerts, 'rules': rules.most_common(15), 'clients': clients.most_common(15),
                'anomaly_max': max(scores) if scores else None, 'events': events[-60:], 'scope': scope,
                'note': 'Comptage de lignes, pas de requêtes uniques. Un code HTTP 403 ne prouve pas un blocage ModSecurity.'}

    section('modsecurity', modsecurity)
    print(json.dumps({'version': 1, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'duration_ms': round((time.monotonic() - started) * 1000), 'sections': sections}))


if __name__ == '__main__':
    main()
