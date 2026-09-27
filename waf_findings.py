"""Date-based TLS alerts, evidence-based WAF analysis, and command previews."""
import math
import shlex
from datetime import datetime, timezone
from ipaddress import ip_address


def command_plan(address, action, execution_host):
    if '%' in address:
        raise ValueError('Adresse IPv4 ou IPv6 sans zone requise')
    ip = str(ip_address(address))
    execution_host = str(ip_address(execution_host))
    base = 'sudo fail2ban-client '
    jail = 'apache-modsecurity'
    target = shlex.quote(ip)
    plans = {
        'ban': ([f'{base}set {jail} banip {target}'], f'{base}set {jail} unbanip {target}',
                'Bannissement manuel dans ce jail. Vérifier que cette adresse ne correspond pas à votre accès, au bastion ou à un proxy partagé.'),
        'whitelist': ([f'{base}set {jail} addignoreip {target}', f'{base}set {jail} unbanip {target}'],
                      f'{base}set {jail} delignoreip {target}',
                      'Ajoute une exception Fail2ban active puis retire un éventuel ban existant. Ne désactive pas ModSecurity. Non persistante après rechargement/redémarrage : reporter l’IP dans la configuration du jail en conservant les exceptions existantes.'),
        'unban': ([f'{base}set {jail} unbanip {target}'], '', 'Retire le ban actuel ; l’IP peut être bannie à nouveau.'),
        'remove_whitelist': ([f'{base}set {jail} delignoreip {target}'], f'{base}set {jail} addignoreip {target}',
                             'Retire l’exception active de ce jail ; ne bannit pas immédiatement l’adresse.'),
    }
    if action not in plans:
        raise ValueError('Action inconnue')
    commands, undo, note = plans[action]
    return {'ip': ip, 'action': action, 'commands': commands, 'undo': undo, 'note': note,
            'verify': [f'{base}status {jail}', f'{base}get {jail} ignoreip'],
            'execution_host': execution_host, 'executable': False}


def expiry(cert, now=None):
    now = now or datetime.now(timezone.utc)
    result = {**cert, 'severity': 'unknown', 'days_remaining': None, 'expiration_state': 'Non vérifié'}
    try:
        end = datetime.fromisoformat(cert['not_after'])
        start = datetime.fromisoformat(cert['not_before'])
        if end.tzinfo is None or start.tzinfo is None or end <= start:
            raise ValueError('Invalid validity interval')
        seconds = (end - now).total_seconds()
        result['days_remaining'] = math.floor(seconds / 86400)
        if seconds <= 0:
            result.update(severity='critical', expiration_state='Expiré')
        elif now < start:
            result.update(severity='critical', expiration_state='Pas encore valide')
        elif seconds <= 7 * 86400:
            result.update(severity='critical', expiration_state='Expire sous 7 jours')
        elif seconds <= 30 * 86400:
            result.update(severity='warning', expiration_state='Expire sous 30 jours')
        else:
            result.update(severity='observed', expiration_state='Échéance au-delà de 30 jours')
    except (KeyError, ValueError, TypeError):
        pass
    return result


def analyze(waf, host_ip, now=None):
    s = waf.get('sections', {})
    findings = []

    def add(key, title, severity, evidence, check, advice):
        findings.append({'id': 'waf:' + key, 'title': title, 'severity': severity, 'domain': 'WAF / TLS',
                         'evidence': evidence, 'check_command': check, 'solution_command': '# ' + advice,
                         'precaution': 'Vérifier la preuve et sa date avant intervention.', 'scope': 'Sur ' + host_ip,
                         'requires_adaptation': True, 'executable': False})

    for item in s.get('services', {}).get('data', []):
        if item.get('name') in ('apache2', 'fail2ban') and item.get('ActiveState') != 'active':
            state = item.get('ActiveState', 'unknown')
            add('service:' + item['name'], 'Service critique ' + item['name'] + ' non confirmé actif',
                'unknown' if state == 'unknown' else 'critical', 'État : ' + state,
                'systemctl status ' + item['name'], 'Examiner le journal du service et la configuration avant redémarrage.')
    if s.get('apache_modules', {}).get('data', {}).get('security_module_loaded') is False:
        add('module', 'ModSecurity absent de la liste des modules Apache', 'critical', 'apache2ctl -M ne liste pas security2/3_module.',
            'sudo apache2ctl -M', 'Vérifier le chargement du module dans la configuration utilisée.')
    for entry in s.get('engine', {}).get('data', {}).get('declarations', []):
        if entry.get('mode', '').lower() in ('off', 'detectiononly'):
            add('engine:' + str(len(findings)), 'Déclaration ModSecurity ' + entry['mode'], 'warning',
                f"{entry.get('file')}:{entry.get('line')} — portée effective à confirmer",
                'sudo apache2ctl -t', 'Vérifier les inclusions et la portée du vhost ; ne pas changer le mode sans examiner les faux positifs.')
    traffic = s.get('traffic', {}).get('data', {})
    if (traffic.get('errors_5xx_pct') or 0) >= 5:
        add('http5xx', 'Réponses HTTP 5xx élevées dans l’échantillon', 'warning',
            str(traffic['errors_5xx_pct']) + '% sur ' + str(traffic.get('requests')) + ' requêtes échantillonnées.',
            'sudo journalctl -u apache2 --since "1 hour ago" --no-pager -n 80',
            'Corréler les erreurs Apache avec les applications amont ; les 5xx ne prouvent pas une attaque.')
    used, capacity = (s.get(k, {}).get('data') for k in ('conntrack', 'conntrack_max'))
    if isinstance(used, int) and isinstance(capacity, int) and capacity > 0 and used / capacity >= .8:
        add('conntrack', 'Table conntrack proche de sa capacité', 'critical' if used / capacity >= .95 else 'warning',
            f'{used} / {capacity} entrées', 'ss -s', 'Analyser les connexions et le trafic avant toute modification de limite.')

    tls = s.get('certificates', {}).get('data', {})
    certificates = [expiry(cert, now) for cert in tls.get('certificates', [])]
    for i, cert in enumerate(certificates):
        if cert['severity'] in ('critical', 'warning', 'unknown'):
            path = cert.get('path', '')
            add('tls:' + str(i), 'Certificat : ' + cert['expiration_state'], cert['severity'],
                f"{path} — expiration : {cert.get('not_after', 'inconnue')} — jours restants : {cert['days_remaining']}",
                'sudo openssl x509 -in ' + shlex.quote(path) + ' -noout -dates -subject -issuer',
                'Vérifier le certificat concerné, son mécanisme de renouvellement et le certificat réellement présenté par le vhost.')
    if not certificates:
        add('tls:coverage', 'Aucun certificat SSL/TLS mesuré', 'unknown', 'Aucune date d’expiration disponible.',
            'sudo apache2ctl -S', 'Vérifier les déclarations SSLCertificateFile et les droits de lecture.')
    if tls.get('partial'):
        add('tls:partial', 'Couverture SSL/TLS partielle', 'unknown', 'Certains fichiers, inclusions ou certificats restent non résolus.',
            'sudo apache2ctl -S', 'Examiner la liste des sources inaccessibles et les limites de découverte.')
    for key, section in s.items():
        if section.get('status') == 'unknown':
            add('coverage:' + key, 'Contrôle WAF incomplet : ' + key, 'unknown', section.get('error', 'Preuve absente'),
                '', 'Vérifier les droits et la disponibilité de la source.')
    findings.sort(key=lambda f: {'critical': 0, 'warning': 1, 'unknown': 2}.get(f['severity'], 3))
    return certificates, findings


def decorate(row):
    if not row.get('waf'):
        return
    certs, findings = analyze(row['waf'], row['ip'])
    row['waf'].update(certificates=certs, analysis=findings)
    row['findings'] = [f for f in row.get('findings', []) if not f['id'].startswith('waf:')] + findings
    if not row.get('stale'):
        if any(f['severity'] == 'critical' for f in findings):
            row['status'] = 'critical'
        elif row['status'] not in ('critical', 'unreachable') and any(f['severity'] == 'warning' for f in findings):
            row['status'] = 'warning'
