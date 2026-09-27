"""Local inventory editing and explicit, bounded HTTPS JSON collection."""
import hashlib
import json
import os
import re
import tempfile
import threading
import socket
import ssl
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

BACULA_TUNNEL_URL = 'http://127.0.0.1:19096/api/v2/jobs'


class Server(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    name: str = Field(min_length=1, max_length=120)
    ip: str
    role: str = Field(default='À renseigner', max_length=80)
    environment: str = Field(default='PROD', max_length=80)
    criticality: Literal['standard', 'critical'] = 'standard'
    services: list[str] = Field(default_factory=list, max_length=100)
    user: str = Field(default='', pattern=r'^(?:[A-Za-z_][A-Za-z0-9_.-]{0,63})?$')
    port: int = Field(default=22, ge=1, le=65535)
    collect_enabled: bool = True

    @field_validator('ip')
    @classmethod
    def valid_ip(cls, value):
        return str(ip_address(value))

    @field_validator('services')
    @classmethod
    def valid_services(cls, values):
        if any(not re.fullmatch(r'[A-Za-z0-9_@.:-]{1,150}', v) for v in values):
            raise ValueError('Nom de service invalide')
        return list(dict.fromkeys(values))


class Connection(BaseModel):
    model_config = ConfigDict(extra='forbid')
    key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')
    name: str = Field(min_length=1, max_length=120)
    url: str = Field(max_length=2048)
    token_env: str = Field(default='', pattern=r'^(?:[A-Z][A-Z0-9_]{0,100})?$')
    host_key: str = ''
    provider: Literal['Proxmox', 'Wazuh', 'Zabbix', 'Elasticsearch', 'Bacula', 'JSON'] = 'JSON'
    ca_bundle: str = Field(default='', max_length=8192)

    @field_validator('url')
    @classmethod
    def valid_url(cls, value):
        if value == BACULA_TUNNEL_URL:
            return value
        u = urlsplit(value)
        if u.scheme != 'https' or not u.hostname or u.username or u.password or u.fragment or u.query:
            raise ValueError('URL HTTPS sans identifiants, paramètres ni fragment requise')
        return value

    @model_validator(mode='after')
    def local_transport(self):
        if self.url == BACULA_TUNNEL_URL and self.provider != 'Bacula':
            raise ValueError('Le tunnel local est réservé à Bacula')
        return self

    @field_validator('ca_bundle')
    @classmethod
    def valid_ca_bundle(cls, value):
        if value.lstrip().startswith('-----BEGIN CERTIFICATE-----') and not value.rstrip().endswith('-----END CERTIFICATE-----'):
            raise ValueError('Certificat PEM incomplet')
        return value


class CertificateProbe(BaseModel):
    model_config = ConfigDict(extra='forbid')
    url: str = Field(max_length=2048)


class WafCommand(BaseModel):
    model_config = ConfigDict(extra='forbid')
    ip: str = Field(min_length=2, max_length=64)
    action: Literal['ban', 'whitelist', 'unban', 'remove_whitelist']
    host_key: str = Field(pattern=r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$')


def atomic_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.inventory-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


# --- Requêtes POST autorisées -------------------------------------------------
# La plateforme ne fait que des GET, sauf pour les API qui n'en proposent aucun.
# Zabbix est dans ce cas : son API est exclusivement du JSON-RPC en POST.
#
# Le principe de ssh.OPERATIONS est repris tel quel : le poste client ne choisit
# jamais la requête, seulement la source à interroger. Les corps ci-dessous sont
# figés dans le code, aucun champ n'est construit à partir d'une saisie, et
# seules des méthodes de LECTURE y figurent. Ajouter une méthode d'écriture ici
# reviendrait à casser la garantie « lecture seule » de la plateforme.
READ_ONLY_RPC = {
    'Zabbix': {
        'content_type': 'application/json-rpc',
        'calls': [
            ('hosts', {'jsonrpc': '2.0', 'id': 1, 'method': 'host.get', 'params': {
                'output': ['hostid', 'host', 'name', 'status'],
                'selectInterfaces': ['ip'],
                'limit': 2000,
            }}),
            ('problems', {'jsonrpc': '2.0', 'id': 2, 'method': 'trigger.get', 'params': {
                'output': ['triggerid', 'description', 'priority', 'lastchange'],
                'selectHosts': ['host', 'name'],
                'selectItems': ['itemid', 'lastclock'],
                'filter': {'value': 1, 'status': 0},
                'monitored': True,
                'skipDependent': True,
                'expandDescription': True,
                'limit': 500,
            }}),
        ],
    },
}


def rpc_request(url, body, headers, content_type, legacy_token=None):
    """Construit une requête JSON-RPC à partir d'un corps figé.

    `legacy_token` sert au repli pour Zabbix antérieur à 6.4, qui ignore
    l'en-tête Authorization et attend le jeton dans le champ `auth`.
    """
    payload = dict(body)
    if legacy_token:
        payload = {**payload, 'auth': legacy_token}
    data = json.dumps(payload).encode()
    return urllib.request.Request(url, data=data, method='POST',
                                  headers={**headers, 'Content-Type': content_type})


def ssl_context_for(item):
    """Certificat CA : soit un chemin de fichier .pem local, soit un certificat
    collé directement (récupéré et vérifié via 'Vérifier le certificat'). La
    vérification TLS standard reste active dans les deux cas ; vide = autorités
    du système."""
    ca = (item.get('ca_bundle') or '').strip()
    if not ca:
        return ssl.create_default_context()
    if ca.startswith('-----BEGIN CERTIFICATE-----'):
        # Un certificat collé sert d'ancre de confiance pour CE serveur : c'est
        # de l'épinglage, et toute la vérification standard reste active —
        # chaîne, nom d'hôte, période de validité, signature.
        #
        # On ne pré-refuse plus les certificats dont get_ca_certs() est vide.
        # Mesuré contre un service interne réel (Zabbix 6.4, certificat
        # auto-signé sans basicConstraints CA:TRUE) : get_ca_certs() renvoie
        # une liste vide, mais OpenSSL accepte parfaitement ce certificat comme
        # ancre et le handshake aboutit. L'ancien contrôle refusait donc une
        # configuration sûre. Un certificat inadapté échoue maintenant au
        # handshake, avec un diagnostic TLS explicite plutôt qu'une supposition.
        context = ssl.create_default_context(cadata=ca)
    else:
        context = ssl.create_default_context(cafile=str(Path(ca).expanduser()))
    # Older Proxmox cluster CAs omit keyUsage. Use standard chain validation
    # only for Proxmox with an explicitly supplied CA; retain CERT_REQUIRED,
    # hostname checking, validity checks and signature verification.
    if item.get('provider') == 'Proxmox':
        context.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return context


def probe_certificate(hostname, port, timeout=6):
    """Récupère le certificat présenté par hostname:port pour inspection humaine
    uniquement : aucune confiance n'est accordée ici, rien n'est enregistré."""
    # Deliberately unverified: this endpoint only displays the presented
    # certificate fingerprint for out-of-band comparison and never trusts it.
    ctx = ssl._create_unverified_context()  # nosec B323
    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise ValueError('Aucun certificat présenté')
    pem = ssl.DER_cert_to_PEM_cert(der)
    digest = hashlib.sha256(der).hexdigest()
    details = {}
    is_ca = False
    try:
        verified = ssl.create_default_context(cadata=pem)
        is_ca = bool(verified.get_ca_certs())
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with verified.wrap_socket(sock, server_hostname=hostname) as ssock:
                details = ssock.getpeercert() or {}
    except Exception:
        pass
    subject = dict(x[0] for x in details.get('subject', []))
    issuer = dict(x[0] for x in details.get('issuer', []))
    # Vérité de terrain plutôt que supposition : `details` n'est renseigné que
    # si la connexion VÉRIFIÉE avec ce certificat en ancre a abouti. C'est donc
    # la preuve directe qu'épingler ce certificat fera fonctionner la collecte,
    # qu'il porte ou non basicConstraints CA:TRUE.
    return {'hostname': hostname, 'port': port, 'pem': pem, 'is_ca': is_ca,
            'usable_anchor': bool(details),
            'self_signed': bool(subject) and subject == issuer,
            'sha256_fingerprint': ':'.join(digest[i:i + 2] for i in range(0, len(digest), 2)).upper(),
            'subject_cn': subject.get('commonName'), 'issuer_cn': issuer.get('commonName'),
            'not_before': details.get('notBefore'), 'not_after': details.get('notAfter')}


def wazuh_token(base_url, credentials, context, timeout):
    """Exchange 'username:password' for a fresh JWT via POST /security/user/authenticate.

    Wazuh JWTs are short-lived (a few minutes by default); calling this on every
    collection means the operator sets a password once and never has to fetch
    and paste a new token by hand again."""
    import base64
    user, sep, password = credentials.partition(':')
    if not sep:
        raise ValueError('Wazuh credentials must be user:password')
    parsed = urlsplit(base_url)
    auth_url = parsed._replace(path='/security/user/authenticate', query='').geturl()
    basic = base64.b64encode(f'{user}:{password}'.encode()).decode()
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=context))
    req = urllib.request.Request(auth_url, method='POST', headers={'Authorization': 'Basic ' + basic, 'Accept': 'application/json'})
    with opener.open(req, timeout=timeout) as response:
        raw = response.read(65536)
    token = json.loads(raw).get('data', {}).get('token')
    if not token:
        raise ValueError('Wazuh authentication response missing token')
    return token


def credential_shape(provider, token):
    """Diagnostic de forme sur un identifiant, sans jamais révéler sa valeur.

    Un 401 ne dit pas *pourquoi* il est refusé. La cause la plus fréquente en
    exploitation n'est pas un droit manquant mais une valeur mal recopiée :
    préfixe oublié, mauvais format d'export, copie tronquée. On ne renvoie donc
    que ce qui cloche dans la forme — jamais un extrait du secret.
    """
    if not token:
        return None
    if provider == 'Proxmox' and not token.startswith('PVEAPIToken='):
        return 'La variable doit contenir l’en-tête complet : PVEAPIToken=USER@REALM!ID=SECRET.'
    if provider == 'Wazuh' and ':' not in token:
        return 'La variable doit contenir « utilisateur:mot_de_passe », pas un jeton.'
    if provider == 'Bacula' and not token.startswith('Basic '):
        return ('Baculum utilise l’authentification Basic : la variable doit contenir '
                '« Basic » suivi d’un espace et de base64(utilisateur:mot_de_passe).')
    if provider == 'Elasticsearch':
        if not token.startswith(('ApiKey ', 'Basic ')):
            return ('La variable doit commencer par « ApiKey » suivi d’un espace et de la clé encodée, '
                    'par exemple ApiKey VnVhQ2ZH… — coller la clé seule ne suffit pas.')
        encoded = token.split(' ', 1)[1].strip()
        if token.startswith('ApiKey '):
            import base64
            import binascii
            try:
                decoded = base64.b64decode(encoded, validate=True).decode('utf-8', 'replace')
            except (binascii.Error, ValueError):
                return ('La valeur après « ApiKey » n’est pas du base64 valide. Dans Kibana, choisir le format '
                        '« Encoded » à la création de la clé, pas « Beats » ni « Logstash ».')
            if ':' not in decoded:
                return ('La clé décodée ne contient pas le couple identifiant:secret attendu. '
                        'Reprendre le format « Encoded » proposé par Kibana.')
    return None


def collection_error(exc):
    """Actionable diagnostics without echoing tokens, server bodies or request headers."""
    if isinstance(exc, urllib.error.HTTPError):
        messages = {
            401: 'Authentification refusée (HTTP 401). Vérifier le format Authorization, l’identifiant et la valeur du jeton (ou, pour Wazuh, le mot de passe).',
            403: 'Accès refusé (HTTP 403). Vérifier les permissions de lecture du compte et du jeton.',
            404: 'Endpoint absent (HTTP 404). Vérifier le chemin de l’URL API.',
        }
        return {'error_kind': 'http', 'http_status': exc.code,
                'error': messages.get(exc.code, 'Réponse HTTP ' + str(exc.code) + '. Vérifier le service API et l’URL ; les redirections ne sont pas suivies.')}
    reason = exc.reason if isinstance(exc, urllib.error.URLError) else exc
    if isinstance(reason, ssl.SSLCertVerificationError):
        code = reason.verify_code
        hint = ('Le nom ou l’IP de l’URL ne correspond pas au certificat. Utiliser un nom présent dans le certificat (champ Subject Alternative Name).' if code in (62, 64)
                else 'Le certificat ne porte pas l’extension Key Usage exigée en mode strict. Le régénérer avec keyCertSign, ou utiliser le certificat de son autorité.' if code == 92
                else 'Le certificat est expiré ou pas encore valide. Vérifier sa période de validité et l’horloge des deux machines.' if code in (9, 10)
                else 'Certificat auto-signé non épinglé. Cliquer « Vérifier le certificat du serveur », comparer l’empreinte SHA-256 à celle affichée par le produit, puis l’épingler.' if code in (18, 19)
                else 'L’autorité du certificat n’est pas reconnue. Épingler le certificat vérifié, renseigner le fichier PEM de son autorité dans « Certificat CA », ou installer cette autorité dans le magasin de confiance.')
        return {'error_kind': 'tls_certificate', 'tls_verify_code': code, 'error': 'Échec de vérification TLS. ' + hint}
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return {'error_kind': 'timeout', 'error': 'Délai de connexion dépassé. Vérifier la route, le VPN, le port et la disponibilité du service.'}
    if isinstance(reason, socket.gaierror):
        return {'error_kind': 'dns', 'error': 'Nom DNS introuvable depuis le poste OpsControl. Vérifier l’URL et le DNS.'}
    if isinstance(reason, ConnectionRefusedError):
        return {'error_kind': 'connection_refused', 'error': 'Connexion refusée. Vérifier que le port de l’URL est bien celui de l’API et que le service écoute.'}
    if isinstance(reason, (FileNotFoundError, PermissionError)):
        return {'error_kind': 'ca_file', 'error': 'Le fichier CA est absent ou inaccessible au processus OpsControl. Vérifier le chemin local du fichier PEM.'}
    if isinstance(reason, ssl.SSLError) and getattr(reason, 'reason', '') in ('WRONG_VERSION_NUMBER', 'UNKNOWN_PROTOCOL', 'HTTP_REQUEST', 'PACKET_LENGTH_TOO_LONG'):
        # Signature sans ambiguïté : le serveur a renvoyé du texte HTTP là où un
        # enregistrement TLS était attendu. Le certificat n'est pas en cause,
        # c'est le service qui n'écoute pas en HTTPS sur ce port.
        return {'error_kind': 'tls_absent',
                'error': 'Ce service répond en HTTP en clair sur ce port : TLS n’y est pas activé. '
                         'Activer HTTPS côté serveur (certificat + SSLEngine on sur le bon VirtualHost, '
                         'puis apache2ctl configtest avant de recharger). OpsControl refuse le HTTP en clair '
                         'car les identifiants y circuleraient lisibles sur le réseau.'}
    if isinstance(reason, ssl.SSLError):
        return {'error_kind': 'tls', 'error': 'Erreur TLS. Vérifier le certificat CA au format PEM et la configuration HTTPS du serveur.'}
    if isinstance(reason, (json.JSONDecodeError, UnicodeDecodeError)):
        return {'error_kind': 'json', 'error': 'La réponse reçue n’est pas un JSON valide. Vérifier que l’URL cible l’API et non l’interface web du produit.'}
    if isinstance(reason, ValueError) and str(reason) == 'Bacula response too large':
        return {'error_kind': 'response_limit', 'error': 'Historique Bacula supérieur à 16 Mio. Une collecte paginée est nécessaire.'}
    if isinstance(reason, ValueError) and str(reason) == 'Response too large':
        return {'error_kind': 'response_limit', 'error': 'Réponse supérieure à la limite de 1 Mo.'}
    if isinstance(reason, ValueError) and str(reason) == 'API error response':
        return {'error_kind': 'api', 'error': 'L’API a retourné une erreur applicative. Vérifier son état et les droits du jeton.'}
    if isinstance(reason, ValueError) and str(reason) == 'Proxmox resources response invalid':
        return {'error_kind': 'proxmox_format', 'error': 'Réponse Proxmox inattendue : utiliser /api2/json/cluster/resources pour collecter les nœuds et leurs VM.'}
    if isinstance(reason, ValueError) and str(reason) == 'Bacula response invalid':
        return {'error_kind': 'bacula_format', 'error': 'Réponse Baculum inattendue : vérifier que l’URL cible /api/v2/jobs.'}
    if isinstance(reason, ValueError) and str(reason) == 'Zabbix response invalid':
        return {'error_kind': 'zabbix_format', 'error': 'Réponse Zabbix inattendue : vérifier que l’URL cible bien /api_jsonrpc.php.'}
    if isinstance(reason, ValueError) and str(reason).startswith('Zabbix API error'):
        return {'error_kind': 'zabbix_api', 'error': str(reason) + ' Vérifier le jeton, ses droits de lecture et la version de l’API (jeton Bearer à partir de Zabbix 6.4).'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh response invalid':
        return {'error_kind': 'wazuh_format', 'error': 'Réponse Wazuh inattendue : vérifier que l’URL cible /manager/status.'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh credentials must be user:password':
        return {'error_kind': 'wazuh_credentials', 'error': 'Pour Wazuh, la variable doit contenir « utilisateur:mot_de_passe », pas un jeton ou un en-tête Authorization.'}
    if isinstance(reason, ValueError) and str(reason) == 'Wazuh authentication response missing token':
        return {'error_kind': 'wazuh_auth', 'error': 'Authentification Wazuh acceptée mais réponse sans jeton : vérifier la version de l’API.'}
    return {'error_kind': 'network_or_local', 'error': 'Connexion impossible ou erreur locale. Vérifier le réseau et le format de l’en-tête Authorization (sans retour à la ligne).'}


def indicators(provider, payload):
    """Extract only expected status enums and numbers, never arbitrary API content."""
    if not isinstance(payload, dict):
        return {}
    if provider == 'Elasticsearch':
        result = {k: payload[k] for k in ('number_of_nodes', 'number_of_data_nodes', 'active_shards', 'unassigned_shards', 'active_shards_percent_as_number') if isinstance(payload.get(k), (int, float))}
        if payload.get('status') in ('green', 'yellow', 'red'):
            result['cluster_status'] = payload['status']
        return result
    data = payload.get('data')
    if provider == 'Proxmox' and isinstance(data, list):
        return {'resources': len(data), 'running': sum(isinstance(x, dict) and x.get('status') == 'running' for x in data), 'stopped': sum(isinstance(x, dict) and x.get('status') == 'stopped' for x in data)}
    if provider == 'Wazuh' and isinstance(data, dict):
        items = data.get('affected_items', [])
        values = [v for x in items if isinstance(x, dict) for v in x.values()] if isinstance(items, list) else []
        return {'running_daemons': sum(v == 'running' for v in values), 'stopped_daemons': sum(v == 'stopped' for v in values)}
    if provider == 'Bacula' and isinstance(payload.get('output'), list):
        rows = [x for x in payload['output'] if isinstance(x, dict)]
        codes = [str(x.get('jobstatus') or '') for x in rows]
        return {'jobs_total': len(rows),
                'jobs_ok': sum(c == 'T' for c in codes),
                'jobs_warning': sum(c in ('W', 'A', 'I', 'B') for c in codes),
                'jobs_error': sum(c in ('E', 'f') for c in codes),
                'jobs_running': sum(c == 'R' for c in codes)}
    if provider == 'Zabbix' and isinstance(payload.get('result'), list):
        # Réponse de host.get : on ne compte que ce que le jeton a pu voir.
        rows = [x for x in payload['result'] if isinstance(x, dict)]
        return {'monitored_hosts': sum(str(x.get('status', '')) == '0' for x in rows),
                'unmonitored_hosts': sum(str(x.get('status', '')) == '1' for x in rows)}
    return {}


def install(app, context):
    base, hosts = context.BASE, context.HOSTS
    api_file = base / 'data/api-connections.json'
    api_lock = threading.Lock()
    collecting = set()
    revision = 0

    def api_revision():
        with api_lock:
            return revision

    context.api_revision = api_revision

    @app.post('/api/waf/commands')
    def waf_commands(request: WafCommand):
        from waf_findings import command_plan
        from waf_audit import is_waf_host
        target = next((h for h in hosts if h['key'] == request.host_key), None)
        if not target or not is_waf_host(target):
            raise HTTPException(422, 'Serveur WAF inconnu ou rôle différent de « WAF ModSecurity »')
        try:
            return command_plan(request.ip, request.action, target['ip'])
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc

    def connections():
        return json.loads(api_file.read_text(encoding='utf-8')) if api_file.exists() else []

    def save_hosts(updated):
        path = base / 'hosts.yaml'
        import yaml
        original = yaml.safe_load(path.read_text(encoding='utf-8-sig'))
        original['hosts'] = updated
        atomic_json(path, original)
        hosts[:] = updated

    def add_discovered(additions):
        with context.lock, context.net_lock:
            if context.job['running'] or context.net_job['running']:
                return []
            added = []
            for item in additions:
                Server.model_validate({k: v for k, v in item.items() if k in Server.model_fields})
                if not any(h['key'] == item['key'] or h['ip'] == item['ip'] for h in hosts + added):
                    added.append(item)
            if added:
                save_hosts(hosts + added)
            return added

    context.add_discovered_hosts = add_discovered

    @app.post('/api/manage/hosts')
    def save_server(server: Server):
        with context.lock, context.net_lock:
            prior = next((h for h in hosts if h['key'] == server.key), {})
            # Refus pendant une collecte SEULEMENT si la modification change la façon
            # de joindre le serveur (ou en ajoute un) : c'est ce que la collecte en
            # cours utilise. Rôle, environnement, services, criticité peuvent changer
            # à tout moment — sinon, rotation SSH et réseau à 60 s tournant presque
            # en continu, plus aucune modification ne passerait.
            joignabilite = {'ip': '', 'port': 22, 'user': '', 'collect_enabled': True}
            change_acces = not prior or any(
                str(prior.get(k, defaut)) != str(getattr(server, k)) for k, defaut in joignabilite.items())
            if change_acces and (context.job['running'] or context.net_job['running']):
                raise HTTPException(409, 'Collecte en cours : un changement d’adresse, de port, de compte ou un ajout '
                                         'de serveur attend la fin des collectes. Rôle, environnement et services '
                                         'peuvent être modifiés à tout moment.')
            if any(h['ip'] == server.ip and h['key'] != server.key for h in hosts):
                raise HTTPException(409, 'Adresse IP déjà présente')
            item = {**prior, **server.model_dump()}
            if not item['user']:
                item.pop('user')
            updated = [item if h['key'] == server.key else h for h in hosts]
            if not prior:
                updated.append(item)
            save_hosts(updated)
            with context.connect() as db:
                db.execute('DELETE FROM network WHERE key=?', (server.key,))
            return item

    @app.post('/api/manage/hosts/{key}/delete')
    def delete_server(key: str):
        with context.lock, context.net_lock:
            if context.job['running'] or context.net_job['running']:
                raise HTTPException(409, 'Attendre la fin des collectes')
            if not any(h['key'] == key for h in hosts):
                raise HTTPException(404, 'Serveur inconnu')
            save_hosts([h for h in hosts if h['key'] != key])
            with context.connect() as db:
                for table in ('states', 'network', 'history'):
                    # `table` comes from this fixed tuple, never from a request.
                    db.execute(f'DELETE FROM {table} WHERE key=?', (key,))  # nosec B608
            return {'deleted': key}

    @app.get('/api/connections')
    def list_connections():
        with api_lock:
            return [{**item, 'auth_configured': bool(os.getenv(item.get('token_env', ''), '')) if item.get('token_env') else None} for item in connections()]

    @app.post('/api/connections')
    def save_connection(connection: Connection):
        if connection.host_key and not any(h['key'] == connection.host_key for h in hosts):
            raise HTTPException(422, 'Serveur associé inconnu')
        with api_lock:
            items = connections()
            prior = next((x for x in items if x['key'] == connection.key), {})
            item = {**prior, **connection.model_dump()}
            # Observations belong to one endpoint/account scope, not to its label.
            if any(prior.get(k) != item.get(k) for k in ('provider', 'url', 'host_key', 'token_env')):
                item.pop('last_result', None)
                item.pop('last_success_result', None)
            items = [x for x in items if x['key'] != connection.key] + [item]
            atomic_json(api_file, items)
            return item

    @app.post('/api/connections/{key}/delete')
    def delete_connection(key: str):
        with api_lock:
            atomic_json(api_file, [x for x in connections() if x['key'] != key])
        return {'deleted': key}

    @app.post('/api/connections/certificate')
    def connection_certificate(probe: CertificateProbe):
        u = urlsplit(probe.url)
        if u.scheme != 'https' or not u.hostname:
            raise HTTPException(422, 'URL HTTPS requise')
        try:
            return probe_certificate(u.hostname, u.port or 443)
        except Exception as exc:
            raise HTTPException(422, 'Certificat introuvable : ' + collection_error(exc)['error']) from exc

    context.api_connections = list_connections

    @app.post('/api/connections/{key}/collect')
    def collect_connection(key: str):
        # Manual, full and fast cycles share the same per-source exclusion.
        with api_lock:
            if key in collecting:
                return {'status': 'busy'}
            collecting.add(key)
        try:
            return collect_connection_once(key)
        finally:
            with api_lock:
                collecting.discard(key)

    def collect_connection_once(key: str):
        nonlocal revision
        with api_lock:
            item = next((x for x in connections() if x['key'] == key), None)
        if item is None:
            raise HTTPException(404, 'Connexion inconnue')
        headers = {'Accept': 'application/json'}
        token = os.getenv(item['token_env'], '') if item['token_env'] else ''
        if item['token_env'] and not token:
            raise HTTPException(422, 'Variable du jeton absente sur le serveur OpsControl')
        provider = item.get('provider')
        result = {'collected_at': datetime.now(timezone.utc).isoformat(), 'status': 'unknown'}
        try:
            # `tls_context`, pas `context` : ce nom est déjà celui du module
            # applicatif passé à install(), le masquer ici serait un piège.
            local_bacula = item['url'] == BACULA_TUNNEL_URL and provider == 'Bacula'
            if urlsplit(item['url']).scheme != 'https' and not local_bacula:
                raise ValueError('HTTPS required')
            tls_context = ssl_context_for(item) if not local_bacula else None
            if provider == 'Wazuh':
                # Wazuh's JWT expires in minutes; re-authenticate with user:password on
                # every collection instead of relying on a token pasted in once.
                if token:
                    headers['Authorization'] = 'Bearer ' + wazuh_token(item['url'], token, tls_context, 10)
            elif token:
                # Zabbix >= 6.4 attend un jeton Bearer ; Proxmox PVEAPIToken=...,
                # Elasticsearch ApiKey ... ; Bacula dépend de son édition.
                headers['Authorization'] = 'Bearer ' + token if provider == 'Zabbix' else token
            handlers = [NoRedirect, urllib.request.HTTPSHandler(context=tls_context)]
            if local_bacula:
                # Never send loopback Basic credentials to an environment proxy.
                handlers.append(urllib.request.ProxyHandler({}))
                result['transport'] = 'Tunnel SSH local requis sur 127.0.0.1:19096'
            opener = urllib.request.build_opener(*handlers)
            response_limit = 16 * 1048576 if provider == 'Bacula' else 1048576

            def fetch(request):
                """Lit une réponse JSON en appliquant la limite de taille commune."""
                with opener.open(request, timeout=10) as response:
                    body = response.read(response_limit + 1)
                if len(body) > response_limit:
                    raise ValueError('Bacula response too large' if provider == 'Bacula' else 'Response too large')
                return body, json.loads(body)

            def sibling(path):
                """Même hôte et même port que l'URL configurée, autre chemin."""
                return urlsplit(item['url'])._replace(path=path, query='').geturl()

            if provider == 'Zabbix':
                spec = READ_ONLY_RPC['Zabbix']
                legacy, payloads, raw = None, {}, b''
                def rpc_failure(answer):
                    failure = answer.get('error') if isinstance(answer, dict) else None
                    if not isinstance(failure, dict):
                        return None
                    return str(failure.get('data') or failure.get('message') or 'réponse en erreur')[:200]

                for index, (name, body) in enumerate(spec['calls']):
                    fetched, answer = fetch(rpc_request(item['url'], body, headers, spec['content_type'], legacy))
                    failure = rpc_failure(answer)
                    # Zabbix < 6.4 ignore l'en-tête Authorization et attend le jeton
                    # dans le champ `auth`. Un seul repli, sur la première requête.
                    if failure and legacy is None and token and index == 0:
                        bearer_failure, legacy = failure, token
                        fetched, answer = fetch(rpc_request(item['url'], body, headers, spec['content_type'], legacy))
                        failure = rpc_failure(answer)
                        if failure:
                            # Les deux modes ont échoué : rapporter les deux diagnostics.
                            # N'en montrer qu'un ferait chercher au mauvais endroit —
                            # le message du mode ancien parle de « session » là où le
                            # vrai sujet est la validité du jeton d'API.
                            failure = f'en-tête Bearer → « {bearer_failure} » ; champ auth → « {failure} »'
                        else:
                            legacy = token
                    if failure:
                        raise ValueError('Zabbix API error : ' + failure + '.')
                    payloads[name] = answer
                    if index == 0:
                        raw = fetched
                payload = payloads['hosts']
                from zabbix_inventory import inventory as zabbix_inventory
                result['inventory'] = zabbix_inventory(payload, payloads.get('problems'))
                if result['inventory']['empty']:
                    result['warning'] = 'Aucun hôte visible. Vérifier les droits du jeton sur les groupes d’hôtes ; cela ne prouve pas que Zabbix ne supervise rien.'
                if legacy:
                    result['warning'] = (result.get('warning', '') + ' Jeton transmis en mode compatibilité (Zabbix antérieur à 6.4).').strip()
            else:
                raw, payload = fetch(urllib.request.Request(item['url'], headers=headers))
                if isinstance(payload, dict) and payload.get('error'):
                    raise ValueError('API error response')
            if provider == 'Proxmox':
                from proxmox_inventory import inventory, cluster_info
                result['inventory'] = inventory(payload)
                if result['inventory']['empty']:
                    result['warning'] = 'Aucun nœud ni VM visible. Vérifier le périmètre des permissions du compte et du jeton ; cela ne prouve pas que le cluster est vide.'
                parsed = urlsplit(item['url'])
                if parsed.path.rstrip('/').endswith('/cluster/resources'):
                    status_url = parsed._replace(path=parsed.path.rstrip('/').rsplit('/', 1)[0] + '/status').geturl()
                    try:
                        result['inventory']['cluster'] = cluster_info(fetch(urllib.request.Request(status_url, headers=headers))[1])
                    except Exception as exc:
                        result['inventory']['cluster_error'] = collection_error(exc)['error']
            if provider == 'Bacula':
                from bacula_inventory import inventory as bacula_inventory
                try:
                    clients = fetch(urllib.request.Request(sibling('/api/v2/clients'), headers=headers))[1]
                    if clients.get('error') or not isinstance(clients.get('output'), list):
                        raise ValueError('Bacula response invalid')
                    client_names = {str(c.get('clientid')): c.get('name') for c in clients['output'] if isinstance(c, dict)}
                    payload = {**payload, 'output': [{**j, 'client': client_names.get(str(j.get('clientid'))) or j.get('client')} if isinstance(j, dict) else j for j in payload.get('output', [])]}
                except Exception as exc:
                    result.setdefault('secondary_errors', {})['clients'] = collection_error(exc)['error']
                result['inventory'] = bacula_inventory(payload)
                if result['inventory']['empty']:
                    result['warning'] = ('Aucun job visible. Vérifier les droits de lecture du compte API Baculum ; '
                                         'cela ne prouve pas qu’aucune sauvegarde n’a tourné.')
            if provider == 'Wazuh':
                # Deux sources secondaires, en lecture seule comme la principale.
                # Leur échec n'invalide pas la collecte : l'interface signale
                # simplement que la donnée n'a pas été mesurée.
                from wazuh_inventory import inventory as wazuh_inventory
                extras = {}
                for name, path in (('agents', '/agents/summary/status'), ('manager', '/manager/info')):
                    try:
                        extras[name] = fetch(urllib.request.Request(sibling(path), headers=headers))[1]
                    except Exception as exc:
                        result.setdefault('secondary_errors', {})[name] = collection_error(exc)['error']
                        extras[name] = None
                result['inventory'] = wazuh_inventory(payload, extras['agents'], extras['manager'])
                try:
                    agents = fetch(urllib.request.Request(sibling('/agents') + '?limit=500&select=id,name,ip,status,version,lastKeepAlive', headers=headers))[1]
                    rows = agents.get('data', {}).get('affected_items', [])
                    if agents.get('error') or not isinstance(rows, list):
                        raise ValueError('Wazuh response invalid')
                    result['inventory']['agents_inventory'] = [{k: a.get(k) for k in ('id','name','ip','status','version','lastKeepAlive')} for a in rows if isinstance(a, dict)]
                    result['inventory']['agents_inventory_total'] = agents.get('data', {}).get('total_affected_items')
                    result['inventory']['agents_inventory_scope'] = 'Au maximum 500 agents visibles ; absence de correspondance ne prouve pas une absence de protection.'
                except Exception as exc:
                    result.setdefault('secondary_errors', {})['agents_inventory'] = collection_error(exc)['error']
            # Raw API bodies may contain secrets; expose structure and counts only.
            result.update(status='observed', summary={
                'type': type(payload).__name__,
                'entries': len(payload) if isinstance(payload, (list, dict)) else 1,
                'bytes': len(raw),
            })
            result['indicators'] = indicators(provider, payload)
        except Exception as exc:
            result.update(collection_error(exc))
            if result.get('http_status') in (401, 403):
                # Un refus d'authentification vient bien plus souvent d'une valeur
                # mal recopiée que d'un droit manquant : le dire évite de partir
                # chercher des permissions côté produit.
                hint = credential_shape(provider, token)
                if hint:
                    result['error'] += ' ' + hint
        with api_lock:
            items = connections()
            current = next((x for x in items if x['key'] == key), None)
            if current and all(current.get(k) == item.get(k) for k in ('provider', 'url', 'token_env', 'host_key', 'ca_bundle')):
                if result.get('status') == 'observed':
                    current.pop('last_success_result', None)
                elif (current.get('last_result') or {}).get('status') == 'observed':
                    current['last_success_result'] = current['last_result']
                current['last_result'] = result
                atomic_json(api_file, items)
                revision += 1
        # A refreshed VM state also requires a current ping for the online view.
        # The existing network lock prevents concurrent duplicate network batches.
        if provider == 'Proxmox' and result.get('status') == 'observed' and hasattr(context, 'launch_network'):
            context.launch_network(context.HOSTS, 'collecte-proxmox')
        return result

    context.collect_api_connection = collect_connection
