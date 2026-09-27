import json
import shutil
import ssl
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import sqlite3
from fastapi import FastAPI, HTTPException
from pydantic import ValidationError
import management as m


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base/'hosts.yaml').write_text(json.dumps({'ssh': {'user': 'test'}, 'hosts': []}))
        @contextmanager
        def connect():
            db = sqlite3.connect(base/'test.db')
            try:
                with db:
                    for table in ('network', 'states', 'history'):
                        db.execute(f'CREATE TABLE IF NOT EXISTS {table}(key TEXT)')
                    yield db
            finally:
                db.close()
        self.context = SimpleNamespace(BASE=base, HOSTS=[], lock=threading.Lock(), net_lock=threading.Lock(), job={'running':False}, net_job={'running':False}, connect=connect)
        app = FastAPI()
        m.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))):r.endpoint for r in app.routes if r.path.startswith('/api/')}

    def call(self, path, *args, method='POST'):
        return self.routes[path, method](*args)

    def test_connection_identity_change_discards_old_observation(self):
        connection = m.Connection(key='api', name='API', provider='JSON', url='https://example.test/a')
        self.call('/api/connections', connection)
        target = self.context.BASE/'data/api-connections.json'
        stored = json.loads(target.read_text())
        stored[0].update(last_result={'status':'observed'}, last_success_result={'status':'observed'})
        target.write_text(json.dumps(stored))
        renamed = self.call('/api/connections', connection.model_copy(update={'name':'Renamed'}))
        self.assertIn('last_result', renamed)
        moved = self.call('/api/connections', connection.model_copy(update={'url':'https://example.test/b'}))
        self.assertNotIn('last_result', moved)
        self.assertNotIn('last_success_result', moved)

    def test_inventory_persists_and_preserves_metadata(self):
        self.call('/api/manage/hosts', m.Server(key='test', name='Test', ip='192.0.2.200'))
        self.context.HOSTS[0]['node'] = 'pve01'
        self.call('/api/manage/hosts', m.Server(key='test', name='Updated', ip='192.0.2.200', services=['nginx']))
        saved = json.loads((self.context.BASE/'hosts.yaml').read_text())
        self.assertEqual(saved['hosts'][0]['node'], 'pve01')
        self.assertEqual(saved['hosts'][0]['services'], ['nginx'])
        self.call('/api/manage/hosts/{key}/delete', 'test')
        self.assertEqual(self.context.HOSTS, [])

    def test_duplicate_and_busy_rejected(self):
        self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='192.0.2.200'))
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts', m.Server(key='b', name='B', ip='192.0.2.200'))
        self.context.net_job['running'] = True
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts/{key}/delete', 'a')

    def test_busy_blocks_only_access_changes(self):
        # Pendant une collecte : rôle et services modifiables, accès (IP) et ajout refusés.
        self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='192.0.2.200'))
        self.context.job['running'] = True
        item = self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='192.0.2.200', role='DB',
                                                       services=['postgresql']))
        self.assertEqual((item['role'], item['services']), ('DB', ['postgresql']))
        with self.assertRaises(HTTPException) as e:
            self.call('/api/manage/hosts', m.Server(key='a', name='A', ip='192.0.2.201'))
        self.assertEqual(e.exception.status_code, 409)
        with self.assertRaises(HTTPException):
            self.call('/api/manage/hosts', m.Server(key='nouveau', name='N', ip='192.0.2.202'))

    def test_validation(self):
        for ip in ('bad', '192.0.2.1;id'):
            with self.assertRaises(ValidationError):m.Server(key='a', name='A', ip=ip)
        with self.assertRaises(ValidationError):m.Server(key='a', name='A', ip='127.0.0.1', services=['nginx;id'])
        for url in ('http://example.org', 'https://user:secret@example.org', 'https://example.org/?token=secret'):  # pragma: allowlist secret -- rejection fixtures
            with self.assertRaises(ValidationError):m.Connection(key='a', name='A', url=url)

    def test_waf_command_preview(self):
        self.context.HOSTS.append({'key': 'waf01', 'ip': '192.0.2.131', 'role': 'WAF ModSecurity'})
        preview=self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='waf01'))
        self.assertFalse(preview['executable'])
        self.assertEqual(preview['execution_host'],'192.0.2.131')
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1; id',action='ban',host_key='waf01'))

    def test_waf_command_rejects_non_waf_host(self):
        self.context.HOSTS.append({'key': 'app01', 'ip': '192.0.2.9', 'role': 'À renseigner'})
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='app01'))
        with self.assertRaises(HTTPException):
            self.call('/api/waf/commands',m.WafCommand(ip='192.0.2.1',action='ban',host_key='inconnu'))

    def test_ssl_context_for_routes_pinned_vs_file_vs_default(self):
        self.assertIsInstance(m.ssl_context_for({'ca_bundle': ''}), ssl.SSLContext)
        with self.assertRaises(FileNotFoundError):
            m.ssl_context_for({'ca_bundle': str(self.context.BASE / 'missing.pem')})
        with self.assertRaises(ssl.SSLError):
            m.ssl_context_for({'ca_bundle': '-----BEGIN CERTIFICATE-----\nbm90cmVhbA==\n-----END CERTIFICATE-----'})

    def test_pinned_certificate_keeps_full_verification(self):
        """Épingler ne doit jamais désactiver une vérification.

        Un certificat auto-signé sans CA:TRUE est une ancre légitime pour le
        serveur qui le présente (OpenSSL l'accepte) : on ne le pré-refuse plus.
        Mais chaîne, nom d'hôte et validité restent contrôlés.
        """
        import subprocess
        if not shutil.which('openssl'):
            self.skipTest('openssl indisponible')
        pem = self.context.BASE / 'leaf.pem'
        key = self.context.BASE / 'leaf.key'
        generated = subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-days', '2', '-nodes',
             '-keyout', str(key), '-out', str(pem), '-subj', '/CN=exemple.test',
             '-addext', 'basicConstraints=critical,CA:FALSE',
             '-addext', 'subjectAltName=DNS:exemple.test'],
            capture_output=True)
        if generated.returncode != 0:
            self.skipTest('openssl indisponible')
        context = m.ssl_context_for({'ca_bundle': pem.read_text()})
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertTrue(context.get_ca_certs.__self__ is context)

    def test_connection_ca_bundle_rejects_incomplete_pem(self):
        with self.assertRaises(ValidationError):
            m.Connection(key='a', name='A', url='https://example.org', ca_bundle='-----BEGIN CERTIFICATE-----\nnotclosed')

    def test_probe_certificate_fingerprint_and_graceful_fallback(self):
        fake_der = b'not-a-real-certificate-but-bytes'
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
        class FakeSSLSock(FakeSock):
            def getpeercert(self, binary_form=False):
                return fake_der if binary_form else {}
        class FakeUnverifiedCtx:
            def wrap_socket(self, sock, server_hostname=None): return FakeSSLSock()
        with patch.object(m.socket, 'create_connection', return_value=FakeSock()), \
             patch.object(m.ssl, '_create_unverified_context', return_value=FakeUnverifiedCtx()):
            result = m.probe_certificate('example.test', 443)
        self.assertEqual(result['hostname'], 'example.test')
        self.assertEqual(result['sha256_fingerprint'].count(':'), 31)
        self.assertIsNone(result['subject_cn'])

    def test_certificate_endpoint_rejects_non_https(self):
        with self.assertRaises(HTTPException):
            self.call('/api/connections/certificate', m.CertificateProbe(url='http://example.org'))

    def test_wazuh_token_exchange_and_bad_credentials(self):
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data":{"token":"jwt-abc"}}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            token = m.wazuh_token('https://wazuh.example:55000/manager/status', 'wazuh-wui:secret', m.ssl.create_default_context(), 10)
        self.assertEqual(token, 'jwt-abc')
        sent_request = opener.open.call_args.args[0]
        self.assertEqual(sent_request.full_url, 'https://wazuh.example:55000/security/user/authenticate')
        self.assertTrue(sent_request.get_header('Authorization').startswith('Basic '))
        with self.assertRaises(ValueError):
            m.wazuh_token('https://wazuh.example:55000/manager/status', 'no-colon', m.ssl.create_default_context(), 10)

    def test_wazuh_collection_reauthenticates_every_time(self):
        self.call('/api/connections', m.Connection(key='waz', name='Waz', provider='Wazuh', url='https://wazuh.example:55000/manager/status', token_env='TEST_WAZUH_AUTH'))
        auth_response = unittest.mock.MagicMock()
        auth_response.__enter__.return_value.read.return_value = b'{"data":{"token":"fresh-jwt"}}'
        data_response = unittest.mock.MagicMock()
        data_response.__enter__.return_value.read.return_value = b'{"data":{"affected_items":[{"status":"running"}]}}'
        opener = unittest.mock.MagicMock()
        opener.open.side_effect = [auth_response, data_response]
        with patch.dict('os.environ', {'TEST_WAZUH_AUTH': 'wazuh-wui:secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'waz')
        self.assertEqual(result['status'], 'observed')
        second_call_headers = opener.open.call_args_list[1].args[0].headers
        self.assertEqual(second_call_headers.get('Authorization'), 'Bearer fresh-jwt')
        self.assertNotIn('secret', json.dumps(result))

    def test_api_collect_and_secret_exclusion(self):
        self.call('/api/connections', m.Connection(key='elastic', name='Elastic', provider='Elasticsearch', url='https://example.org/_cluster/health'))
        response = unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"status":"yellow","number_of_nodes":3,"token":"private"}'
        opener = unittest.mock.MagicMock()
        opener.open.return_value = response
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'elastic')
        self.assertEqual(result['indicators']['cluster_status'], 'yellow')
        self.assertNotIn('private', json.dumps(result))
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')

    def test_api_failure_not_ok(self):
        self.call('/api/connections', m.Connection(key='a', name='A', url='https://example.org'))
        with patch.object(m.urllib.request, 'build_opener', side_effect=OSError('secret')):
            result = self.call('/api/connections/{key}/collect', 'a')
        self.assertEqual(result['status'], 'unknown')
        self.assertNotIn('secret', json.dumps(result))

    def test_proxmox_collection_refreshes_network(self):
        from unittest.mock import Mock
        self.context.launch_network = Mock()
        self.call('/api/connections', m.Connection(key='pve-ping', name='PVE', provider='Proxmox',
                  url='https://pve.test/resources'))
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, *args): return b'{"data":[]}'
        opener = Mock()
        opener.open.return_value = Response()
        with patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'pve-ping')
        self.assertEqual(result['status'], 'observed')
        self.context.launch_network.assert_called_once_with([], 'collecte-proxmox')

    def test_proxmox_details_persist(self):
        self.call('/api/connections',m.Connection(key='pve',name='Cluster',url='https://pve.example/api2/json/cluster/resources',provider='Proxmox'))
        response=unittest.mock.MagicMock()
        response.__enter__.return_value.read.return_value=b'{"data":[{"type":"qemu","vmid":101,"node":"pve01","name":"web","status":"running"}]}'
        opener=unittest.mock.MagicMock();opener.open.return_value=response
        with patch.object(m.urllib.request,'build_opener',return_value=opener):
            result=self.call('/api/connections/{key}/collect','pve')
        self.assertEqual(result['inventory']['nodes'][0]['guests'][0]['vmid'],101)
        saved=self.call('/api/connections',method='GET')
        self.assertEqual(saved[0]['last_result']['inventory'],result['inventory'])


if __name__ == '__main__':
    unittest.main()
