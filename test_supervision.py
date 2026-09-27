"""Collecte Zabbix (JSON-RPC en POST) et enrichissement Wazuh."""
import json
import sqlite3
import tempfile
import threading
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import FastAPI

import management as m
import wazuh_inventory
import zabbix_inventory


def response_for(body):
    """Réponse HTTP simulée : urlopen renvoie un gestionnaire de contexte."""
    handle = MagicMock()
    handle.__enter__.return_value.read.return_value = json.dumps(body).encode()
    return handle


class ZabbixInventoryTests(unittest.TestCase):
    def test_hosts_and_problems_normalised(self):
        hosts = {'jsonrpc': '2.0', 'id': 1, 'result': [
            {'hostid': '10084', 'host': 'demo-host-07', 'name': 'Zabbix server', 'status': '0',
             'interfaces': [{'ip': '192.0.2.11'}]},
            {'hostid': '10085', 'host': 'old', 'name': 'Hôte retiré', 'status': '1', 'interfaces': []},
            {'nothing': True},
        ]}
        triggers = {'jsonrpc': '2.0', 'id': 2, 'result': [
            {'triggerid': '1', 'description': 'Disque plein', 'priority': '4', 'lastchange': '1757000000',
             'hosts': [{'host': 'demo-host-07', 'name': 'Zabbix server'}]},
            {'triggerid': '2', 'description': 'Charge élevée', 'priority': '2', 'hosts': []},
            {'triggerid': '3', 'description': 'Gravité absente', 'priority': None, 'hosts': []},
        ]}
        result = zabbix_inventory.inventory(hosts, triggers)
        self.assertEqual(result['counts'], {'monitored': 1, 'unmonitored': 1, 'unknown': 0})
        self.assertEqual(result['ignored'], 1)
        self.assertEqual(result['hosts'][1]['addresses'], ['192.0.2.11'])
        # Le plus grave d'abord, et une gravité absente reste 'unknown'.
        self.assertEqual([p['severity'] for p in result['problems']], ['critical', 'warning', 'unknown'])
        # Les deux familles de compteurs cohabitent sans s'écraser.
        # La gravité absente du 3e trigger compte comme 'unknown', jamais comme sain.
        self.assertEqual(result['problem_counts'], {'critical': 1, 'warning': 1, 'unknown': 1})
        self.assertEqual(result['counts'], {'monitored': 1, 'unmonitored': 1, 'unknown': 0})
        self.assertEqual(result['problems'][0]['hosts'], ['Zabbix server'])

    def test_host_and_problem_keys_never_collide(self):
        """inventory() fusionne deux dictionnaires : aucune clé ne doit s'écraser."""
        hosts = {'jsonrpc': '2.0', 'result': [{'hostid': '1', 'host': 'a', 'name': 'A', 'status': '0'}]}
        triggers = {'jsonrpc': '2.0', 'result': [{'triggerid': '1', 'description': 'X', 'priority': '4', 'hosts': []}]}
        result = zabbix_inventory.inventory(hosts, triggers)
        self.assertIn('Hôtes visibles', result['scope'])
        self.assertIn('Triggers en anomalie', result['problems_scope'])
        self.assertEqual(result['counts'], {'monitored': 1, 'unmonitored': 0, 'unknown': 0})
        self.assertEqual(result['problem_counts'], {'critical': 1, 'warning': 0, 'unknown': 0})
        shared = set(zabbix_inventory.hosts_inventory(hosts)) & set(zabbix_inventory.problems(triggers))
        self.assertEqual(shared, set(), f'clés en collision : {shared}')

    def test_problems_absent_is_not_zero_problems(self):
        hosts = {'jsonrpc': '2.0', 'result': []}
        result = zabbix_inventory.inventory(hosts, None)
        self.assertIsNone(result['problems'])
        self.assertTrue(result['empty'])

    def test_malformed_response_rejected(self):
        for payload in ({'result': 'texte'}, {'error': {}}, [], None):
            with self.assertRaises(ValueError):
                zabbix_inventory.inventory(payload)


class WazuhInventoryTests(unittest.TestCase):
    STATUS = {'data': {'affected_items': [{'wazuh-db': 'running', 'wazuh-remoted': 'stopped', 'wazuh-x': 'bizarre'}]}}

    def test_daemons_counted_and_sorted(self):
        result = wazuh_inventory.inventory(self.STATUS)
        self.assertEqual(result['counts'], {'running': 1, 'stopped': 1, 'failed': 0, 'unknown': 1})
        self.assertEqual(result['daemons'][0]['name'], 'wazuh-remoted')  # arrêté en tête
        self.assertFalse(result['empty'])

    def test_agents_and_manager_optional(self):
        result = wazuh_inventory.inventory(self.STATUS)
        self.assertIsNone(result['agents'])
        self.assertIsNone(result['manager'])

    def test_agents_summary_normalised(self):
        agents = {'data': {'connection': {'active': 12, 'disconnected': 3, 'pending': 0, 'never_connected': 1, 'total': 16}}}
        info = {'data': {'affected_items': [{'version': 'v4.14.5', 'max_agents': '10000'}]}}
        result = wazuh_inventory.inventory(self.STATUS, agents, info)
        self.assertEqual(result['agents']['total'], 16)
        self.assertEqual({s['key']: s['count'] for s in result['agents']['states']}['active'], 12)
        self.assertEqual(result['manager']['version'], 'v4.14.5')

    def test_broken_secondary_source_does_not_break_collection(self):
        result = wazuh_inventory.inventory(self.STATUS, {'data': 'cassé'}, None)
        self.assertIsNone(result['agents'])
        self.assertEqual(result['counts']['running'], 1)


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        (base / 'hosts.yaml').write_text(json.dumps({'ssh': {'user': 'test'}, 'hosts': []}))

        @contextmanager
        def connect():
            db = sqlite3.connect(base / 'test.db')
            try:
                with db:
                    for table in ('network', 'states', 'history'):
                        db.execute(f'CREATE TABLE IF NOT EXISTS {table}(key TEXT)')
                    yield db
            finally:
                db.close()

        self.context = SimpleNamespace(BASE=base, HOSTS=[], lock=threading.Lock(), net_lock=threading.Lock(),
                                       job={'running': False}, net_job={'running': False}, connect=connect)
        app = FastAPI()
        m.install(app, self.context)
        self.routes = {(r.path, next(iter(r.methods))): r.endpoint for r in app.routes if r.path.startswith('/api/')}

    def call(self, path, *args, method='POST'):
        return self.routes[path, method](*args)

    def add_zabbix(self):
        self.call('/api/connections', m.Connection(key='zbx', name='Zabbix', provider='Zabbix',
                                                   url='https://zbx.example/api_jsonrpc.php', token_env='TEST_ZBX_AUTH'))

    def test_zabbix_posts_fixed_readonly_rpc_with_bearer(self):
        self.add_zabbix()
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'jsonrpc': '2.0', 'id': 1, 'result': [{'hostid': '1', 'host': 'a', 'name': 'A', 'status': '0'}]}),
            response_for({'jsonrpc': '2.0', 'id': 2, 'result': [{'triggerid': '9', 'description': 'X', 'priority': '5', 'hosts': []}]}),
        ]
        with patch.dict('os.environ', {'TEST_ZBX_AUTH': 'jeton-secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'zbx')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['indicators'], {'monitored_hosts': 1, 'unmonitored_hosts': 0})
        self.assertEqual(result['inventory']['problems'][0]['severity'], 'critical')
        first = opener.open.call_args_list[0].args[0]
        self.assertEqual(first.get_method(), 'POST')
        self.assertEqual(first.get_header('Authorization'), 'Bearer jeton-secret')
        # Le corps est figé côté serveur : seules des méthodes de lecture.
        bodies = [json.loads(c.args[0].data) for c in opener.open.call_args_list]
        self.assertEqual([b['method'] for b in bodies], ['host.get', 'trigger.get'])
        self.assertNotIn('jeton-secret', json.dumps(bodies))
        self.assertNotIn('jeton-secret', json.dumps(result))

    def test_zabbix_falls_back_to_legacy_auth_field(self):
        self.add_zabbix()
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'jsonrpc': '2.0', 'error': {'message': 'Not authorised', 'data': 'Not authorised.'}}),
            response_for({'jsonrpc': '2.0', 'id': 1, 'result': []}),
            response_for({'jsonrpc': '2.0', 'id': 2, 'result': []}),
        ]
        with patch.dict('os.environ', {'TEST_ZBX_AUTH': 'jeton-secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'zbx')
        self.assertEqual(result['status'], 'observed')
        self.assertIn('compatibilité', result['warning'])
        self.assertEqual(json.loads(opener.open.call_args_list[1].args[0].data)['auth'], 'jeton-secret')
        self.assertNotIn('jeton-secret', json.dumps(result))

    def test_both_auth_diagnostics_are_reported_when_both_fail(self):
        """Le message du mode ancien parle de « session » : ne pas masquer celui du Bearer."""
        self.add_zabbix()
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'jsonrpc': '2.0', 'error': {'message': 'Not authorised', 'data': 'Not authorised.'}}),
            response_for({'jsonrpc': '2.0', 'error': {'message': 'Application error.', 'data': 'Session terminated, re-login, please.'}}),
        ]
        with patch.dict('os.environ', {'TEST_ZBX_AUTH': 'jeton-secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'zbx')
        self.assertEqual(result['error_kind'], 'zabbix_api')
        self.assertIn('Not authorised', result['error'])
        self.assertIn('Session terminated', result['error'])
        self.assertNotIn('jeton-secret', json.dumps(result))

    def test_zabbix_api_error_is_reported_without_leaking(self):
        self.add_zabbix()
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'jsonrpc': '2.0', 'error': {'message': 'Invalid params', 'data': 'Aucun droit.'}}),
            response_for({'jsonrpc': '2.0', 'error': {'message': 'Invalid params', 'data': 'Aucun droit.'}}),
        ]
        with patch.dict('os.environ', {'TEST_ZBX_AUTH': 'jeton-secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'zbx')
        self.assertNotEqual(result['status'], 'observed')
        self.assertEqual(result['error_kind'], 'zabbix_api')
        self.assertNotIn('jeton-secret', json.dumps(result))

    def test_wazuh_collects_agents_and_manager(self):
        self.call('/api/connections', m.Connection(key='waz', name='Waz', provider='Wazuh',
                                                   url='https://waz.example:55000/manager/status', token_env='TEST_WAZ_AUTH'))
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'data': {'token': 'jwt'}}),
            response_for({'data': {'affected_items': [{'wazuh-db': 'running'}]}}),
            response_for({'data': {'connection': {'active': 12, 'disconnected': 3, 'pending': 0, 'never_connected': 1, 'total': 16}}}),
            response_for({'data': {'affected_items': [{'version': 'v4.14.5'}]}}),
        ]
        with patch.dict('os.environ', {'TEST_WAZ_AUTH': 'user:secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'waz')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['inventory']['agents']['total'], 16)
        self.assertEqual(result['inventory']['manager']['version'], 'v4.14.5')
        # Les sources secondaires visent le même hôte et le même port.
        urls = [c.args[0].full_url for c in opener.open.call_args_list]
        self.assertIn('https://waz.example:55000/agents/summary/status', urls)
        self.assertIn('https://waz.example:55000/manager/info', urls)
        self.assertNotIn('secret', json.dumps(result))

    def test_wazuh_secondary_failure_keeps_primary_result(self):
        self.call('/api/connections', m.Connection(key='waz', name='Waz', provider='Wazuh',
                                                   url='https://waz.example:55000/manager/status', token_env='TEST_WAZ_AUTH'))
        opener = MagicMock()
        opener.open.side_effect = [
            response_for({'data': {'token': 'jwt'}}),
            response_for({'data': {'affected_items': [{'wazuh-db': 'running'}]}}),
            OSError('agents indisponible'),
            OSError('info indisponible'),
        ]
        with patch.dict('os.environ', {'TEST_WAZ_AUTH': 'user:secret'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'waz')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['inventory']['counts']['running'], 1)
        self.assertIsNone(result['inventory']['agents'])
        self.assertIn('agents', result['secondary_errors'])

    def test_credential_shape_diagnoses_without_revealing(self):
        secret = 'VnVhQ2ZHY0JDZGJrUW0tZTVhT3g6dWkybHAyYXhUTm1zeWFrdzl0dk5udw=='  # pragma: allowlist secret -- fictional format fixture
        cas = [
            ('Elasticsearch', secret,               'doit commencer par'),          # préfixe oublié
            ('Elasticsearch', 'ApiKey pas-du-b64!', 'base64 valide'),               # mauvais format Kibana
            ('Elasticsearch', 'ApiKey ' + secret,   None),                          # correct
            ('Proxmox',       'juste-le-secret',    'PVEAPIToken='),
            ('Proxmox',       'PVEAPIToken=a@pve!b=c', None),
            ('Wazuh',         'un-jeton-jwt',       'utilisateur:mot_de_passe'),
            ('Wazuh',         'user:pass',          None),
            ('Zabbix',        'abcdef',             None),                          # pas de forme imposée ici
        ]
        for provider, token, attendu in cas:
            hint = m.credential_shape(provider, token)
            if attendu is None:
                self.assertIsNone(hint, f'{provider} : diagnostic inattendu « {hint} »')
            else:
                self.assertIsNotNone(hint, f'{provider} : diagnostic manquant')
                self.assertIn(attendu, hint)
                # Le secret ne doit jamais fuiter dans le message.
                self.assertNotIn(token, hint)
                self.assertNotIn(secret[:16], hint)

    def test_401_carries_the_shape_diagnostic(self):
        self.call('/api/connections', m.Connection(key='es', name='ES', provider='Elasticsearch',
                                                   url='https://es.example:9200/_cluster/health', token_env='TEST_ES_AUTH'))
        opener = MagicMock()
        opener.open.side_effect = m.urllib.error.HTTPError('https://es.example:9200/_cluster/health', 401, 'Unauthorized', {}, None)
        with patch.dict('os.environ', {'TEST_ES_AUTH': 'cle-collee-sans-prefixe'}), \
             patch.object(m.urllib.request, 'build_opener', return_value=opener):
            result = self.call('/api/connections/{key}/collect', 'es')
        self.assertEqual(result['http_status'], 401)
        self.assertIn('doit commencer par', result['error'])
        self.assertNotIn('cle-collee-sans-prefixe', json.dumps(result))

    def test_zabbix_is_an_accepted_provider(self):
        self.assertIn('Zabbix', m.Connection.model_fields['provider'].annotation.__args__)


if __name__ == '__main__':
    unittest.main()


class BaculaTests(unittest.TestCase):
    """Baculum API v2 : {"error": 0, "output": [ ... ]}"""

    PAYLOAD = {'error': 0, 'output': [
        {'jobid': 101, 'name': 'Sauvegarde-SQL', 'client': 'demo-host-01-fd', 'level': 'F',
         'jobstatus': 'T', 'endtime': '2026-09-14 02:14:03', 'jobbytes': 84213, 'jobfiles': 12},
        {'jobid': 102, 'name': 'Sauvegarde-Web', 'client': 'demo-host-06-fd', 'level': 'I',
         'jobstatus': 'E', 'endtime': '2026-09-14 02:31:55', 'jobbytes': 0, 'jobfiles': 0},
        {'jobid': 103, 'name': 'Sauvegarde-Fic', 'client': 'demo-nfs-01-fd', 'level': 'I',
         'jobstatus': 'W', 'endtime': '2026-09-14 03:02:10'},
        {'jobid': 104, 'name': 'Sauvegarde-App', 'jobstatus': 'R'},
        {'jobid': 105, 'name': 'Code inconnu', 'jobstatus': 'Z'},
        'pas un objet',
    ]}

    def test_jobs_normalised_and_ranked(self):
        import bacula_inventory
        result = bacula_inventory.inventory(self.PAYLOAD)
        self.assertEqual(result['jobs_count'], 5)
        self.assertEqual(result['counts'],
                         {'ok': 1, 'warning': 1, 'critical': 1, 'running': 1, 'pending': 0, 'unknown': 1})
        # Les anomalies remontent en tête.
        self.assertEqual([j['severity'] for j in result['jobs']][:3], ['critical', 'warning', 'unknown'])
        # Un code non reconnu reste 'unknown', jamais rangé avec les succès.
        self.assertEqual(result['jobs'][2]['status_label'], 'État non reconnu')
        self.assertEqual(result['last_success'], '2026-09-14 02:14:03')
        self.assertFalse(result['empty'])

    def test_current_state_is_last_run_per_job_not_history(self):
        # Un historique long peut afficher des milliers d'« erreurs » pour un seul
        # job en échec : l'état actuel se lit sur le dernier passage de chaque job.
        import bacula_inventory
        result = bacula_inventory.inventory({'output': [
            {'jobid': 1, 'name': 'Backup-A', 'jobstatus': 'E', 'endtime': '2025-01-01 01:00:00'},
            {'jobid': 2, 'name': 'Backup-A', 'jobstatus': 'E', 'endtime': '2025-01-02 01:00:00'},
            {'jobid': 3, 'name': 'Backup-A', 'jobstatus': 'T', 'endtime': '2026-09-22 01:00:00'},
            {'jobid': 4, 'name': 'Backup-B', 'jobstatus': 'T', 'endtime': '2026-09-21 01:00:00'},
            {'jobid': 5, 'name': 'Backup-B', 'jobstatus': 'f', 'endtime': '2026-09-22 02:00:00'},
        ]})
        self.assertEqual(result['counts']['critical'], 3)
        self.assertEqual(result['latest_counts']['critical'], 1)
        self.assertEqual(result['latest_counts']['ok'], 1)
        self.assertEqual([j['name'] for j in result['latest']], ['Backup-B', 'Backup-A'])
        self.assertEqual(result['history_since'], '2025-01-01 01:00:00')

    def test_history_bounded_but_counts_complete(self):
        import bacula_inventory
        rows = [{'jobid': i, 'name': 'Job-%d' % (i % 7), 'jobstatus': 'T'} for i in range(1, 1201)]
        with patch.object(bacula_inventory, 'HISTORY_KEPT', 100):
            result = bacula_inventory.inventory({'output': rows})
        self.assertEqual(result['jobs_count'], 1200)
        self.assertEqual(result['counts']['ok'], 1200)
        self.assertEqual(len(result['jobs']), 100)
        self.assertEqual(result['jobs_truncated'], 1100)
        # On garde les plus récents, pas les plus anciens.
        self.assertEqual(min(j['jobid'] for j in result['jobs']), 1101)
        self.assertEqual(len(result['latest']), 7)

    def test_scope_never_claims_a_backup_is_restorable(self):
        import bacula_inventory
        scope = bacula_inventory.inventory(self.PAYLOAD)['scope']
        self.assertIn('pas que la sauvegarde est restaurable', scope)

    def test_malformed_response_rejected(self):
        import bacula_inventory
        for payload in ({'output': 'texte'}, {'error': 0}, [], None):
            with self.assertRaises(ValueError):
                bacula_inventory.inventory(payload)

    def test_indicators_and_basic_auth_hint(self):
        self.assertEqual(m.indicators('Bacula', self.PAYLOAD),
                         {'jobs_total': 5, 'jobs_ok': 1, 'jobs_warning': 1, 'jobs_error': 1, 'jobs_running': 1})
        # Les indicateurs et l'inventaire doivent compter de la même façon :
        # deux totaux divergents dans la même collecte seraient ingérables.
        inventaire = __import__('bacula_inventory').inventory(self.PAYLOAD)['counts']
        indicateurs = m.indicators('Bacula', self.PAYLOAD)
        self.assertEqual(indicateurs['jobs_ok'], inventaire['ok'])
        self.assertEqual(indicateurs['jobs_warning'], inventaire['warning'])
        self.assertEqual(indicateurs['jobs_error'], inventaire['critical'])
        self.assertIn('Basic', m.credential_shape('Bacula', 'user:motdepasse'))
        self.assertIsNone(m.credential_shape('Bacula', 'Basic dXNlcjpwYXNz'))


class TlsDiagnosticTests(unittest.TestCase):
    def test_plain_http_service_is_named_as_such(self):
        """Un serveur qui parle HTTP sur un port HTTPS a une signature nette."""
        for motif in ('WRONG_VERSION_NUMBER', 'UNKNOWN_PROTOCOL', 'HTTP_REQUEST'):
            erreur = m.ssl.SSLError(1, motif)
            erreur.reason = motif
            diag = m.collection_error(m.urllib.error.URLError(erreur))
            self.assertEqual(diag['error_kind'], 'tls_absent', motif)
            self.assertIn('HTTP en clair', diag['error'])

    def test_other_tls_errors_keep_the_certificate_wording(self):
        erreur = m.ssl.SSLError(1, 'DECRYPTION_FAILED')
        erreur.reason = 'DECRYPTION_FAILED'
        diag = m.collection_error(m.urllib.error.URLError(erreur))
        self.assertEqual(diag['error_kind'], 'tls')


class MissingAuthSignalTests(unittest.TestCase):
    """Un secret absent doit etre signale une fois, globalement."""

    def test_overview_lists_sources_without_credentials(self):
        import app
        # api_connections() est fourni par management.install au demarrage.
        faux = [
            {'key': 'a', 'name': 'Proxmox audit', 'provider': 'Proxmox', 'auth_configured': False},
            {'key': 'b', 'name': 'Wazuh', 'provider': 'Wazuh', 'auth_configured': True},
            {'key': 'c', 'name': 'Zabbix', 'provider': 'Zabbix', 'auth_configured': False},
            {'key': 'd', 'name': 'Sans jeton', 'provider': 'JSON', 'auth_configured': None},
        ]
        with patch.object(app, 'api_connections', lambda: faux):
            resultat = app.overview()
        # Seules les sources dont la variable est declaree mais absente remontent.
        self.assertEqual(resultat['missing_auth'], ['Proxmox audit', 'Zabbix'])

    def test_no_signal_when_every_secret_is_loaded(self):
        import app
        faux = [{'key': 'a', 'name': 'Proxmox', 'provider': 'Proxmox', 'auth_configured': True}]
        with patch.object(app, 'api_connections', lambda: faux):
            self.assertEqual(app.overview()['missing_auth'], [])
