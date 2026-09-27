import json
from unittest.mock import MagicMock, patch
from pydantic import ValidationError
from test_management import ManagementTests
import management as m


class BaculaTunnelTests(ManagementTests):
    def test_loopback_exception_is_exact_and_bacula_only(self):
        m.Connection(key='b', name='Backup', provider='Bacula', url=m.BACULA_TUNNEL_URL)
        for provider, url in [('JSON', m.BACULA_TUNNEL_URL),
                              ('Bacula', 'http://192.0.2.148:9096/api/v2/jobs'),
                              ('Bacula', m.BACULA_TUNNEL_URL + '?x=1')]:
            with self.assertRaises(ValidationError):
                m.Connection(key='b', name='Backup', provider=provider, url=url)

    def test_local_get_disables_proxy_and_accepts_large_history(self):
        self.call('/api/connections', m.Connection(key='b', name='Backup', provider='Bacula',
                  url=m.BACULA_TUNNEL_URL, token_env='TEST_BACULA_AUTH'))
        response = MagicMock()
        payload = {'error': 0, 'output': [{'jobid': i, 'jobstatus': 'T', 'name': 'x' * 100} for i in range(11869)]}
        response.__enter__.return_value.read.return_value = json.dumps(payload).encode()
        opener = MagicMock()
        opener.open.return_value = response
        with patch.dict('os.environ', {'TEST_BACULA_AUTH': 'Basic dTpw'}), patch.object(
                m.urllib.request, 'build_opener', return_value=opener) as build:
            result = self.call('/api/connections/{key}/collect', 'b')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['inventory']['jobs_count'], 11869)
        self.assertTrue(any(isinstance(h, m.urllib.request.ProxyHandler) and h.proxies == {}
                            for h in build.call_args.args))
        self.assertIn(m.NoRedirect, build.call_args.args)
        self.assertEqual(opener.open.call_args.args[0].get_method(), 'GET')
        self.assertNotIn('dTpw', json.dumps(result))
