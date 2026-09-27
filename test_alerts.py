import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import alert_center
import alert_policy as policy
import shares_view
import storage_probe

NOW = datetime.now(timezone.utc).isoformat()
OLD = '2026-01-01T00:00:00+00:00'
GIB = policy.GIB


def host(key, ip, stale=False, shares=(), exports=None, findings=(), status='critical', at=NOW, fs=(), **extra):
    return {'key': key, 'name': key, 'ip': ip, 'stale': stale, 'status': status, 'collected_at': at,
            'issues': [], 'findings': list(findings),
            'storage': {'remote_shares': list(shares), 'exports': exports, 'filesystems': list(fs)}, **extra}


def volume(mount, use, total_gib=20, free_gib=None):
    total = total_gib * GIB
    free = free_gib * GIB if free_gib is not None else total * (100 - use) // 100
    return {'mount': mount, 'use_pct': use, 'total_kb': total, 'available_kb': free, 'used_kb': total - free}


def mount(source, status='accessible', use=50, access='read-write', path='/mnt/x'):
    return {'mount': path, 'source': source, 'fstype': 'nfs4', 'status': status, 'access': access, 'use_pct': use}


class PolicyTests(unittest.TestCase):
    def test_disk_percentage_grid(self):
        self.assertEqual(policy.disk(96, 20 * GIB, 0.8 * 20 * GIB)[0], 'critical')
        self.assertEqual(policy.disk(91, 20 * GIB, 1.8 * GIB)[0], 'warning')
        self.assertEqual(policy.disk(82, 20 * GIB, 3.6 * GIB)[0], 'preventive')
        self.assertEqual(policy.disk(70, 20 * GIB, 6 * GIB)[0], None)

    def test_large_free_space_lowers_urgency_but_never_hides(self):
        niveau, raisons = policy.disk(97, 10000 * GIB, 300 * GIB)
        self.assertEqual(niveau, 'warning')
        self.assertIn('urgence réduite', raisons[-1])
        self.assertEqual(policy.disk(83, 10000 * GIB, 1700 * GIB)[0], 'preventive')

    def test_under_one_gib_is_critical_whatever_the_percentage(self):
        self.assertEqual(policy.disk(85, 5 * GIB, 0.5 * GIB)[0], 'critical')

    def test_trend_projects_saturation(self):
        debut = datetime(2026, 9, 1, tzinfo=timezone.utc)
        total = 100 * GIB
        # +2 Gio par jour, 20 Gio restants : saturation dans 10 jours → préventif.
        points = [((debut + timedelta(days=d)).isoformat(), (70 + 2 * d) * GIB, total) for d in range(6)]
        jours = policy.days_to_full(points)
        self.assertAlmostEqual(jours, 10, places=3)
        self.assertEqual(policy.disk(80, total, 20 * GIB, jours)[0], 'preventive')
        self.assertEqual(policy.disk(60, total, 40 * GIB, 5)[0], 'warning')

    def test_trend_refuses_short_or_resized_or_shrinking_history(self):
        t = datetime(2026, 9, 1, tzinfo=timezone.utc)
        court = [((t + timedelta(hours=h)).isoformat(), 10 + h, 100) for h in range(3)]
        self.assertIsNone(policy.days_to_full(court))
        agrandi = [((t + timedelta(days=d)).isoformat(), 10 + d, 100 + d) for d in range(4)]
        self.assertIsNone(policy.days_to_full(agrandi))
        decroit = [((t + timedelta(days=d)).isoformat(), 50 - d, 100) for d in range(4)]
        self.assertIsNone(policy.days_to_full(decroit))

    def test_services_graded_by_role(self):
        self.assertEqual(policy.service('tomcat-charika.service')[0], 'critical')
        self.assertEqual(policy.service('postgresql@16-main.service')[0], 'critical')
        self.assertEqual(policy.service('zabbix-agent.service')[0], 'warning')
        self.assertEqual(policy.service('logrotate.service')[0], 'preventive')
        self.assertEqual(policy.service('inconnu.service')[0], 'warning')
        self.assertEqual(policy.service('logrotate.service', {'logrotate'})[0], 'critical')

    def test_cpu_requires_sustained_load(self):
        self.assertEqual(policy.cpu([99])[0], None)
        self.assertEqual(policy.cpu([95, 92, 97, 10])[0], 'warning')

    def test_zabbix_requalification(self):
        cas = {
            'Test Disaster Trigger for pagerduty': 'info',
            'Proxmox: VM [pve/VM 9000 (qemu/9000)]: Not running': 'info',
            'MS Nantissement DOWN': 'critical',
            'PostgreSQL service not running on db02': 'critical',
            'Zabbix agent on git01 is unreachable for 5 minutes': 'warning',
            'Cert: SSL certificate expires soon (less than 30 days)': 'preventive',
            'Free disk space is less than 20% on volume /': 'disk',
        }
        for description, attendu in cas.items():
            self.assertEqual(policy.zabbix(description, 'critical')[0], attendu, description)
        # Trigger inconnu : jamais repris tel quel, abaissé d'un cran et signalé.
        niveau, raison, couvert = policy.zabbix('Quelque chose d’inédit', 'critical')
        self.assertEqual((niveau, couvert), ('warning', False))


class ExportsProbeTests(unittest.TestCase):
    def test_exports_use_local_filesystem_without_extra_command(self):
        out = ('##DF\nFilesystem Type 1024-blocks Used Available Capacity Mounted on\n'
               '/dev/sda1 ext4 100 50 50 50% /\n/dev/sdb1 xfs 100 97 3 97% /var/nfs_share\n'
               '##EXPORTS\nNFS|/var/nfs_share/cb|198.51.100.0/24(ro)\nSMB|/srv/commun|commun\n')
        exports = storage_probe.parse(out)['exports']
        self.assertEqual(exports[0]['use_pct'], 97)
        self.assertEqual(exports[0]['filesystem'], '/var/nfs_share')
        self.assertEqual(exports[1], {'protocol': 'SMB', 'path': '/srv/commun', 'use_pct': 50,
                                      'filesystem': '/', 'name': 'commun'})
        bloc = storage_probe.COMMAND.split('##EXPORTS')[1].split('##SSHFAIL')[0]
        self.assertNotIn('df ', bloc)

    def test_older_probe_means_not_collected_not_empty(self):
        self.assertIsNone(storage_probe.parse('##DF\n')['exports'])
        self.assertEqual(storage_probe.parse('##EXPORTS\n')['exports'], [])


class SharesViewTests(unittest.TestCase):
    def test_one_share_many_clients_is_one_line(self):
        rows = [host('c%d' % i, '198.51.100.%d' % i, shares=[mount('198.51.100.50:/data', use=70)]) for i in range(9)]
        rows.append(host('nfs', '198.51.100.50'))
        view = shares_view.build(rows)
        self.assertEqual(len(view['shares']), 1)
        share = view['shares'][0]
        self.assertEqual((share['clients_count'], share['status'], share['server_host']['key']), (9, 'ok', 'nfs'))

    def test_stale_client_makes_share_critical_and_is_counted(self):
        rows = [host('a', '1.1.1.1', shares=[mount('srv:/d')]),
                host('b', '1.1.1.2', shares=[mount('srv:/d', status='stale', use=None)])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['status'], share['stale_clients']), ('critical', 1))
        self.assertIn('Injoignable depuis 1 client(s) sur 2', share['reasons'])

    def test_server_measure_wins_and_policy_grid(self):
        rows = [host('c', '1.1.1.1', shares=[mount('198.51.100.5:/d', use=70)]),
                host('srv', '198.51.100.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': 96, 'clients': '*'}])]
        share = shares_view.build(rows)['shares'][0]
        self.assertEqual((share['use_pct'], share['status']), (96, 'critical'))
        rows[1]['storage']['exports'][0]['use_pct'] = 92
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'warning')
        rows[1]['storage']['exports'][0]['use_pct'] = 82
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'preventive')

    def test_unmeasured_is_unknown_never_ok(self):
        rows = [host('srv', '198.51.100.5', exports=[{'protocol': 'NFS', 'path': '/d', 'use_pct': None, 'clients': '*'}])]
        self.assertEqual(shares_view.build(rows)['shares'][0]['status'], 'unknown')

    def test_old_measurements_are_not_fresh(self):
        rows = [host('c', '1.1.1.1', stale=True, at=OLD, shares=[mount('s:/d', use=99)])]
        self.assertFalse(shares_view.build(rows)['shares'][0]['fresh'])


def context(rows, connections=()):
    return SimpleNamespace(rows=lambda: rows, api_connections=lambda: list(connections))


def source(provider, inventory, at=NOW, **extra):
    return {'key': provider.lower(), 'name': provider, 'provider': provider,
            'last_result': {'status': 'observed', 'collected_at': at, 'inventory': inventory, **extra}}


def ids(result):
    return {a['id']: a['severity'] for a in result['alerts']}


class AlertCenterTests(unittest.TestCase):
    def test_disks_graded_from_raw_measure_not_from_audit_finding(self):
        rows = [host('a', '1.1.1.1', fs=[volume('/', 97)],
                     findings=[{'id': 'disk_max', 'title': 'Disques : 97 %', 'severity': 'critical'}]),
                host('b', '1.1.1.2', fs=[volume('/data', 97, total_gib=10000, free_gib=300)])]
        alertes = {a['id']: a for a in alert_center.build(context(rows))['alerts']}
        self.assertEqual(set(alertes), {'SSH:disk:critical', 'SSH:disk:warning'})
        self.assertIn('/data : 97 % occupé', alertes['SSH:disk:warning']['targets'][0]['detail'])

    def test_same_service_on_many_hosts_is_one_alert_graded_by_role(self):
        f = {'id': 'service:tomcat.service', 'title': 'Service tomcat.service : failed', 'severity': 'critical'}
        g = {'id': 'service:logrotate.service', 'title': 'Service logrotate.service : failed', 'severity': 'critical'}
        result = alert_center.build(context([host('a', '1.1.1.1', findings=[f, g]), host('b', '1.1.1.2', findings=[f])]))
        alertes = {a['id']: a for a in result['alerts']}
        self.assertEqual(alertes['SSH:service:tomcat.service:critical']['count'], 2)
        self.assertEqual(alertes['SSH:service:logrotate.service:preventive']['source_severity'], 'Audit : critical')

    def test_stale_evidence_is_shown_but_not_confirmed(self):
        result = alert_center.build(context([host('a', '1.1.1.1', stale=True, at=OLD, fs=[volume('/', 99)])]))
        self.assertEqual((result['counts']['critical'], result['counts']['critical_stale']), (0, 1))

    def test_stale_mount_counted_once_per_share_not_per_client(self):
        f = {'id': 'mount:/mnt/x', 'title': 'Partage distant injoignable', 'severity': 'critical'}
        rows = [host('a', '1.1.1.1', findings=[f], shares=[mount('srv:/d', status='stale', use=None)]),
                host('b', '1.1.1.2', findings=[f], shares=[mount('srv:/d', status='stale', use=None)])]
        alerts = alert_center.build(context(rows))['alerts']
        self.assertEqual([a['source'] for a in alerts], ['Partages'])

    def test_zabbix_noise_becomes_info_in_one_group(self):
        problems = [{'description': 'Proxmox: VM [pve/VM %d (qemu/%d)]: Not running' % (i, i), 'severity': 'warning',
                     'severity_label': 'Moyenne', 'hosts': ['pve']} for i in range(42)]
        result = alert_center.build(context([], [source('Zabbix', {'problems': problems})]))
        self.assertEqual(len(result['alerts']), 1)
        alerte = result['alerts'][0]
        self.assertEqual((alerte['severity'], alerte['count'], alerte['source_severity']), ('info', 42, 'Zabbix : Moyenne'))

    def test_zabbix_disk_trigger_requalified_by_ssh_measure(self):
        rows = [host('big', '1.1.1.1', fs=[volume('/all_backup10', 83, total_gib=10000, free_gib=1700)]),
                host('root', '1.1.1.2', fs=[volume('/', 96)])]
        problems = [{'description': 'Free disk space is less than 20% on volume /all_backup10', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['big']},
                    {'description': 'Free disk space is less than 20% on volume /', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['root']},
                    {'description': 'Free disk space is less than 20% on volume /var', 'severity': 'warning',
                     'severity_label': 'Avertissement', 'hosts': ['inconnu']}]
        zabbix = {k: v for k, v in ids(alert_center.build(context(rows, [source('Zabbix', {'problems': problems})]))).items()
                  if k.startswith('Zabbix')}
        self.assertEqual(zabbix, {
            'Zabbix:Free disk space is less than 20% on volume /all_backup10:preventive': 'preventive',
            'Zabbix:Free disk space is less than 20% on volume /:critical': 'critical',
            'Zabbix:Free disk space is less than 20% on volume /var:preventive': 'preventive'})

    def test_bacula_reads_last_run_not_history(self):
        jobs = [{'jobid': 1, 'name': 'Backup-A', 'severity': 'critical', 'status_label': 'Erreur', 'client': 'a-fd'},
                {'jobid': 2, 'name': 'Backup-A', 'severity': 'ok', 'status_label': 'OK', 'client': 'a-fd'},
                {'jobid': 3, 'name': 'Backup-B', 'severity': 'critical', 'status_label': 'Erreur fatale', 'client': 'b-fd'}]
        result = alert_center.build(context([host('b', '1.1.1.2')], [source('Bacula', {'jobs': jobs})]))
        self.assertEqual([a['id'] for a in result['alerts']], ['Bacula:job:Backup-B:critical'])
        self.assertEqual(result['alerts'][0]['targets'][0]['host_key'], 'b')

    def test_failed_source_is_an_alert_itself(self):
        conn = {'key': 'z', 'name': 'ZABBIX', 'provider': 'Zabbix',
                'last_result': {'status': 'unknown', 'error': 'TLS', 'collected_at': NOW}}
        result = alert_center.build(context([], [conn]))
        self.assertEqual(result['alerts'][0]['id'], 'Zabbix:collection:warning')
        self.assertFalse(result['sources'][0]['fresh'])

    def test_elastic_yellow_and_proxmox_memory(self):
        conns = [source('Elasticsearch', {}, indicators={'cluster_status': 'yellow', 'unassigned_shards': 41}),
                 source('Proxmox', {'nodes': [{'name': 'pve03', 'status': 'online', 'memory_bytes': 92, 'memory_total_bytes': 100}]})]
        self.assertEqual(ids(alert_center.build(context([], conns))),
                         {'Elastic:cluster:warning': 'warning', 'Proxmox:node-memory:warning': 'warning'})

    def test_uptime_and_memory_are_preventive_signals(self):
        rows = [host('a', '1.1.1.1', uptime='up 665 days,  6:52', ram=87.0)]
        self.assertEqual(ids(alert_center.build(context(rows))),
                         {'SSH:uptime:preventive': 'preventive', 'SSH:memory:preventive': 'preventive'})

    def test_policy_is_published_with_the_alerts(self):
        result = alert_center.build(context([]))
        self.assertEqual([l['key'] for l in result['levels']], ['critical', 'warning', 'preventive', 'info'])
        self.assertTrue(any(r['domain'] == 'Zabbix' for r in result['policy']))


if __name__ == '__main__':
    unittest.main()
