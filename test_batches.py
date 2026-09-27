import json
import sqlite3
import unittest
from contextlib import closing, contextmanager
from types import SimpleNamespace
from unittest.mock import patch
from datetime import datetime,timezone
import batch_remote as probe
import batch_monitor as monitor
import ssh


class BatchProbeTests(unittest.TestCase):
    def test_cron_timezone_system_owner_and_secret_omission(self):
        rows=probe.cron_rows('CRON_TZ=Africa/Casablanca\nTOKEN=do-not-expose\n15 2 * * 1-5 app /opt/nightly --password=secret-value\n# disabled\n@reboot root /bin/sh -c "echo secret-command"','/etc/crontab','root',system=True)
        self.assertEqual(len(rows),2)
        self.assertEqual(rows[0]['schedule'],'15 2 * * 1-5')
        self.assertEqual(rows[0]['timezone'],'Africa/Casablanca')
        self.assertEqual(rows[0]['owner'],'app')
        self.assertEqual(rows[0]['name'],'nightly')
        self.assertEqual(rows[0]['state'],'scheduled')
        self.assertIsNone(rows[0]['last_run'])
        for secret in ('secret-value','secret-command','do-not-expose'):
            self.assertNotIn(secret,json.dumps(rows))

    def test_timer_inactive_success_requires_execution_evidence(self):
        timer={'Id':'backup.timer','Unit':'backup.service','ActiveState':'active','LastTriggerUSec':'Thu 02:00','NextElapseUSecRealtime':'Fri 02:00'}
        service={'Id':'backup.service','ActiveState':'inactive','Result':'success','ExecMainExitTimestamp':''}
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'unknown')
        service['ExecMainExitTimestamp']='Thu 02:05'
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'success')
        service['Result']='exit-code'
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'failed')
        service.update(ActiveState='active',SubState='running',Result='success')
        self.assertEqual(probe.timer_rows([timer],[service],'UTC')[0]['state'],'running')

    def test_collect_failure_and_payload_are_separate(self):
        host={'key':'a','ip':'192.0.2.1'}
        cfg=ssh.SSHConfig(user='test',key_path='unused')
        with patch.object(ssh,'run_operation',return_value=ssh.RunResult(False,None,'','private-error',1,'host_key')) as run:
            r=monitor.collect_host(host,cfg)
            self.assertEqual(r['status'],'unknown');self.assertIn('Clé SSH',r['limitations'][0])
            self.assertEqual(run.call_args.args[1],'batch_inventory')
            self.assertNotIn('private-error',json.dumps(r))
        with patch.object(ssh,'run_operation',return_value=ssh.RunResult(True,0,'{"jobs": [], "limitations": ["partial"]}','',1,'')):
            self.assertEqual(monitor.collect_host(host,cfg)['limitations'],['partial'])

    def test_stale_snapshot_retained_and_bacula_latest_only(self):
        now=datetime.now(timezone.utc).isoformat()
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE batch_states(key TEXT,ip TEXT,payload TEXT)')
            db.execute('INSERT INTO batch_states VALUES(?,?,?)',('a','192.0.2.1',json.dumps({'status':'unknown','collected_at':now,'last_observation':{'jobs':[{'id':'x','state':'failed'}],'collected_at':'old'}})))
            @contextmanager
            def connect(): yield db
            context=SimpleNamespace(connect=connect,HOSTS=[{'key':'a','name':'web','ip':'192.0.2.1'}],api_connections=lambda:[{'key':'b','name':'Director','provider':'Bacula','last_result':{'status':'observed','collected_at':now,'inventory':{'jobs':[{'jobid':1,'name':'backup','client':'web-fd','severity':'critical'},{'jobid':2,'name':'backup','client':'web-fd','severity':'ok'}]}}}])
            r=monitor.snapshot(context)
            self.assertEqual(len(r['jobs']),2)
            self.assertFalse(r['jobs'][0]['fresh'])
            self.assertEqual(r['jobs'][1]['state'],'success')
            self.assertEqual(r['jobs'][1]['host_key'],'a')
            self.assertEqual(r['fresh_failures'],0)

    def test_remote_program_never_executes_cron_content(self):
        self.assertNotIn('shell=True',monitor.COMMAND)
        self.assertNotIn('sudo ',monitor.COMMAND)
        self.assertNotIn('systemctl start',monitor.COMMAND)
