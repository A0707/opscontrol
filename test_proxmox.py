import json
import ssl
import unittest
import urllib.error
from management import collection_error
from proxmox_inventory import inventory, cluster_info


class ProxmoxTests(unittest.TestCase):
    def test_nodes_guests_and_migration(self):
        data=[{'type':'qemu','node':'pve02','vmid':101,'name':'web','status':'running','cpu':.25,'maxmem':4096},
              {'type':'node','node':'pve01','status':'online','cpu':.1},
              {'type':'node','node':'pve02','status':'online'},
              {'type':'lxc','node':'pve01','vmid':102,'name':'dns','status':'stopped'},
              {'type':'storage','node':'pve01','password':'SECRET'}]  # pragma: allowlist secret -- verifies redaction
        result=inventory({'data':data})
        self.assertEqual(result['nodes_count'],2)
        self.assertEqual(result['nodes'][0]['guests'][0]['vmid'],102)
        self.assertEqual(result['nodes'][1]['guests'][0]['cpu_pct'],25)
        self.assertIsNone(result['nodes'][1]['guests'][0]['memory_bytes'])
        self.assertEqual(result['counts']['qemu'],1)
        self.assertNotIn('SECRET',json.dumps(result))
        data[0]['node']='pve01'
        self.assertEqual(len(inventory({'data':data})['nodes'][0]['guests']),2)

    def test_missing_node_and_permissions(self):
        result=inventory({'data':[{'type':'qemu','node':'pve01','vmid':1,'status':'running'}]})
        self.assertFalse(result['nodes'][0]['reported'])
        self.assertEqual(result['nodes'][0]['status'],'unknown')
        self.assertTrue(inventory({'data':[]})['empty'])
        with self.assertRaises(ValueError):inventory({'data':{'version':'9'}})
        self.assertEqual(cluster_info({'data':[{'type':'cluster','name':'OVH','quorate':0}] }),{'name':'OVH','quorate':False})
        self.assertIsNone(cluster_info({'data':[{'type':'node','name':'pve01'}]}))

    def test_error_types_hide_credentials(self):
        error=ssl.SSLCertVerificationError('SECRET')
        error.verify_code=20
        result=collection_error(urllib.error.URLError(error))
        self.assertEqual(result['error_kind'],'tls_certificate')
        self.assertNotIn('SECRET',json.dumps(result))
        for code in (401,403,404):
            result=collection_error(urllib.error.HTTPError('https://example.test',code,'SECRET',{},None))
            self.assertEqual(result['http_status'],code)
            self.assertNotIn('SECRET',json.dumps(result))
        self.assertEqual(collection_error(TimeoutError())['error_kind'],'timeout')
        self.assertEqual(collection_error(FileNotFoundError())['error_kind'],'ca_file')


if __name__=='__main__':unittest.main()
