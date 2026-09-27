import re
import unittest
from pathlib import Path

import payload_slim

HOTE = {'key': 'a', 'name': 'a', 'status': 'critical', 'stale': False, 'findings': [{'id': 'disk_max'}],
        'checks': [{'id': 'cpu', 'command': 'x' * 500}], 'storage': {'filesystems': []}, 'filesystems': [{'mount': '/'}],
        'attempts': [{'rc': 0}], 'documented': {'backup': {'paths': '/var'}}, 'proxmox_matches': [],
        'all_services': [{'name': 'ssh', 'status': 'active'}, {'name': 'tomcat', 'status': 'failed'},
                         {'name': 'kdump', 'status': 'inactive'}],
        'last_attempt': {'collected_at': 't', 'issues': ['timeout'], 'checks': [{'x': 1}], 'status': 'unreachable'}}


class SlimTests(unittest.TestCase):
    def test_detail_only_fields_removed_and_flagged(self):
        s = payload_slim.slim(HOTE)
        for champ in payload_slim.DETAIL_ONLY:
            self.assertNotIn(champ, s)
        self.assertTrue(s['detail_trimmed'])
        # Ce que les listes lisent reste : constats, documentation, rapprochement Proxmox.
        self.assertEqual((s['findings'], s['documented'], s['proxmox_matches']),
                         (HOTE['findings'], HOTE['documented'], []))

    def test_failed_services_kept_for_the_fleet_table(self):
        s = payload_slim.slim(HOTE)
        self.assertEqual([x['name'] for x in s['all_services']], ['tomcat', 'kdump'])
        self.assertEqual(s['services_total'], 3)
        self.assertEqual(sum(x['status'] == 'failed' for x in s['all_services']), 1)  # colonne « Services »

    def test_last_attempt_keeps_what_lists_show(self):
        self.assertEqual(payload_slim.slim(HOTE)['last_attempt'],
                         {'collected_at': 't', 'issues': ['timeout'], 'status': 'unreachable'})

    def test_original_row_untouched_for_the_detail_endpoint(self):
        payload_slim.slim(HOTE)
        self.assertIn('checks', HOTE)
        self.assertEqual(len(HOTE['all_services']), 3)

    def test_services_endpoint_returns_everything(self):
        self.assertEqual(len(payload_slim.services([HOTE])['a']), 3)

    def test_removed_fields_are_not_read_by_list_views(self):
        """Garde-fou : un champ retiré ne doit être lu que dans la fiche serveur.

        storage.js et la fonction checks()/l'onglet audit d'app.js sont des vues
        de fiche (h = hostDetail). Si une vue de LISTE se met à lire ces champs,
        ce test échoue : il faudra les rendre à la liste ou passer par l'API.
        """
        web = Path(__file__).parent / 'web'
        autorises = {'storage.js'}
        for fichier in web.glob('*.js'):
            if fichier.name in autorises:
                continue
            texte = fichier.read_text(encoding='utf-8')
            for champ in ('storage', 'filesystems'):
                self.assertIsNone(re.search(r'\bh\.' + champ + r'\b', texte), f'{fichier.name} lit h.{champ}')


if __name__ == '__main__':
    unittest.main()
