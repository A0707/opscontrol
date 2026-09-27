"""Flux SSE : signale les changements sans jamais declencher de collecte."""
import asyncio
import json
import threading
import unittest
from types import SimpleNamespace

from fastapi import FastAPI

import realtime


class FluxTests(unittest.TestCase):
    def setUp(self):
        self.context = SimpleNamespace(
            lock=threading.Lock(), net_lock=threading.Lock(),
            job={'running': False, 'completed': 0, 'total': 0, 'error': None},
            net_job={'running': False, 'completed': 0, 'total': 0},
            monitor={'interval': 0, 'next_at': None},
            api_sync_state=lambda: {'running': False, 'completed': 0, 'total': 0},
        )
        app = FastAPI()
        realtime.WATCH_SECONDS = 0.01
        realtime.install(app, self.context)
        self.endpoint = next(r.endpoint for r in app.routes if getattr(r, 'path', '') == '/api/events')

    def lire(self, messages, deconnecte_apres=6):
        """Consomme le flux jusqu'a `deconnecte_apres` fragments."""
        recus = []
        etat = {'n': 0}

        async def is_disconnected():
            etat['n'] += 1
            return etat['n'] > deconnecte_apres

        requete = SimpleNamespace(is_disconnected=is_disconnected)

        async def run():
            reponse = await self.endpoint(requete)
            async for fragment in reponse.body_iterator:
                recus.append(fragment)
                if messages and len(recus) in messages:
                    messages[len(recus)]()
        asyncio.run(run())
        return recus

    def test_premier_message_immediat(self):
        """Le client doit savoir que le canal est ouvert sans attendre un changement."""
        recus = self.lire({}, deconnecte_apres=1)
        self.assertTrue(recus[0].startswith('event: ready'))

    def test_un_changement_produit_un_evenement(self):
        def demarre_collecte():
            self.context.job.update(running=True, completed=3, total=84)
        # Declenche apres le message `ready` : c'est le seul fragment garanti,
        # puisqu'un etat stable n'en produit aucun autre avant le maintien.
        recus = self.lire({1: demarre_collecte}, deconnecte_apres=5)
        etats = [m for m in recus if m.startswith('event: state')]
        self.assertTrue(etats, 'aucun evenement state emis apres le changement')
        charge = json.loads(etats[-1].split('data: ', 1)[1].strip())
        self.assertEqual(charge['ssh']['completed'], 3)
        self.assertEqual(charge['ssh']['total'], 84)

    def test_aucun_evenement_sans_changement(self):
        """Un etat stable ne doit produire que des commentaires de maintien."""
        recus = self.lire({}, deconnecte_apres=5)
        etats = [m for m in recus if m.startswith('event: state')]
        self.assertEqual(etats, [], 'le flux emet alors que rien n a change')

    def test_direct_source_commit_notifies_without_job_change(self):
        revision = [0]
        self.context.api_revision = lambda: revision[0]
        messages = self.lire({1: lambda: revision.__setitem__(0, 1)})
        updates = [m for m in messages if m.startswith('event: state')]
        payload = json.loads(updates[-1].split('data: ', 1)[1])
        self.assertEqual(payload['api_revision'], 1)
        self.assertFalse(payload['ssh']['running'])

    def test_batch_completion_notifies_the_dashboard(self):
        batch = {'running': True, 'completed': 0, 'total': 1}
        self.context.batch_job = lambda: dict(batch)
        messages = self.lire({1: lambda: batch.update(running=False, completed=1)})
        updates = [m for m in messages if m.startswith('event: state')]
        payload = json.loads(updates[-1].split('data: ', 1)[1])
        self.assertEqual(payload['batch']['completed'], 1)
        self.assertFalse(payload['batch']['running'])

    def test_extension_absente_ne_coupe_pas_le_flux(self):
        """api_sync_state indisponible : on signale l'inconnue, on ne plante pas."""
        def casse():
            raise RuntimeError('extension non installee')
        self.context.api_sync_state = casse
        recus = self.lire({}, deconnecte_apres=2)
        self.assertTrue(recus[0].startswith('event: ready'))

    def test_le_flux_ne_declenche_aucune_collecte(self):
        """Garde-fou : observer l'etat ne doit jamais lancer de SSH ni d'API."""
        appels = []
        self.context.launch = lambda *a, **k: appels.append('ssh')
        self.context.launch_network = lambda *a, **k: appels.append('network')
        self.context.launch_api_sync = lambda *a, **k: appels.append('api')
        self.lire({}, deconnecte_apres=5)
        self.assertEqual(appels, [])


if __name__ == '__main__':
    unittest.main()
