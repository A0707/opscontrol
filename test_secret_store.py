"""Coffre DPAPI : precedence, absence de fuite, robustesse."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import secret_store


class CoffreTests(unittest.TestCase):
    def test_variable_existante_jamais_ecrasee(self):
        """Le lanceur et les surcharges manuelles priment sur le coffre."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'OPSCONTROL_TEST_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.dict(os.environ, {'OPSCONTROL_TEST_AUTH': 'valeur-du-lanceur'}):
                charges = secret_store.charger(dossier)
                self.assertEqual(charges, [])
                self.assertEqual(os.environ['OPSCONTROL_TEST_AUTH'], 'valeur-du-lanceur')

    def test_coffre_absent_n_est_pas_une_erreur(self):
        """Un poste sans coffre doit demarrer normalement."""
        self.assertEqual(secret_store.charger(Path(tempfile.gettempdir()) / 'coffre-inexistant-xyz'), [])

    def test_blob_illisible_ignore_sans_lever(self):
        """Un fichier corrompu ne doit pas empecher le demarrage."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'OPSCONTROL_CASSE_AUTH.dpapi').write_text('pas du hexadecimal', encoding='utf-8')
            (Path(dossier) / 'OPSCONTROL_VIDE_AUTH.dpapi').write_text('', encoding='utf-8')
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop('OPSCONTROL_CASSE_AUTH', None)
                os.environ.pop('OPSCONTROL_VIDE_AUTH', None)
                self.assertEqual(secret_store.charger(dossier), [])

    def test_ne_renvoie_que_des_noms(self):
        """Le retour alimente des journaux : aucune valeur ne doit en sortir."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'OPSCONTROL_X_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.object(secret_store, '_dechiffrer', return_value='secret-tres-confidentiel'):
                os.environ.pop('OPSCONTROL_X_AUTH', None)
                try:
                    charges = secret_store.charger(dossier)
                    self.assertEqual(charges, ['OPSCONTROL_X_AUTH'])
                    self.assertNotIn('secret-tres-confidentiel', ' '.join(charges))
                finally:
                    os.environ.pop('OPSCONTROL_X_AUTH', None)

    def test_valeur_vide_non_posee(self):
        """Une entree vide ne doit pas masquer l'absence reelle de secret."""
        with tempfile.TemporaryDirectory() as dossier:
            (Path(dossier) / 'OPSCONTROL_Y_AUTH.dpapi').write_text('00ff', encoding='utf-8')
            with patch.object(secret_store, '_dechiffrer', return_value='   '):
                os.environ.pop('OPSCONTROL_Y_AUTH', None)
                self.assertEqual(secret_store.charger(dossier), [])
                self.assertNotIn('OPSCONTROL_Y_AUTH', os.environ)


if __name__ == '__main__':
    unittest.main()
