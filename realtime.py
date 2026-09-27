"""Server-Sent Events : pousse les changements d'état vers l'interface.

Pourquoi SSE et pas WebSocket : le flux est strictement descendant (le serveur
notifie, le client ne publie rien), SSE passe les proxys HTTP sans négociation,
se reconnecte tout seul, et ne demande aucune dépendance supplémentaire. Un
WebSocket n'apporterait ici qu'un canal montant dont personne n'a besoin.

Pourquoi pas Celery/Redis : la collecte tourne déjà dans des threads de ce
processus (app.scheduler + ThreadPoolExecutor). Pour un parc géré par un seul
seul opérateur, ajouter un courtier de messages et un worker séparé ajouterait
deux services à exploiter, deux sources de panne et un déploiement, sans rien
résoudre. Le jour où la collecte devra survivre au redémarrage de l'API ou
s'étaler sur plusieurs machines, la question se reposera — pas avant.

Ce module ne collecte rien : il observe l'état déjà produit et signale qu'il a
changé. L'interface décide ensuite quoi recharger.
"""
import asyncio
import json

from fastapi import Request
from fastapi.responses import StreamingResponse

# Cadence d'observation de l'état en mémoire. Ce n'est PAS une fréquence de
# collecte : aucune requête SSH ni API n'est déclenchée ici.
WATCH_SECONDS = 1.0
# Commentaire de maintien : traverse les proxys qui coupent une connexion
# inactive, et permet au client de détecter une rupture.
KEEPALIVE_SECONDS = 15.0


def install(app, context):
    """Enregistre /api/events. `context` est le module applicatif (app.py)."""

    def snapshot():
        """Empreinte compacte de ce qui justifie un rafraîchissement d'écran.

        On ne sérialise pas l'état complet : il peut peser plusieurs centaines de
        Ko, et le recalculer chaque seconde coûterait plus cher que
        le sondage qu'on cherche à remplacer. On compare uniquement les
        compteurs de progression et l'horodatage des collectes.
        """
        with context.lock:
            jobs = {'ssh': dict(context.job), 'monitoring': dict(context.monitor)}
        with context.net_lock:
            jobs['network'] = dict(context.net_job)
        if hasattr(context, 'batch_job'):
            jobs['batch'] = context.batch_job()
        try:
            jobs['api'] = context.api_sync_state()
        except Exception:
            # Une extension absente ou en cours d'initialisation ne doit pas
            # interrompre le flux : on signale simplement l'inconnue.
            jobs['api'] = None
        digest = {
            name: None if job is None else {k: job.get(k) for k in ('running', 'completed', 'total', 'error', 'next_at')}
            for name, job in jobs.items()
        }
        if hasattr(context, 'api_revision'):
            digest['api_revision'] = context.api_revision()
        return json.dumps(digest, sort_keys=True, default=str)

    @app.get('/api/events')
    async def events(request: Request):
        """Flux SSE. Émet `state` à chaque changement, `ping` sinon."""

        async def stream():
            # On part de l'état courant, et non de None : sinon chaque connexion
            # — donc chaque reconnexion après coupure réseau — émettrait un
            # « changement » qui n'en est pas un, et provoquerait un rechargement
            # complet inutile côté client.
            previous = snapshot()
            idle = 0.0
            # Voie rapide : on POUSSE l'état lui-même (quelques Ko), pas un simple
            # signal de changement. Le client n'a rien à recharger : une panne
            # d'un serveur critique arrive à l'écran dans la seconde qui suit la sonde.
            tier0 = getattr(context, 'tier0_snapshot', None)
            tier0_seen = None
            # Premier message immédiat : le client sait que le canal est ouvert
            # et n'attend pas le premier changement pour afficher quelque chose.
            yield 'event: ready\ndata: {}\n\n'
            while True:
                if await request.is_disconnected():
                    return
                if tier0 is not None:
                    etat = tier0()
                    marque = (etat.get('revision'), etat.get('last_probe_at'))
                    if marque != tier0_seen:
                        tier0_seen = marque
                        idle = 0.0
                        yield 'event: tier0\ndata: ' + json.dumps(etat, default=str) + '\n\n'
                current = snapshot()
                if current != previous:
                    previous = current
                    idle = 0.0
                    yield 'event: state\ndata: ' + current + '\n\n'
                else:
                    idle += WATCH_SECONDS
                    if idle >= KEEPALIVE_SECONDS:
                        idle = 0.0
                        yield ': ping\n\n'
                await asyncio.sleep(WATCH_SECONDS)

        return StreamingResponse(stream(), media_type='text/event-stream', headers={
            'Cache-Control': 'no-store',
            # Neutralise la mise en tampon d'un reverse-proxy nginx éventuel :
            # sans cela le flux arrive par paquets et le temps réel disparaît.
            'X-Accel-Buffering': 'no',
        })
