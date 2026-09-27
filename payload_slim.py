"""Allègement des listes de serveurs (/api/overview, /api/sync).

La réponse `/api/overview` est appelée périodiquement. La majorité de son poids
peut venir de données détaillées que seule la fiche d'un serveur affiche, comme
les contrôles, services, volumes et systèmes de fichiers.

La fiche serveur (/api/hosts/{clé}) est construite à part, depuis rows() : elle
garde TOUT. Ici, on ne retire que ce qu'aucune vue de liste ne lit (vérifié dans
web/*.js), et on le dit dans la réponse (`detail_trimmed`).

`all_services` : la liste du parc n'en utilise que les unités en échec (colonne
« Services ») ; seules les unités non actives restent, avec le total. La page
Services charge la liste complète par /api/services.
"""
from __future__ import annotations

# Lus uniquement dans la fiche d'un serveur (app.js detailView, storage.js).
DETAIL_ONLY = ('checks', 'storage', 'filesystems', 'attempts')
ATTEMPT_KEEP = ('collected_at', 'issues', 'status')


def slim(host):
    allege = {k: v for k, v in host.items() if k not in DETAIL_ONLY}
    services = host.get('all_services')
    if isinstance(services, list):
        allege['all_services'] = [s for s in services if isinstance(s, dict) and s.get('status') != 'active']
        allege['services_total'] = len(services)
    tentative = host.get('last_attempt')
    if isinstance(tentative, dict):
        allege['last_attempt'] = {k: tentative[k] for k in ATTEMPT_KEEP if k in tentative}
    allege['detail_trimmed'] = True
    return allege


def services(rows):
    """{clé serveur: toutes les unités observées} pour la page Services."""
    return {h['key']: h.get('all_services') or h.get('service_states') or [] for h in rows}
