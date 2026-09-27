"""Keep SSH observations separate from failed attempts and configuration changes."""
from copy import deepcopy
from datetime import datetime, timezone


def measured(result):
    return bool(result and result.get('collected_at') and
                result.get('coverage', {}).get('measured', 0) > 0)


def retain_attempt(result, previous=None):
    """Caller must supply previous state only for the same inventory key AND IP."""
    saved = deepcopy(result)
    saved.pop('last_observation', None)
    if not measured(result) and previous:
        observation = previous if measured(previous) else previous.get('last_observation')
        if measured(observation):
            saved['last_observation'] = deepcopy(observation)
            saved['last_observation'].pop('last_observation', None)
    return saved


def display_audit(latest, fingerprint, now=None):
    """An old observation stays visible, explicitly non-current, after a failure."""
    latest = latest or {'status': 'unknown', 'issues': ['Audit initial requis'],
                        'findings': [], 'checks': [], 'collected_at': None,
                        'coverage': {'measured': 0, 'total': 15}}
    observation = latest if measured(latest) else latest.get('last_observation')
    retained = measured(observation) and not measured(latest)
    row = deepcopy(observation if retained else latest)
    row.pop('last_observation', None)
    changed = bool(row.get('fingerprint') and row['fingerprint'] != fingerprint)
    row['audit_available'] = measured(row)
    row['audit_recorded'] = measured(row) and not changed
    row['configuration_changed'] = changed
    row['audit_retained'] = bool(retained)
    row['audit_status'] = row.get('status')
    if retained:
        row['last_attempt'] = {key: deepcopy(latest.get(key)) for key in
                               ('collected_at', 'status', 'issues', 'attempts', 'findings')}
    try:
        age = ((now or datetime.now(timezone.utc)) -
               datetime.fromisoformat(row['collected_at'])).total_seconds()
        stale = age < 0 or age > 900
    except (ValueError, TypeError, KeyError):
        stale = True
    row['stale'] = stale or bool(retained) or changed
    if row['stale']:
        row['last_status'] = row.get('status')
        row['status'] = 'unknown'
    return row
