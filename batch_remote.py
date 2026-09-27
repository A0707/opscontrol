"""Read-only Linux scheduling probe. Executed through SSH's fixed allowlist.

Never executes a scheduled command. Never returns cron command arguments or
environment values. Python 3 is required on the remote host; no installation.
"""
import datetime
import glob
import hashlib
import json
import os
import re
import shlex
import subprocess
import time

LIMIT = 300


def cron_rows(text, source, owner, system=False, zone='Heure locale du serveur'):
    jobs = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if re.match(r'^[A-Za-z_][A-Za-z0-9_]*\s*=', line):
            if line.startswith('CRON_TZ='):
                zone = line.split('=', 1)[1].strip().strip('"\'')[:80]
            continue
        count = (1 if line.startswith('@') else 5) + int(system)
        parts = line.split(None, count)
        if len(parts) != count + 1:
            continue
        schedule = ' '.join(parts[:count-int(system)])
        user = parts[count-1] if system else owner
        command = parts[-1]
        # Retain only the executable; shell wrappers intentionally hide the script
        # argument. Operators can identify the source file and line on the server.
        try:
            tokens = shlex.split(command)
            program = next((t for t in tokens if not re.match(r'^\w+=', t)), '')
            program = os.path.basename(program)
            if not re.fullmatch(r'[A-Za-z0-9_.+-]{1,100}', program):
                program = 'Commande composée'
        except ValueError:
            program = 'Commande à vérifier sur le serveur'
        jobs.append({'id': hashlib.sha256((source+':'+str(number)).encode()).hexdigest()[:20],
                     'kind': 'cron', 'name': program, 'source': source, 'line': number,
                     'owner': user[:100], 'schedule': schedule[:120], 'timezone': zone,
                     'state': 'scheduled', 'last_run': None, 'next_run': None,
                     'evidence': 'Planification déclarée ; exécution et résultat non mesurés.'})
    return jobs


def properties(text):
    return [dict(line.split('=', 1) for line in part.splitlines() if '=' in line)
            for part in text.strip().split('\n\n') if part.strip()]


def timer_rows(timers, services, zone):
    by_id = {s.get('Id'): s for s in services}
    jobs = []
    for timer in timers:
        name = timer.get('Id', '')
        if not name.endswith('.timer'):
            continue
        unit = timer.get('Unit') or name[:-6]+'.service'
        service = by_id.get(unit, {})
        active, sub = service.get('ActiveState'), service.get('SubState')
        ended = service.get('ExecMainExitTimestamp') or None
        outcome = service.get('Result')
        if active == 'failed' or (ended and outcome and outcome != 'success'):
            state = 'failed'
        elif active == 'activating' or (active == 'active' and sub in ('running', 'start')):
            state = 'running'
        elif ended and outcome == 'success':
            state = 'success'
        else:
            state = 'unknown'
        jobs.append({'id': name, 'kind': 'systemd', 'name': name, 'source': unit,
                     'owner': service.get('User') or 'root (systemd système)',
                     'schedule': timer.get('TimersCalendar') or timer.get('TimersMonotonic') or 'Expression non disponible',
                     'timezone': zone, 'state': state, 'timer_state': timer.get('ActiveState'),
                     'last_run': timer.get('LastTriggerUSec') or None,
                     'next_run': timer.get('NextElapseUSecRealtime') or None,
                     'exit_code': service.get('ExecMainStatus'),
                     'evidence': 'Dernier résultat du service : '+(outcome or 'non mesuré')})
    return jobs


def main():
    import pwd
    deadline = time.monotonic() + 18
    limitations, jobs = [], []

    def read_command(args):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            return None
        try:
            # stdout/stderr=PIPE + universal_newlines plutôt que capture_output/text :
            # ceux-ci n’existent qu’à partir de Python 3.7, et CentOS 7 (srv-batch-02)
            # n’a que 3.6 — la sonde y plantait, d’où « Sonde indisponible ».
            # (Apostrophes typographiques exprès : une apostrophe droite dans ce
            # fichier casse les guillemets de la commande SSH.)
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
                                  errors='replace', timeout=min(3, remaining),
                                  env={**os.environ, 'LC_ALL':'C', 'SYSTEMD_COLORS':'0'})
        except (OSError, subprocess.TimeoutExpired):
            return None

    tz = read_command(['timedatectl', 'show', '-p', 'Timezone', '--value'])
    zone = tz.stdout.strip()[:80] if tz and tz.returncode == 0 else 'Heure locale du serveur (fuseau non lu)'
    user = pwd.getpwuid(os.getuid()).pw_name
    cron = read_command(['crontab', '-l'])
    if cron and cron.returncode == 0:
        jobs.extend(cron_rows(cron.stdout, 'crontab:'+user, user, zone=zone))
    elif not cron or 'no crontab for' not in cron.stderr.lower():
        limitations.append('Crontab du compte non accessible ou outil absent')
    files = ['/etc/crontab'] + sorted(glob.glob('/etc/cron.d/*'))
    for filename in files[:128]:
        if not os.path.isfile(filename):
            continue
        try:
            with open(filename, encoding='utf-8', errors='replace') as handle:
                content = handle.read(262145)
            if len(content) > 262144:
                limitations.append('Fichier cron trop volumineux : '+filename)
                continue
            jobs.extend(cron_rows(content, filename, 'root', system=True, zone=zone))
        except OSError:
            limitations.append('Fichier cron non accessible : '+filename)
    limitations.append('Crontabs des autres comptes et ordonnanceurs applicatifs non inspectés')
    listing = read_command(['systemctl','list-units','--type=timer','--all','--plain','--no-legend','--no-pager'])
    if listing and listing.returncode == 0:
        units = [line.split()[0] for line in listing.stdout.splitlines() if line.split() and re.fullmatch(r'[A-Za-z0-9_.@:-]+\.timer',line.split()[0])]
        if len(units)>64:
            limitations.append('Timers limités aux 64 premières unités chargées')
        units = units[:64]
        props = 'Id,Unit,ActiveState,LastTriggerUSec,NextElapseUSecRealtime,TimersCalendar,TimersMonotonic'
        timers = read_command(['systemctl','show','--no-pager','-p',props,'--']+units) if units else None
        if timers and timers.returncode == 0:
            parsed = properties(timers.stdout)
            service_units = [t.get('Unit') or t.get('Id','')[:-6]+'.service' for t in parsed]
            service_units = [u for u in service_units if re.fullmatch(r'[A-Za-z0-9_.@:-]+\.service',u)]
            services = read_command(['systemctl','show','--no-pager','-p','Id,User,ActiveState,SubState,Result,ExecMainStatus,ExecMainExitTimestamp','--']+service_units) if service_units else None
            jobs.extend(timer_rows(parsed, properties(services.stdout) if services and services.returncode==0 else [], zone))
            if not services or services.returncode:
                limitations.append('Résultats des services associés non mesurés')
        elif units:
            limitations.append('Propriétés des timers non accessibles')
    else:
        limitations.append('Timers systemd non accessibles ou systemd absent')
    if len(files)>128 or len(jobs)>LIMIT:
        limitations.append('Inventaire tronqué par les limites de collecte')
    print(json.dumps({'collected_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      'jobs':jobs[:LIMIT], 'limitations':limitations, 'timezone':zone}, ensure_ascii=True))


if __name__ == '__main__':
    main()
