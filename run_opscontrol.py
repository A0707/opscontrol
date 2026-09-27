"""Keep the local Bacula tunnel alive for the lifetime of the API server."""
import json
import os
import re
import shutil
from pathlib import Path
import socket
import subprocess
import sys
import time
import threading
from contextlib import contextmanager

BASE = Path(__file__).resolve().parent


def tunnel_required():
    config = BASE / 'data/api-connections.json'
    if not config.exists():
        return False
    items = json.loads(config.read_text(encoding='utf-8-sig'))
    return any(item.get('provider') == 'Bacula' and
               item.get('url') == 'http://127.0.0.1:19096/api/v2/jobs' and
               os.getenv(item.get('token_env', '')) for item in items)


def ssh_client():
    """Client OpenSSH : celui de Windows s'il existe, sinon celui du PATH (VM Linux).

    Le chemin Windows était écrit en dur : sur la VM, le tunnel Bacula échouait
    en boucle (« client SSH indisponible ») et la source restait muette.
    """
    if os.name == 'nt':
        windows = Path(os.environ.get('WINDIR', 'C:/Windows')) / 'System32/OpenSSH/ssh.exe'
        if windows.exists():
            return str(windows)
    return shutil.which('ssh')


def tunnel_target():
    """Compte et hôte du tunnel. Sur la VM : le compte de service, pas un compte personnel."""
    cible = os.environ.get('OPSCONTROL_BACULA_TUNNEL_TARGET', 'opscontrol@192.0.2.148')
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,63}@[A-Za-z0-9][A-Za-z0-9_.:-]*', cible):
        raise ValueError('OPSCONTROL_BACULA_TUNNEL_TARGET invalide : attendu compte@hôte')
    return cible


def port_open():
    try:
        with socket.create_connection(('127.0.0.1', 19096), timeout=0.3):
            return True
    except OSError:
        return False


def stop_child(child):
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()


class Tunnel:
    def __init__(self):
        self.child = None
        self.retry_at = 0

    def tick(self):
        if self.child is not None and self.child.poll() is None:
            return
        # Respect an independently launched tunnel; never stop somebody else's process.
        if time.monotonic() < self.retry_at or port_open():
            return
        self.retry_at = time.monotonic() + 30
        ssh = ssh_client()
        if ssh is None:
            print('Bacula : client OpenSSH introuvable ; nouvelle tentative dans 30 secondes.', flush=True)
            return
        known = BASE / 'data/bacula-known_hosts'
        if not known.exists():
            print('Bacula : enregistrer la cle avec LANCER-TUNNEL-BACULA.ps1 -RegisterHostKey.', flush=True)
            return
        args = [str(ssh), '-N', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '-o', 'StrictHostKeyChecking=yes', '-o', f'UserKnownHostsFile={known.as_posix()}',
                '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
                '-o', 'ServerAliveCountMax=3', '-L',
                '127.0.0.1:19096:127.0.0.1:9096', tunnel_target()]
        try:
            self.child = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                          creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            print('Bacula : ouverture du tunnel SSH ; nouvelle tentative automatique en cas de coupure.', flush=True)
        except OSError:
            print('Bacula : client SSH indisponible ; nouvelle tentative dans 30 secondes.', flush=True)

    def close(self):
        stop_child(self.child)


@contextmanager
def application_tunnel(connections):
    """Fallback owner for direct uvicorn starts; never stop an external tunnel."""
    if os.getenv('OPSCONTROL_TUNNEL_SUPERVISED') == '1':
        yield
        return
    stopped = threading.Event()
    tunnel = Tunnel()

    def supervise():
        try:
            while not stopped.is_set():
                if any(c.get('provider') == 'Bacula' and
                       c.get('url') == 'http://127.0.0.1:19096/api/v2/jobs' and
                       c.get('auth_configured') is True for c in connections()):
                    tunnel.tick()
                if stopped.wait(1):
                    break
        finally:
            tunnel.close()

    thread = threading.Thread(target=supervise, name='bacula-tunnel', daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join(7)


def main():
    tunnel = Tunnel()
    server = None
    try:
        enabled = tunnel_required()
        if enabled:
            tunnel.tick()
            # Give forwarding a bounded chance to become ready before initial collection.
            for _ in range(20):
                if port_open():
                    break
                time.sleep(0.5)
        server = subprocess.Popen([sys.executable, '-m', 'uvicorn', 'app:app',
                                   '--host', '127.0.0.1', '--port', '8000'], cwd=BASE,
                                  env={**os.environ, 'OPSCONTROL_TUNNEL_SUPERVISED': '1'})
        while server.poll() is None:
            if enabled:
                tunnel.tick()
            time.sleep(1)
        return server.returncode
    except KeyboardInterrupt:
        return 0
    finally:
        stop_child(server)
        tunnel.close()


if __name__ == '__main__':
    raise SystemExit(main())
