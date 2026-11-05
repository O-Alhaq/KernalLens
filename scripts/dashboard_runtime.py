#!/usr/bin/env python3
"""Foreground M11 development supervisor. Security engines remain separate."""

import argparse
import fcntl
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

ROOT = Path(__file__).resolve().parents[1]
SOCKET_PATH = Path('/run/kernellens/events.sock')
API_URL = 'http://127.0.0.1:8000'
UI_URL = 'http://127.0.0.1:5173/'


def say(message):
    print(f'[KernelLens] {message}', flush=True)


def default_interface():
    try:
        routes = json.loads(subprocess.check_output(
            ['ip', '-j', 'route', 'show', 'default'], text=True, timeout=5))
        candidates = [r for r in routes if r.get('dev') and r.get('type', 'unicast') == 'unicast']
        metric = min(r.get('metric', 0) for r in candidates)
        names = {r['dev'] for r in candidates if r.get('metric', 0) == metric}
        if len(names) == 1:
            return names.pop()
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
        pass
    raise RuntimeError('Cannot determine a unique default-route interface. Use make dashboard INTERFACE=<name>.')


def validate_interface(name):
    try:
        socket.if_nametoindex(name)
    except (OSError, ValueError):
        raise RuntimeError(f'Interface {name!r} does not exist. Use make dashboard INTERFACE=<name>.') from None
    return name


def check_ports():
    for port in (8000, 5173):
        with socket.socket() as probe:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError as error:
                raise RuntimeError(f'Port {port} is unavailable: {error}. Stop its owning service or choose another session.') from error


def socket_registered(path):
    # Inspect without connecting: a probe connection would displace telemetry.
    with open('/proc/net/unix', encoding='utf-8') as entries:
        return any(len(parts := line.split(maxsplit=7)) == 8 and parts[7].strip() == str(path)
                   for line in entries)


def check_database(path, uid):
    parent = path.parent
    if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
        raise RuntimeError(f'Database directory is missing or unwritable: {parent}')
    for candidate in (path, Path(str(path)+'-wal'), Path(str(path)+'-shm')):
        try:
            info = candidate.lstat()
        except FileNotFoundError:
            continue
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                or not info.st_mode & stat.S_IWUSR or not os.access(candidate, os.R_OK | os.W_OK)):
            raise RuntimeError(f'Database/WAL/SHM must be a writable regular file owned by the normal user: {candidate}. '
                               'Choose DATABASE=/path/to/user-owned.db or repair ownership separately; no file was deleted or chowned.')
    # Reserve new files as the operator, never through sudo. No symlink following.
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    os.close(fd)


def private_runtime(path, uid):
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & 0o077:
        raise RuntimeError(f'Runtime directory must be owned by you, mode 0700, and not a symlink: {path}')
    fd = os.open(path/'launcher.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise RuntimeError('A KernelLens dashboard launcher is already running for this user.') from None
    return fd


@dataclass
class Child:
    name: str
    process: subprocess.Popen
    privileged: bool = False
    grouped: bool = True


class Launcher:
    def __init__(self, args):
        self.args = args
        self.children = []
        self.logs = []
        self.stop_requested = False
        self.lock_fd = None
        self.log_dir = None

    def request_stop(self, *_):
        self.stop_requested = True

    def check_children(self):
        if self.stop_requested:
            raise InterruptedError('Stop requested')
        for child in self.children:
            if child.process.poll() is not None:
                raise RuntimeError(f'{child.name} exited (status {child.process.returncode}). See {self.log_dir}.')

    def wait_for(self, predicate, label):
        end = time.monotonic() + self.args.timeout
        while time.monotonic() < end:
            self.check_children()
            if predicate():
                self.check_children()
                return
            time.sleep(0.1)
        raise RuntimeError(f'Timed out waiting for {label}. See {self.log_dir}.')

    def start(self, name, command, *, privileged=False, env=None):
        log = open(self.log_dir/f'{name.lower()}.log', 'xb')
        self.logs.append(log)
        process = subprocess.Popen(command, cwd=ROOT, env=env, start_new_session=not privileged,
                                   stdin=subprocess.PIPE if privileged else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if privileged else log, stderr=log)
        self.children.append(Child(name, process, privileged))
        return process

    @staticmethod
    def receiver_ready(path):
        with open(path, 'rb') as log:
            return b'Agent status: ready' in log.read(65536)

    def http_ready(self, url, health=False):
        # Ignore proxy environment for local readiness probes.
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(url, timeout=0.5) as response:
                if response.status != 200:
                    return False
                if health:
                    value = json.loads(response.read(4096))
                    return value == {'status': 'ok', 'database': 'ok'}
                return True
        except (OSError, ValueError, urllib.error.URLError):
            return False

    def run(self):
        if os.geteuid() == 0:
            raise RuntimeError('Run make dashboard as your normal user, not with sudo. Only the agent/runtime helper uses sudo.')
        uid, gid = os.getuid(), os.getgid()
        runtime = Path(tempfile.gettempdir()) / f'kernellens-runtime-{uid}'
        self.lock_fd = private_runtime(runtime, uid)
        self.log_dir = Path(tempfile.mkdtemp(prefix='run-', dir=runtime))
        self.args.interface = validate_interface(self.args.interface or default_interface())
        database = Path(self.args.database).expanduser().absolute()
        say('KernelLens Dashboard')
        say(f'Interface: {self.args.interface}')
        say(f'Database: {database}')
        say(f'Logs: {self.log_dir}')
        check_ports()
        if socket_registered(SOCKET_PATH):
            raise RuntimeError(f'Telemetry socket is in use: {SOCKET_PATH}. Stop its owning agent first.')
        check_database(database, uid)
        for command in ('make', 'sudo', 'npm', 'node'):
            if shutil.which(command) is None:
                raise RuntimeError(f'Missing required command: {command}. Run ./scripts/setup.sh; see docs/SETUP.md.')
        for package in ('vite', 'react', 'react-dom', 'json-bigint'):
            if not (ROOT/'frontend/node_modules'/package/'package.json').is_file():
                raise RuntimeError('Frontend packages are missing. Run ./scripts/setup.sh to install the supported frontend dependencies.')
        say('Checking Python dependencies and database...')
        self.run_setup([sys.executable, '-B', '-c',
            'import fastapi, uvicorn, yaml, websockets; from backend.storage import EventStore; '
            'import sys; EventStore(sys.argv[1]).initialize()', str(database)], 'Dependencies')
        say('Checking incremental agent build...')
        self.run_setup(['make', 'all'], 'Build')
        self.check_children()
        say('Authenticating sudo (once)...')
        # Use the controlling terminal: the shell wrapper starts us in the background.
        try:
            with open('/dev/tty', 'rb') as terminal:
                auth = subprocess.Popen(['sudo', '-v'], stdin=terminal)
        except OSError as error:
            raise RuntimeError('An interactive terminal is required for sudo authentication. Run make dashboard in a terminal.') from error
        authentication = Child('sudo authentication', auth, grouped=False)
        self.children.append(authentication)
        while auth.poll() is None:
            if self.stop_requested:
                raise InterruptedError('Stop requested')
            time.sleep(0.1)
        self.children.remove(authentication)
        if auth.returncode:
            raise RuntimeError('sudo authentication failed; no components started.')
        self.check_children()
        say('Starting agent; waiting for telemetry socket...')
        helper = self.start('Agent', ['sudo', '-n', '--', sys.executable, '-I', '-B',
            str(Path(__file__).resolve()), '--agent-helper', str(uid), str(gid), self.args.interface,
            str(self.args.timeout)], privileged=True)
        handshake = bytearray()

        def ready():
            if select.select([helper.stdout], [], [], 0)[0]:
                handshake.extend(os.read(helper.stdout.fileno(), 4096))
            return b'SOCKET_READY\n' in handshake

        self.wait_for(ready, 'telemetry socket and receiver permissions')
        say('Agent started; telemetry socket ready (0711 directory, operator-owned 0660 socket).')
        self.start('Receiver', [sys.executable, '-B', str(ROOT/'backend/receiver.py'), str(SOCKET_PATH),
            '--rules', str(ROOT/'config/rules.yaml'), '--scoring', str(ROOT/'config/scoring.yaml'),
            '--correlation', str(ROOT/'config/correlation.yaml'), '--database', str(database)])
        receiver_log = self.log_dir/'receiver.log'
        self.wait_for(lambda: self.receiver_ready(receiver_log), 'receiver handshake')
        say('Receiver connected')
        env = dict(os.environ, KERNELLENS_DATABASE=str(database),
                   KERNELLENS_UI_ORIGINS='http://127.0.0.1:5173,http://localhost:5173')
        self.start('API', [sys.executable, '-B', '-m', 'uvicorn', 'backend.api:app',
                           '--host', '127.0.0.1', '--port', '8000'], env=env)
        self.wait_for(lambda: self.http_ready(API_URL+'/health', health=True), 'API /health')
        say('API listening on 127.0.0.1:8000; WebSocket backend /ws/live')
        env = dict(os.environ, VITE_API_BASE_URL=API_URL, VITE_WS_URL='ws://127.0.0.1:8000/ws/live')
        self.start('Frontend', ['npm', '--prefix', 'frontend', 'run', 'dev', '--',
                               '--host', '127.0.0.1', '--port', '5173', '--strictPort'], env=env)
        self.wait_for(lambda: self.http_ready(UI_URL), 'frontend HTTP endpoint')
        say(f'Dashboard listening on {UI_URL}')
        self.open_browser()
        say('Press Ctrl+C to stop KernelLens.')
        while not self.stop_requested:
            self.check_children()
            time.sleep(0.2)
        return 0

    def run_setup(self, command, label):
        # Also supervise setup commands, so build failures/signals cannot orphan them.
        self.start(label, command)
        child = self.children[-1]
        while child.process.poll() is None:
            if self.stop_requested:
                raise InterruptedError('Stop requested')
            time.sleep(0.1)
        self.children.remove(child)
        if child.process.returncode:
            raise RuntimeError(f'{label} failed. See {self.log_dir}/{label.lower()}.log. '
                               'Check build prerequisites, .venv dependencies, and database ownership.')

    def open_browser(self):
        if not self.args.open_browser:
            say(f'Browser opening disabled. Open {UI_URL}')
        elif not shutil.which('xdg-open') or not (os.environ.get('DISPLAY') or os.environ.get('WAYLAND_DISPLAY')):
            say(f'No graphical browser opener available. Open {UI_URL}')
        else:
            say('Opening browser...')
            # The opener may return immediately; it must never end the stack.
            log = open(self.log_dir/'browser.log', 'xb')
            self.logs.append(log)
            try:
                self.browser = subprocess.Popen(['xdg-open', UI_URL], stdin=subprocess.DEVNULL,
                                                stdout=log, stderr=log, start_new_session=True)
            except OSError as error:
                say(f'Could not open browser ({error}). Open {UI_URL}')

    def cleanup(self):
        if self.children:
            say('Stopping KernelLens...')
        failed = False
        for child in reversed(self.children):
            process = child.process
            try:
                if child.privileged:
                    # Root helper watches EOF, even if the supervisor is killed.
                    process.stdin.close()
                    process.wait(timeout=15)
                else:
                    # Signal the owned process group even if npm's leader exited.
                    try:
                        if child.grouped:
                            os.killpg(process.pid, signal.SIGINT if child.name == 'Receiver' else signal.SIGTERM)
                        elif process.poll() is None:
                            process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=15 if child.name == 'Receiver' else 5)
                    except subprocess.TimeoutExpired:
                        failed = True
                        say(f'{child.name} exceeded shutdown grace; forcing its owned process group.')
                        if child.grouped:
                            os.killpg(process.pid, signal.SIGKILL)
                        else:
                            process.kill()
                        process.wait(timeout=2)
                    # npm can exit before its Vite child; reap remaining group members.
                    try:
                        if child.grouped:
                            os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                if process.stdout is not None:
                    process.stdout.close()
                say(f'{child.name} stopped')
                if child.privileged and process.returncode:
                    failed = True
                    say(f'Agent cleanup returned {process.returncode}; inspect agent.log for detach results.')
                elif not child.privileged and process.returncode not in (0, -signal.SIGINT, -signal.SIGTERM, 128+signal.SIGINT, 128+signal.SIGTERM):
                    failed = True
                    say(f'{child.name} shutdown returned {process.returncode}; inspect its log.')
            except (OSError, subprocess.TimeoutExpired) as error:
                failed = True
                say(f'Could not confirm {child.name} shutdown: {error}. Inspect {self.log_dir}.')
        self.children.clear()
        opener = getattr(self, 'browser', None)
        if opener is not None:
            try:
                opener.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(opener.pid, signal.SIGTERM)
                    opener.wait(timeout=2)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    pass
        for log in self.logs:
            log.close()
        self.logs.clear()
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
        return not failed


def prepare_socket_directory(path):
    directory = path.parent
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError(f'Refusing unsafe runtime directory {directory}; require a root-owned real directory without group/other write access.')
    return directory


def remove_stale_socket(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode):
        raise RuntimeError(f'Refusing non-socket or symlink at {path}')
    if socket_registered(path):
        raise RuntimeError(f'Telemetry socket is active: {path}')
    if path.lstat() != info:
        raise RuntimeError('Telemetry socket changed during inspection; refusing removal.')
    path.unlink()


def agent_helper(uid, gid, interface, timeout):
    """Only privileged path: fixed runtime directory, socket setup, owned agent."""
    if os.geteuid() != 0 or uid == 0:
        raise RuntimeError('Agent helper requires sudo and a non-root operator UID.')
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, stop)
    directory = prepare_socket_directory(SOCKET_PATH)
    lock = os.open(directory/'launcher.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    process = None
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another KernelLens launcher owns the agent runtime lock.') from None
        remove_stale_socket(SOCKET_PATH)
        process = subprocess.Popen([str(ROOT/'build/kernellens-agent'), '--host', interface, str(SOCKET_PATH)],
                                   stdin=subprocess.DEVNULL, stdout=sys.stderr, stderr=sys.stderr)
        deadline = time.monotonic() + timeout
        announced = False
        while not stopped:
            if process.poll() is not None:
                raise RuntimeError(f'Agent exited with status {process.returncode}; inspect agent.log.')
            # EOF is reliable even after sudo credentials expire or parent SIGKILL.
            if select.select([sys.stdin.buffer], [], [], 0.1)[0]:
                if not os.read(sys.stdin.fileno(), 1):
                    break
            if not announced:
                try:
                    info = SOCKET_PATH.lstat()
                except FileNotFoundError:
                    info = None
                if info is not None:
                    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
                        raise RuntimeError('Agent socket has unexpected type/owner.')
                    os.chmod(directory, 0o711)
                    os.chown(SOCKET_PATH, uid, gid)
                    os.chmod(SOCKET_PATH, 0o660)
                    print('SOCKET_READY', flush=True)
                    announced = True
                elif time.monotonic() >= deadline:
                    raise RuntimeError('Timed out waiting for agent telemetry socket.')
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    print('Agent required SIGKILL; graceful XDP/tracepoint cleanup unconfirmed.', file=sys.stderr)
                    raise RuntimeError('Agent graceful cleanup timed out.')
            if process.returncode != 0:
                print(f'Agent final status: {process.returncode}; inspect detach results.', file=sys.stderr)
        os.close(lock)
    return 0 if process.returncode == 0 else 1


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--agent-helper':
        if len(sys.argv) != 6:
            raise RuntimeError('Invalid agent helper arguments')
        return agent_helper(int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], float(sys.argv[5]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--interface', default=os.environ.get('INTERFACE', ''))
    parser.add_argument('--database', default=os.environ.get('DATABASE', '/tmp/kernellens.db'))
    parser.add_argument('--open-browser', choices=('0', '1'), default=os.environ.get('OPEN_BROWSER', '1'))
    parser.add_argument('--timeout', type=float, default=20, help='readiness timeout per stage (seconds)')
    args = parser.parse_args()
    if not 0 < args.timeout <= 300:
        parser.error('timeout must be greater than 0 and at most 300 seconds')
    args.open_browser = args.open_browser == '1'
    launcher = Launcher(args)
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, launcher.request_stop)
    result = 1
    try:
        result = launcher.run()
    except InterruptedError:
        result = 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        say(f'ERROR: {error}')
    finally:
        if not launcher.cleanup():
            result = 1
    return result


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f'[KernelLens] ERROR: {error}', file=sys.stderr)
        sys.exit(1)
