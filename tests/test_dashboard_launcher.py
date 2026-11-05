"""Non-privileged launcher checks; no real sudo, network ports or eBPF loads."""
import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scripts import dashboard_runtime as runtime


class LauncherChecks(unittest.TestCase):
    def test_default_route_detection_selects_unique_lowest_metric(self):
        routes = [{'dev': 'eth9', 'metric': 500}, {'dev': 'eth2', 'metric': 100}]
        with patch.object(runtime.subprocess, 'check_output', return_value=json.dumps(routes)) as run:
            self.assertEqual(runtime.default_interface(), 'eth2')
            self.assertEqual(run.call_args.args[0], ['ip', '-j', 'route', 'show', 'default'])

    def test_missing_or_ambiguous_default_route_has_actionable_error(self):
        for routes in ([], [{'dev': 'a'}, {'dev': 'b'}]):
            with self.subTest(routes=routes), patch.object(runtime.subprocess, 'check_output', return_value=json.dumps(routes)):
                with self.assertRaisesRegex(RuntimeError, 'INTERFACE=<name>'):
                    runtime.default_interface()
        with patch.object(runtime.subprocess, 'check_output', side_effect=FileNotFoundError):
            with self.assertRaisesRegex(RuntimeError, 'INTERFACE=<name>'):
                runtime.default_interface()

    def test_explicit_interface_is_validated(self):
        with patch.object(runtime.socket, 'if_nametoindex', return_value=7) as lookup:
            self.assertEqual(runtime.validate_interface('ens33'), 'ens33')
            lookup.assert_called_once_with('ens33')
        with patch.object(runtime.socket, 'if_nametoindex', side_effect=OSError):
            with self.assertRaisesRegex(RuntimeError, 'does not exist'):
                runtime.validate_interface('missing0')

    def test_database_and_sidecars_require_operator_ownership_and_writability(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Path(directory)/'operator.db'
            runtime.check_database(db, os.getuid())
            self.assertEqual(db.stat().st_uid, os.getuid())
            self.assertEqual(db.stat().st_mode & 0o777, 0o600)
            with self.assertRaisesRegex(RuntimeError, 'owned by the normal user'):
                runtime.check_database(db, os.getuid()+1)
            wal = Path(str(db)+'-wal')
            wal.write_bytes(b'untouched')
            wal.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, 'WAL/SHM'):
                runtime.check_database(db, os.getuid())
            self.assertEqual(wal.read_bytes(), b'untouched')
            wal.chmod(0o600)
            wal.unlink()
            db.chmod(0o400)
            with self.assertRaisesRegex(RuntimeError, 'writable regular file'):
                runtime.check_database(db, os.getuid())
            db.chmod(0o600)
            link = Path(directory)/'link.db'
            link.symlink_to(db)
            with self.assertRaisesRegex(RuntimeError, 'regular file'):
                runtime.check_database(link, os.getuid())
            self.assertTrue(link.is_symlink())

    def test_port_conflict_reports_port_and_does_not_kill_owner(self):
        with patch.object(runtime.socket, 'socket') as constructor:
            constructor.return_value.__enter__.return_value.bind.side_effect = OSError('Address in use')
            with self.assertRaisesRegex(RuntimeError, 'Port 8000'):
                runtime.check_ports()

    def test_active_socket_is_never_removed_but_stale_socket_can_be_removed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'events.sock'
            with socket.socket(socket.AF_UNIX) as active:
                active.bind(str(path))
                active.listen()
                self.assertTrue(runtime.socket_registered(path))
                with self.assertRaisesRegex(RuntimeError, 'active'):
                    runtime.remove_stale_socket(path)
                self.assertTrue(path.exists())
            self.assertFalse(runtime.socket_registered(path))
            runtime.remove_stale_socket(path)
            self.assertFalse(path.exists())
            path.write_text('keep')
            with self.assertRaisesRegex(RuntimeError, 'non-socket'):
                runtime.remove_stale_socket(path)
            self.assertEqual(path.read_text(), 'keep')

    def test_runtime_lock_prevents_duplicate_launch_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'runtime'
            fd = runtime.private_runtime(path, os.getuid())
            try:
                with self.assertRaisesRegex(RuntimeError, 'already running'):
                    runtime.private_runtime(path, os.getuid())
            finally:
                os.close(fd)
            link = Path(directory)/'link'
            link.symlink_to(path)
            with self.assertRaisesRegex(RuntimeError, 'not a symlink'):
                runtime.private_runtime(link, os.getuid())

    def test_browser_disabled_never_invokes_opener(self):
        launcher = runtime.Launcher(argparse.Namespace(open_browser=False))
        with patch.object(runtime.subprocess, 'Popen') as spawn, redirect_stdout(io.StringIO()):
            launcher.open_browser()
        spawn.assert_not_called()

    def test_missing_browser_opener_is_nonfatal(self):
        launcher = runtime.Launcher(argparse.Namespace(open_browser=True))
        with patch.object(runtime.shutil, 'which', return_value=None), patch.object(runtime.subprocess, 'Popen') as spawn, redirect_stdout(io.StringIO()):
            launcher.open_browser()
        spawn.assert_not_called()

    def test_browser_execution_failure_is_nonfatal(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = runtime.Launcher(argparse.Namespace(open_browser=True))
            launcher.log_dir = Path(directory)
            with patch.object(runtime.shutil, 'which', return_value='/stub/xdg-open'), \
                 patch.dict(os.environ, {'DISPLAY': ':0'}), \
                 patch.object(runtime.subprocess, 'Popen', side_effect=OSError('opener unavailable')), \
                 redirect_stdout(io.StringIO()) as output:
                launcher.open_browser()
                self.assertIn(runtime.UI_URL, output.getvalue())
                self.assertTrue(launcher.cleanup())

    def test_launcher_rejects_sudo_for_entire_stack(self):
        launcher = runtime.Launcher(argparse.Namespace())
        with patch.object(runtime.os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(RuntimeError, 'normal user'):
                launcher.run()


STUB = r'''
import os, signal, subprocess, sys, time
from pathlib import Path
name, mode, markers = sys.argv[1:]
def stop(*_):
    Path(markers, name+'.stopped').touch()
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
if name == 'Agent':
    if mode != 'socket-timeout': print('SOCKET_READY', flush=True)
    sys.stdin.buffer.read()
    stop()
if name == 'Receiver': print('Agent status: ready', file=sys.stderr, flush=True)
if name == 'Frontend':
    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    Path(markers, 'grandchild.pid').write_text(str(child.pid))
Path(markers, name+'.ready').touch()
while True: time.sleep(.02)
'''


class StubLauncher(runtime.Launcher):
    """Exercise real child supervision while substituting component executables."""
    def __init__(self, args, root, mode):
        super().__init__(args)
        self.root = root
        self.mode = mode
        self.commands = {}
        self.environments = {}
        self.started = []
        self.browser_called = False

    def run_setup(self, command, label):
        self.commands[label] = command
        if self.mode == 'build-fail' and label == 'Build':
            raise RuntimeError('Build failed')

    def start(self, name, command, **kwargs):
        self.commands[name] = command
        self.environments[name] = kwargs.get('env')
        process = super().start(name, [sys.executable, '-B', str(self.root/'stub.py'), name, self.mode, str(self.root)], **kwargs)
        self.started.append(process)
        return process

    def http_ready(self, url, health=False):
        if self.mode == 'readiness-fail':
            return False
        name = 'API' if health else 'Frontend'
        return (self.root/(name+'.ready')).exists()

    def open_browser(self):
        self.browser_called = True
        super().open_browser()
        self.request_stop()


class SupervisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root/'stub.py').write_text(STUB)
        for package in ('vite', 'react', 'react-dom', 'json-bigint'):
            path = self.root/'frontend/node_modules'/package
            path.mkdir(parents=True)
            (path/'package.json').write_text('{}')
        self.runtime = self.root/'runtime'
        self.runtime.mkdir(mode=0o700)
        self.real_popen = subprocess.Popen

    def launcher(self, mode='normal', interface='lo'):
        return StubLauncher(argparse.Namespace(interface=interface, database=str(self.root/'test database.db'),
                            timeout=0.6, open_browser=False), self.root, mode)

    def run_stub(self, launcher):
        original_open = open

        def terminal(path, *args, **kwargs):
            return original_open('/dev/null' if path == '/dev/tty' else path, *args, **kwargs)

        def popen(command, **kwargs):
            if command == ['sudo', '-v']:
                command = [sys.executable, '-c', 'pass']
            return self.real_popen(command, **kwargs)

        with patch.object(runtime, 'ROOT', self.root), patch.object(runtime.tempfile, 'gettempdir', return_value=str(self.root)), \
             patch.object(runtime, 'check_ports'), patch.object(runtime, 'socket_registered', return_value=False), \
             patch.object(runtime.shutil, 'which', return_value='/stub/command'), \
             patch.object(runtime, 'default_interface', return_value='lo') as detection, \
             patch.object(runtime.subprocess, 'Popen', side_effect=popen), patch('builtins.open', side_effect=terminal), \
             redirect_stdout(io.StringIO()):
            try:
                result = launcher.run()
            finally:
                self.assertTrue(launcher.cleanup())
        return result, detection.call_count

    def test_full_startup_explicit_interface_shared_database_urls_and_cleanup(self):
        launcher = self.launcher()
        result, detected = self.run_stub(launcher)
        self.assertEqual(result, 0)
        self.assertEqual(detected, 0)
        self.assertEqual(set(launcher.commands), {'Dependencies', 'Build', 'Agent', 'Receiver', 'API', 'Frontend'})
        receiver = launcher.commands['Receiver']
        db = receiver[receiver.index('--database')+1]
        self.assertEqual(db, launcher.environments['API']['KERNELLENS_DATABASE'])
        self.assertEqual(launcher.environments['Frontend']['VITE_API_BASE_URL'], runtime.API_URL)
        self.assertEqual(launcher.environments['Frontend']['VITE_WS_URL'], 'ws://127.0.0.1:8000/ws/live')
        self.assertEqual(launcher.commands['Agent'][:3], ['sudo', '-n', '--'])
        for name in ('Receiver', 'API', 'Frontend'):
            self.assertNotIn('sudo', launcher.commands[name])
        self.assertTrue(launcher.browser_called)
        self.assertTrue(all(p.poll() is not None for p in launcher.started))
        self.assertTrue((self.root/'Agent.stopped').exists())
        grandchild = int((self.root/'grandchild.pid').read_text())
        status = Path(f'/proc/{grandchild}/stat')
        if status.exists():
            self.assertEqual(status.read_text().split()[2], 'Z')

    def test_default_interface_workflow(self):
        launcher = self.launcher(interface='')
        _, detected = self.run_stub(launcher)
        self.assertEqual(detected, 1)
        self.assertEqual(launcher.args.interface, 'lo')

    def test_socket_timeout_cleans_up_agent_without_starting_receiver(self):
        launcher = self.launcher('socket-timeout')
        with self.assertRaisesRegex(RuntimeError, 'telemetry socket'):
            self.run_stub(launcher)
        self.assertNotIn('Receiver', launcher.commands)
        self.assertTrue((self.root/'Agent.stopped').exists())
        self.assertTrue(all(p.poll() is not None for p in launcher.started))

    def test_readiness_failure_cleans_up_only_owned_pids(self):
        unrelated = self.real_popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
        try:
            launcher = self.launcher('readiness-fail')
            with self.assertRaisesRegex(RuntimeError, 'API /health'):
                self.run_stub(launcher)
            self.assertTrue(all(p.poll() is not None for p in launcher.started))
            self.assertIsNone(unrelated.poll())
            self.assertNotIn('Frontend', launcher.commands)
            self.assertFalse(launcher.browser_called)
        finally:
            unrelated.terminate()
            unrelated.wait(timeout=3)

    def test_build_failure_prevents_privileged_start(self):
        launcher = self.launcher('build-fail')
        with self.assertRaisesRegex(RuntimeError, 'Build failed'):
            self.run_stub(launcher)
        self.assertEqual(launcher.started, [])

    def test_missing_frontend_packages_prevent_any_privileged_start(self):
        (self.root/'frontend/node_modules/react/package.json').unlink()
        launcher = self.launcher()
        with self.assertRaisesRegex(RuntimeError, 'Frontend packages are missing'):
            self.run_stub(launcher)
        self.assertEqual(launcher.started, [])

    def test_setup_commands_have_logs_and_fail_without_orphaning_children(self):
        launcher = runtime.Launcher(argparse.Namespace())
        launcher.log_dir = self.root
        with redirect_stdout(io.StringIO()):
            launcher.run_setup([sys.executable, '-c', 'print("dependency check")'], 'Dependencies')
            self.assertEqual((self.root/'dependencies.log').read_text().strip(), 'dependency check')
            with self.assertRaisesRegex(RuntimeError, 'Build failed'):
                launcher.run_setup([sys.executable, '-c', 'raise SystemExit(3)'], 'Build')
            self.assertTrue(launcher.cleanup())
        self.assertEqual(launcher.children, [])
        self.assertTrue((self.root/'build.log').is_file())

    def test_unexpected_component_exit_is_detected(self):
        launcher = self.launcher()
        launcher.log_dir = self.root
        process = self.real_popen([sys.executable, '-c', 'pass'], start_new_session=True)
        process.wait(timeout=3)
        launcher.children.append(runtime.Child('Receiver', process))
        with self.assertRaisesRegex(RuntimeError, 'Receiver exited'):
            launcher.check_children()
        with redirect_stdout(io.StringIO()):
            launcher.cleanup()


class AgentHelperTests(unittest.TestCase):
    def run_helper(self, create_socket):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root/'build').mkdir()
        agent = root/'build/kernellens-agent'
        agent.write_text(f'#!{sys.executable}\n' + '''
import os, signal, socket, sys, time
from pathlib import Path
path = Path(sys.argv[-1])
stopped = False
def stop(*_):
    global stopped
    stopped = True
signal.signal(signal.SIGTERM, stop)
sock = socket.socket(socket.AF_UNIX)
''' + ("sock.bind(str(path)); sock.listen()\n" if create_socket else '') + '''
try:
    while not stopped: time.sleep(.01)
finally:
    sock.close()
    if path.exists(): path.unlink()
    (path.parent/'agent-cleaned').touch()
''')
        agent.chmod(0o700)
        # Simulate only root identity/ownership operations; execute actual process,
        # pipe, bounded socket wait, permission ordering and signal cleanup logic.
        code = r'''
import os, sys
from pathlib import Path
from unittest.mock import patch
from scripts import dashboard_runtime as m
root = Path(sys.argv[1]); m.ROOT = root; m.SOCKET_PATH = root/'events.sock'
original = Path.lstat
def lstat(path, *a, **kw):
    info = original(path, *a, **kw)
    if path == m.SOCKET_PATH:
        values = list(info); values[4] = 0
        return os.stat_result(values)
    return info
def chown(path, uid, gid):
    (root/'chown').write_text(f'{uid}:{gid}')
with patch.object(m.os, 'geteuid', return_value=0), patch.object(m, 'prepare_socket_directory', return_value=root), patch.object(Path, 'lstat', lstat), patch.object(m.os, 'chown', chown):
    sys.exit(m.agent_helper(os.getuid(), os.getgid(), 'lo', .3))
'''
        process = subprocess.Popen([sys.executable, '-B', '-c', code, str(root)], cwd=runtime.ROOT,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.finish_helper, process)
        return root, process

    @staticmethod
    def finish_helper(process):
        if process.stdin and not process.stdin.closed:
            process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stdout.close()
        process.stderr.close()

    def test_helper_prepares_permissions_then_eof_stops_owned_agent(self):
        root, process = self.run_helper(True)
        import select
        self.assertTrue(select.select([process.stdout], [], [], 3)[0])
        self.assertEqual(process.stdout.readline(), b'SOCKET_READY\n')
        self.assertEqual((root/'chown').read_text(), f'{os.getuid()}:{os.getgid()}')
        self.assertEqual(root.stat().st_mode & 0o777, 0o711)
        self.assertEqual((root/'events.sock').stat().st_mode & 0o777, 0o660)
        process.stdin.close()
        self.assertEqual(process.wait(timeout=3), 0, process.stderr.read().decode())
        self.assertTrue((root/'agent-cleaned').exists())
        self.assertFalse((root/'events.sock').exists())

    def test_helper_socket_timeout_terminates_agent_and_reports_failure(self):
        root, process = self.run_helper(False)
        self.assertEqual(process.wait(timeout=3), 1)
        self.assertIn(b'Timed out waiting for agent telemetry socket', process.stderr.read())
        self.assertTrue((root/'agent-cleaned').exists())


class TerminalSignalTests(unittest.TestCase):
    def test_shell_trap_forwards_sigterm_and_waits_for_child_cleanup(self):
        self.check_signal(signal.SIGTERM)

    def test_shell_trap_forwards_ctrl_c_and_waits_for_child_cleanup(self):
        self.check_signal(signal.SIGINT)

    def test_ctrl_c_preserves_supervisor_failure_status(self):
        self.check_signal(signal.SIGINT, expected_status=1)

    def check_signal(self, signum, expected_status=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            program = root/'supervisor.py'
            program.write_text('''
import signal, sys
from pathlib import Path
sys.path[:0] = [str(Path.cwd()), str(Path.cwd()/'tests')]
from test_dashboard_launcher import SupervisionTests, StubLauncher
case = SupervisionTests(); case.setUp()
launcher = case.launcher()
def ready():
    Path(sys.argv[1], 'ready').touch()
launcher.open_browser = ready
signal.signal(signal.SIGTERM, launcher.request_stop)
signal.signal(signal.SIGINT, launcher.request_stop)
try:
    case.run_stub(launcher)
finally:
    Path(sys.argv[1], 'stopped').write_text(str(all(p.poll() is not None for p in launcher.started)))
    case.doCleanups()
sys.exit(int(sys.argv[2]))
''')
            shim = root/'python'
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -B "{program}" "{root}" "{expected_status}"\n')
            shim.chmod(0o700)
            with open(root/'terminal.log', 'wb') as log:
                process = subprocess.Popen(['bash', 'scripts/start_dashboard.sh'], cwd=runtime.ROOT,
                                           env=dict(os.environ, PYTHON=str(shim)), stdout=log, stderr=log,
                                           start_new_session=True)
                try:
                    deadline = time.monotonic()+5
                    while not (root/'ready').exists() and process.poll() is None and time.monotonic() < deadline:
                        time.sleep(.02)
                    self.assertTrue((root/'ready').exists(), (root/'terminal.log').read_text())
                    process.send_signal(signum)
                    process.wait(timeout=5)
                    self.assertEqual(process.returncode, expected_status, (root/'terminal.log').read_text())
                    self.assertEqual((root/'stopped').read_text(), 'True')
                    if expected_status == 0:
                        self.assertIn('KernelLens stopped.', (root/'terminal.log').read_text())
                    else:
                        self.assertNotIn('KernelLens stopped.', (root/'terminal.log').read_text())
                finally:
                    if process.poll() is None:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=5)


class EntryPointTests(unittest.TestCase):
    def test_make_target_passes_overrides_without_shell_interpolation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shim = root/'python'
            output = root/'environment.json'
            shim.write_text(f'#!/bin/sh\nexec "{sys.executable}" -c \'import os,json; open(os.environ["LAUNCHER_TEST_OUTPUT"],"w").write(json.dumps(dict(os.environ)))\'\n')
            shim.chmod(0o700)
            database = str(root/"database with spaces and ' quote.db")
            result = subprocess.run(['make', 'dashboard', 'INTERFACE=ens33', f'DATABASE={database}',
                                     'OPEN_BROWSER=0', f'DASHBOARD_PYTHON={shim}'], cwd=runtime.ROOT,
                                    env=dict(os.environ, LAUNCHER_TEST_OUTPUT=str(output)), capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            values = json.loads(output.read_text())
            self.assertEqual(values['INTERFACE'], 'ens33')
            self.assertEqual(values['DATABASE'], database)
            self.assertEqual(values['OPEN_BROWSER'], '0')

    def test_missing_venv_has_actionable_error(self):
        result = subprocess.run(['bash', 'scripts/start_dashboard.sh'], cwd=runtime.ROOT,
                                env=dict(os.environ, PYTHON='/nonexistent/kernellens-python'),
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertIn('Missing Python venv', result.stderr)


class HttpReadinessTests(unittest.TestCase):
    def test_local_http_and_health_content_are_verified(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import threading

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok","database":"ok"}' if self.path == '/health' else b'frontend')

            def log_message(self, *_):
                pass

        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            launcher = runtime.Launcher(argparse.Namespace())
            url = f'http://127.0.0.1:{server.server_port}'
            with patch.dict(os.environ, {'http_proxy': 'http://127.0.0.1:1'}):
                self.assertTrue(launcher.http_ready(url+'/health', health=True))
                self.assertTrue(launcher.http_ready(url))
                self.assertFalse(launcher.http_ready(url, health=True))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class ExitStatusTests(unittest.TestCase):
    def test_startup_and_component_failures_remain_nonzero(self):
        for failure in ('startup', 'Agent', 'Receiver', 'API', 'Frontend'):
            with self.subTest(failure=failure), patch.object(runtime, 'Launcher') as constructor, \
                 patch.object(runtime.signal, 'signal'), patch.object(sys, 'argv', ['dashboard_runtime.py']), \
                 redirect_stdout(io.StringIO()):
                constructor.return_value.run.side_effect = RuntimeError(f'{failure} failed')
                constructor.return_value.cleanup.return_value = True
                self.assertEqual(runtime.main(), 1)
                constructor.return_value.cleanup.assert_called_once()

    def test_cleanup_failure_overrides_successful_stop(self):
        with patch.object(runtime, 'Launcher') as constructor, patch.object(runtime.signal, 'signal'), \
             patch.object(sys, 'argv', ['dashboard_runtime.py']):
            constructor.return_value.run.return_value = 0
            constructor.return_value.cleanup.return_value = False
            self.assertEqual(runtime.main(), 1)

    def test_genuine_supervisor_exit_130_is_not_normalized(self):
        with tempfile.TemporaryDirectory() as directory:
            shim = Path(directory)/'python'
            shim.write_text('#!/bin/sh\nexit 130\n')
            shim.chmod(0o700)
            result = subprocess.run(['bash', 'scripts/start_dashboard.sh'], cwd=runtime.ROOT,
                                    env=dict(os.environ, KERNELLENS_DASHBOARD_PYTHON=str(shim)),
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 130)
            self.assertNotIn('KernelLens stopped.', result.stdout)
