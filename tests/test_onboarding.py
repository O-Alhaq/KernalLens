"""Setup and real-parser validation tests: never install OS packages or load BPF."""
import argparse
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml
from scripts import setup_environment as setup
from scripts import validate_config

ROOT = Path(__file__).resolve().parents[1]


class ConfigurationCommandTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = Path(self.directory.name)
        for source in (ROOT/'config').glob('*.yaml'):
            shutil.copyfile(source, self.config/source.name)

    def check(self, expected):
        with redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(validate_config.validate(self.config), expected)
        self.assertNotIn('Traceback', stderr.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def test_shipped_configuration_succeeds_with_real_loaders(self):
        stdout, stderr = self.check(0)
        for name in ('rules.yaml', 'scoring.yaml', 'correlation.yaml'):
            self.assertIn('✓ '+name, stdout)
        self.assertEqual(stderr, '')

    def malformed(self, filename):
        (self.config/filename).write_text('invalid: [unterminated')
        _, stderr = self.check(1)
        self.assertIn(filename, stderr)
        self.assertIn('line ', stderr)

    def test_malformed_rules(self):
        self.malformed('rules.yaml')

    def test_malformed_scoring(self):
        self.malformed('scoring.yaml')

    def test_malformed_correlation(self):
        self.malformed('correlation.yaml')

    def test_rule_semantics_and_duplicate_ids_are_rejected(self):
        path = self.config/'rules.yaml'
        original = path.read_text()
        for change in ({'threshold': 0}, {'window_seconds': 0}, {'enabled': 'true'},
                       {'unknown': True}, {'type': 'block_ip'}):
            value = yaml.safe_load(original)
            value['rules'][0].update(change)
            path.write_text(yaml.safe_dump(value))
            _, stderr = self.check(1)
            self.assertIn('rule 1:', stderr)
        value = yaml.safe_load(original)
        value['rules'].append(value['rules'][0])
        path.write_text(yaml.safe_dump(value))
        self.assertIn('duplicate rule ID', self.check(1)[1])

    def test_invalid_scoring_policy_is_rejected(self):
        path = self.config/'scoring.yaml'
        value = yaml.safe_load(path.read_text())
        value['scoring']['port_scan']['tiers'][0]['score'] = 80
        path.write_text(yaml.safe_dump(value))
        self.assertIn('scoring.yaml', self.check(1)[1])

    def test_invalid_correlation_policy_is_rejected(self):
        path = self.config/'correlation.yaml'
        value = yaml.safe_load(path.read_text())
        value['correlation']['network_sequence']['window_seconds'] = -1
        path.write_text(yaml.safe_dump(value))
        self.assertIn('correlation.yaml', self.check(1)[1])

    def test_help_and_validation_make_targets(self):
        help_result = subprocess.run(['make', 'help', 'PKG_CONFIG=/nonexistent/pkg-config'], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(help_result.returncode, 0)
        self.assertEqual(help_result.stderr, '')
        help_text = help_result.stdout
        for name in ('./scripts/setup.sh', 'dashboard', 'validate-config', 'test', 'help'):
            self.assertIn(name, help_text)
        self.assertNotIn('dashboard-stop', help_text)
        result = subprocess.run(['make', 'validate-config'], cwd=ROOT, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('configuration is valid', result.stdout)

    def test_shipped_values_have_not_changed(self):
        rules = yaml.safe_load((self.config/'rules.yaml').read_text())['rules']
        syn = next(r for r in rules if r['id'] == 'syn_flood_basic')
        self.assertEqual((syn['threshold'], syn['window_seconds'], syn['quiet_seconds'], syn['max_detection_seconds']), (1000, 5, 3, 60))
        self.assertEqual([r['id'] for r in rules if not r['enabled']], ['traffic_flood_example', 'process_example'])
        scoring = yaml.safe_load((self.config/'scoring.yaml').read_text())['scoring']
        self.assertEqual(scoring['syn_flood'], {'base_score':60, 'volume_tiers':[{'multiple':2,'points':10},{'multiple':5,'points':20}]})
        correlation = yaml.safe_load((self.config/'correlation.yaml').read_text())
        self.assertEqual([v['window_seconds'] for v in correlation['correlation'].values()], [60, 30, 60])
        self.assertEqual(correlation['monitored_ips'], [])


class SetupHelperTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_supported_platform_and_clear_unsupported_platform_error(self):
        setup.check_platform({'ID':'ubuntu', 'VERSION_ID':'26.04'}, 'Linux')
        for release, system in (({'ID':'ubuntu', 'VERSION_ID':'24.04'}, 'Linux'), ({'ID':'debian'}, 'Linux'), ({}, 'Darwin')):
            with self.assertRaisesRegex(RuntimeError, 'Ubuntu 26.04'):
                setup.check_platform(release, system)

    def test_missing_kernel_btf_fails_without_privileged_probe(self):
        with self.assertRaisesRegex(RuntimeError, 'Kernel BTF'):
            setup.check_kernel(self.root/'missing-btf')

    def test_satisfied_os_packages_do_not_install_anything(self):
        with patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            setup.install_packages([])
        run.assert_not_called()

    def test_missing_packages_require_consent_and_are_printed(self):
        with patch.object(sys.stdin, 'isatty', return_value=False), patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()) as text:
            with self.assertRaisesRegex(RuntimeError, 'declined'):
                setup.install_packages(['clang'])
        self.assertIn('clang', text.getvalue())
        run.assert_not_called()

    def test_only_approved_os_installation_uses_sudo(self):
        with patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            setup.install_packages(['clang', 'bpftool'], assume_yes=True)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['sudo', '-v'], ['sudo', '-n', 'apt-get', 'update'],
            ['sudo', '-n', 'apt-get', 'install', '-y', '--no-install-recommends', 'clang', 'bpftool']])

    def test_existing_venv_is_reused_and_not_recreated(self):
        python = self.root/'.venv/bin/python'
        python.parent.mkdir(parents=True)
        python.touch()
        with patch.object(setup, 'output', return_value='True'), patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            self.assertEqual(setup.ensure_venv(self.root), python)
            self.assertEqual(setup.ensure_venv(self.root), python)
        run.assert_not_called()

    def test_missing_venv_is_created_as_normal_user(self):
        python = self.root/'.venv/bin/python'
        def create(command):
            self.assertNotIn('sudo', command)
            python.parent.mkdir(parents=True)
            python.touch()
        with patch.object(setup, 'output', return_value='True'), patch.object(setup, 'run', side_effect=create) as run, redirect_stdout(io.StringIO()):
            self.assertEqual(setup.ensure_venv(self.root), python)
        run.assert_called_once()

    def test_broken_venv_is_preserved_and_diagnosed(self):
        (self.root/'.venv').mkdir()
        with self.assertRaisesRegex(RuntimeError, 'not deleted'):
            setup.ensure_venv(self.root)
        self.assertTrue((self.root/'.venv').is_dir())

    def test_old_node_fails_without_remote_installer(self):
        with patch.object(setup, 'output', return_value='v18.0.0'), patch.object(setup, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'Node.js 22.12'):
                setup.npm_command(self.root)
        run.assert_not_called()

    def test_old_global_npm_gets_local_install_only(self):
        with patch.object(setup, 'output', side_effect=['v22.22.1', '9.2.0', '11.0.0']), patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            command = setup.npm_command(self.root)
        self.assertEqual(command[0], 'node')
        self.assertTrue(command[1].startswith(str(self.root/'.tools')))
        invocation = run.call_args.args[0]
        self.assertNotIn('sudo', invocation)
        self.assertNotIn('-g', invocation)
        self.assertIn('npm@11', invocation)

    def test_local_npm_is_reused(self):
        local = self.root/'.tools/npm/node_modules/npm/bin/npm-cli.js'
        local.parent.mkdir(parents=True)
        local.touch()
        with patch.object(setup, 'output', side_effect=['v22.22.1', '9.2.0', '11.0.0']), patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            setup.npm_command(self.root)
        run.assert_not_called()

    def frontend(self):
        (self.root/'frontend/node_modules').mkdir(parents=True)
        (self.root/'frontend/package.json').write_text('{}')
        (self.root/'frontend/package-lock.json').write_text('{}')

    def test_frontend_reused_on_repeated_setup(self):
        self.frontend()
        with patch.object(setup.subprocess, 'run', return_value=argparse.Namespace(returncode=0)), patch.object(setup, 'run') as install, redirect_stdout(io.StringIO()):
            setup.ensure_frontend(['npm'], self.root)
            setup.ensure_frontend(['npm'], self.root)
        install.assert_not_called()
        self.assertEqual((self.root/'.tools/frontend-dependencies.sha256').stat().st_uid, os.getuid())

    def test_changed_manifest_requires_lockfile_install_unprivileged(self):
        self.frontend()
        (self.root/'.tools').mkdir()
        (self.root/'.tools/frontend-dependencies.sha256').write_text('outdated')
        with patch.object(setup, 'run') as run, redirect_stdout(io.StringIO()):
            setup.ensure_frontend(['node', '/local/npm-cli.js'], self.root)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn('ci', commands[0])
        self.assertTrue(all('sudo' not in command for command in commands))

    def test_artifacts_must_belong_to_normal_user_without_symlinked_outputs(self):
        (self.root/'build').mkdir()
        (self.root/'build/output').touch()
        setup.check_owned_artifacts(self.root)
        with self.assertRaisesRegex(RuntimeError, 'owned by another user'):
            setup.check_owned_artifacts(self.root, os.getuid()+1)
        (self.root/'.venv').symlink_to(self.root/'build')
        with self.assertRaisesRegex(RuntimeError, 'symlinked'):
            setup.check_owned_artifacts(self.root)

    def test_setup_refuses_root_before_any_changes(self):
        with patch.object(setup.os, 'geteuid', return_value=0), patch.object(sys, 'argv', ['setup_environment.py']), patch.object(setup, 'run') as run, redirect_stderr(io.StringIO()):
            self.assertEqual(setup.main(), 1)
        run.assert_not_called()

    def test_read_only_preflight_does_not_install_or_build(self):
        with patch.object(setup, 'check_platform'), patch.object(setup, 'check_kernel'), patch.object(setup, 'check_owned_artifacts'), \
             patch.object(setup, 'missing_packages', return_value=[]), patch.object(setup, 'run') as run, \
             patch.object(sys, 'argv', ['setup_environment.py', '--check']), redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(), 0)
        run.assert_not_called()

    def test_project_steps_never_run_under_sudo(self):
        python = self.root/'.venv/bin/python'
        with patch.object(setup, 'check_platform'), patch.object(setup, 'check_kernel'), patch.object(setup, 'check_owned_artifacts'), \
             patch.object(setup, 'missing_packages', return_value=[]), patch.object(setup.shutil, 'which', return_value='/usr/bin/tool'), \
             patch.object(setup, 'ensure_venv', return_value=python), patch.object(setup, 'npm_command', return_value=['npm']), \
             patch.object(setup, 'ensure_frontend'), patch.object(setup, 'run') as run, \
             patch.object(sys, 'argv', ['setup_environment.py']), redirect_stdout(io.StringIO()):
            self.assertEqual(setup.main(), 0)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertTrue(all(command[0] != 'sudo' for command in commands))
        pip = next(command for command in commands if 'pip' in command and 'install' in command)
        self.assertEqual(pip[0], str(python))
        self.assertIn([str(python), '-B', 'scripts/validate_config.py'], commands)
