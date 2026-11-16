"""Behavior tests: no host commands or host configuration changes are executed."""
import argparse
import contextlib
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import vpsguard as guard


def success(stdout=''):
    return SimpleNamespace(returncode=0, stdout=stdout, stderr='')


class CommandSafetyTests(unittest.TestCase):
    def test_command_failures_never_echo_arguments_or_output(self):
        payload = 'private-command-fixture'
        errors = [subprocess.TimeoutExpired(['tool', payload], 60, output=payload, stderr=payload),
                  OSError(5, payload), UnicodeDecodeError('utf-8', b'\xff', 0, 1, payload)]
        for error in errors:
            with self.subTest(error=type(error).__name__), patch.object(
                    guard.subprocess, 'run', side_effect=error), self.assertRaises(guard.Refusal) as caught:
                guard.run('tool', payload)
            self.assertNotIn(payload, str(caught.exception))
            self.assertIn('[REDACTED]', str(caught.exception))
        result = SimpleNamespace(returncode=1, stdout=payload, stderr=payload)
        with patch.object(guard.subprocess, 'run', return_value=result), self.assertRaises(guard.Refusal) as caught:
            guard.run('tool', payload)
        self.assertNotIn(payload, str(caught.exception))
        self.assertIn('[REDACTED]', str(caught.exception))


class FirewallRuntimeTests(unittest.TestCase):
    rules = ('*filter\n:INPUT DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n'
             ':ufw-before-input - [0:0]\n:ufw-user-input - [0:0]\n'
             '-A INPUT -j ufw-before-input\n'
             '-A ufw-before-input -j ufw-user-input\n'
             '-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\nCOMMIT\n')

    def test_both_families_are_checked_and_counters_do_not_cause_drift(self):
        with patch.object(guard, 'run', side_effect=[
                success('Status: active\n'), success(self.rules), success(self.rules)]) as command:
            before = guard.firewall_state(['tcp:22'])
        self.assertEqual([call.args[0] for call in command.call_args_list],
                         ['ufw', 'iptables-save', 'ip6tables-save'])
        with patch.object(guard, 'run', side_effect=[
                success('Status: active\n'), success(self.rules.replace('[0:0]', '[40:2000]')),
                success(self.rules)]):
            self.assertEqual(guard.firewall_state(['tcp:22']), before)

    def test_active_ufw_cannot_hide_missing_ipv6_rule_policy_or_hook(self):
        invalid = [self.rules.replace(':INPUT DROP', ':INPUT ACCEPT'),
                   self.rules.replace('-A ufw-before-input -j ufw-user-input\n', ''),
                   self.rules.replace('-A ufw-user-input -p tcp -m tcp --dport 22 -j ACCEPT\n', '')]
        for rules in invalid:
            with self.subTest(rules=rules), patch.object(guard, 'run', side_effect=[
                    success('Status: active\n'), success(self.rules), success(rules)]), self.assertRaises(guard.Refusal):
                guard.firewall_state(['tcp:22'])


class PolicyTests(unittest.TestCase):
    def test_port_validation_and_normalization(self):
        self.assertEqual(guard.allow_port('tcp:00022'), 'tcp:22')
        self.assertEqual(guard.allow_port('udp:65535'), 'udp:65535')
        for value in ('tcp:0', 'tcp:65536', 'tcp:22;id', '22', 'TCP:22', 'udp:-1'):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                guard.allow_port(value)

    def test_public_ipv4_ipv6_and_udp_preserved_but_loopback_excluded(self):
        text = ('tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n'
                'tcp LISTEN 0 128 [::]:443 [::]:*\n'
                'udp UNCONN 0 0 192.0.2.1:53 0.0.0.0:*\n'
                'tcp LISTEN 0 128 127.0.0.1:5432 0.0.0.0:*\n'
                'tcp LISTEN 0 128 [::1]:8080 [::]:*\n')
        self.assertEqual(guard.exposed_ports(text), ['tcp:22', 'tcp:443', 'udp:53'])

    def test_unknown_listener_format_is_not_silently_dropped(self):
        for text in ('mystery\n', 'tcp LISTEN 0 128 example.com:22 *:*', 'udp UNCONN 0 0 *:domain *:*'):
            with self.assertRaises(guard.Refusal):
                guard.exposed_ports(text)

    def test_ufw_rules_survive_inventory(self):
        guard.firewall_inventory('*filter\n:INPUT DROP [0:0]\n:ufw-user-input - [0:0]\n'
                                 '-A INPUT -j ufw-user-input\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\nCOMMIT\n')

    def test_docker_and_unmanaged_filtering_refused(self):
        examples = ('*filter\n:DOCKER - [0:0]\nCOMMIT',
                    '*filter\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT',
                    '*nat\n-A POSTROUTING -j MASQUERADE\nCOMMIT',
                    '*filter\n:KUBE-SERVICES - [0:0]\nCOMMIT')
        for text in examples:
            with self.subTest(text=text), self.assertRaises(guard.Refusal):
                guard.firewall_inventory(text)

    def test_hash_independent_of_dictionary_order(self):
        self.assertEqual(guard.digest({'a': 1, 'b': 2}), guard.digest({'b': 2, 'a': 1}))
        self.assertNotEqual(guard.digest({'a': 1}), guard.digest({'a': 2}))

    def test_state_identifier_rejects_traversal(self):
        for value in ('../other', 'a' * 23, 'A' * 24, '/etc/passwd'):
            with self.assertRaises(guard.Refusal):
                guard.transaction_path(value)

    def test_trusted_path_rejects_symlink_writable_and_nonroot(self):
        good_dir = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        bad = (SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0),
               SimpleNamespace(st_mode=stat.S_IFREG | 0o666, st_uid=0),
               SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000))
        for info in bad:
            with patch.object(Path, 'lstat', side_effect=[good_dir, good_dir, info]), self.assertRaises(guard.Refusal):
                guard.trusted(Path('/safe/file'))

    def test_automatic_updates_are_security_only_without_reboot(self):
        self.assertIn('#clear Unattended-Upgrade::Origins-Pattern;', guard.APT_TEXT)
        self.assertIn('"Ubuntu:noble-security"', guard.APT_TEXT)
        self.assertNotIn('"Ubuntu:noble-updates"', guard.APT_TEXT)
        self.assertIn('Automatic-Reboot "false"', guard.APT_TEXT)
        self.assertIn('Automatic-Reboot-WithUsers "false"', guard.APT_TEXT)

    def test_plan_cli_requires_explicit_service_allowlist(self):
        with patch('sys.stderr'), self.assertRaises(SystemExit):
            guard.parser().parse_args(['plan'])
        arguments = guard.parser().parse_args(['apply', '--allow', 'tcp:22', '--approve', 'abc'])
        self.assertEqual(arguments.rollback_minutes, 5)


class AccessProofTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(guard, 'require_root'))
        self.stack.enter_context(patch.dict(os.environ, {'SUDO_USER': 'alice', 'SUDO_UID': '1000',
                                                        'SSH_CONNECTION': '198.51.100.8 54321 192.0.2.8 22'}, clear=True))
        self.stack.enter_context(patch.object(guard.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=1000)))
        self.stack.enter_context(patch.object(guard.os, 'getppid', return_value=30))
        self.stack.enter_context(patch.object(guard.time, 'time', return_value=200.0))
        self.stack.enter_context(patch.object(Path, 'read_text', autospec=True, side_effect=self.process_text))
        self.command = Mock(return_value=success())
        self.stack.enter_context(patch.object(guard, 'run', side_effect=lambda *args, **kwargs:
                                             success('10\n') if args[0] == 'systemctl' else self.command(*args, **kwargs)))

    @staticmethod
    def process_text(path):
        contents = {'/proc/30/comm': 'sudo\n', '/proc/30/status': 'PPid:\t20\n',
                    '/proc/20/comm': 'sshd\n', '/proc/20/status': 'PPid:\t10\n',
                    '/proc/10/comm': 'sshd\n', '/proc/10/status': 'PPid:\t1\n'}
        return contents[str(path)]

    @staticmethod
    def event(message='Accepted publickey for alice from 198.51.100.8 port 54321 ssh2: ED25519 SHA256:test', timestamp=150):
        return json.dumps({'MESSAGE': message, '__REALTIME_TIMESTAMP': str(timestamp * 1_000_000)}) + '\n'

    def test_recent_public_key_event_bound_to_current_session(self):
        self.command.return_value = success(self.event())
        proof = guard.prove_access(100)
        self.assertEqual((proof['uid'], proof['server_port'], proof['login_at']), (1000, 22, 150))

    def test_password_login_wrong_source_and_stale_log_cannot_prove_access(self):
        events = (self.event('Accepted password for alice from 198.51.100.8 port 54321 ssh2'),
                  self.event('Accepted publickey for alice from 198.51.100.9 port 54321 ssh2: ED25519 key'),
                  self.event(timestamp=99), self.event(timestamp=201), '')
        for event in events:
            self.command.return_value = success(event)
            with self.subTest(event=event), self.assertRaises(guard.Refusal):
                guard.prove_access(100)

    def test_missing_journal_is_not_success(self):
        self.command.side_effect = guard.Refusal('journal unavailable')
        with self.assertRaises(guard.Refusal):
            guard.prove_access(100)

    def test_root_or_loopback_session_is_not_accepted(self):
        with patch.dict(os.environ, {'SUDO_UID': '0'}), self.assertRaises(guard.Refusal):
            guard.prove_access(100)
        with patch.dict(os.environ, {'SSH_CONNECTION': '127.0.0.1 54321 127.0.0.1 22'}), self.assertRaises(guard.Refusal):
            guard.prove_access(100)

    def test_no_sshd_ancestry_is_refused_even_with_a_matching_log(self):
        self.command.return_value = success(self.event())
        with patch.object(guard.os, 'getppid', return_value=1), self.assertRaises(guard.Refusal):
            guard.prove_access(100)

    def test_unmanaged_sshd_cannot_prove_managed_service_access(self):
        with patch.object(guard, 'run', return_value=success('999\n')), self.assertRaises(guard.Refusal):
            guard.prove_access(100)


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.plan = {'digest': 'approved', 'allow': ['tcp:22'], 'ssh_port': 22, 'files': {}, 'ufw_active': True}
        self.state = {'version': 1, 'id': 'a' * 24, 'status': 'awaiting_access', 'created_at': 100,
                      'plan': self.plan, 'proof': {'verified_at': 190, 'uid': 1000},
                      'deadline': 500, 'changed_at': 180, 'applied_files': {}, 'applied_firewall': {}}
        self.stack.enter_context(patch.object(guard, 'locked', side_effect=contextlib.nullcontext))
        self.stack.enter_context(patch.object(guard, 'preflight', return_value=self.plan))
        self.stack.enter_context(patch.object(guard, 'load_state', side_effect=lambda *args: self.state))
        self.saved = []
        self.stack.enter_context(patch.object(guard, 'save_state', side_effect=lambda state: self.saved.append(copy.deepcopy(state))))
        self.stack.enter_context(patch.object(guard.time, 'time', return_value=200))
        self.stack.enter_context(patch.object(guard, 'snapshot', return_value={}))
        self.commands = self.stack.enter_context(patch.object(guard, 'run', return_value=success('Status: active\n')))
        self.arm = self.stack.enter_context(patch.object(guard, 'arm_rollback'))
        self.change = self.stack.enter_context(patch.object(guard, 'change_configuration'))
        self.restore = self.stack.enter_context(patch.object(guard, 'restore_configuration'))
        self.disarm = self.stack.enter_context(patch.object(guard, 'disarm_rollback'))
        self.stack.enter_context(patch.object(guard, 'validate_effective'))
        self.backups = self.stack.enter_context(patch.object(guard, 'validate_backups'))
        self.firewall = self.stack.enter_context(patch.object(guard, 'firewall_state', return_value={}))
        self.prove = self.stack.enter_context(patch.object(guard, 'prove_access', return_value={'uid': 1000, 'server_port': 22}))

    def test_approval_mismatch_changes_nothing(self):
        with self.assertRaises(guard.Refusal):
            guard.apply_plan(['tcp:22'], 'stale', 5)
        self.assertEqual(self.saved, [])
        self.change.assert_not_called()
        self.arm.assert_not_called()

    def test_unproved_preparation_never_arms_or_changes_configuration(self):
        self.state.pop('proof')
        result = guard.apply_plan(['tcp:22'], 'approved', 5)
        self.assertEqual(result['status'], 'awaiting_access')
        self.assertFalse(result['changed'])
        self.change.assert_not_called()
        self.arm.assert_not_called()

    def test_expired_proof_requires_another_new_connection(self):
        self.state['proof']['verified_at'] = -1000
        with self.assertRaises(guard.Refusal):
            guard.apply_plan(['tcp:22'], 'approved', 5)
        self.assertNotIn('proof', self.state)
        self.assertEqual(self.state['created_at'], 200)
        self.change.assert_not_called()

    def test_rollback_is_armed_before_any_change(self):
        events = []
        self.arm.side_effect = lambda state: events.append(('armed', state['status']))
        self.change.side_effect = lambda state: events.append(('changed', state['status']))
        result = guard.apply_plan(['tcp:22'], 'approved', 5)
        self.assertEqual(events, [('armed', 'arming'), ('changed', 'applying')])
        self.assertEqual(result['status'], 'applied')
        self.assertEqual(result['rollback_at'], 500)
        self.disarm.assert_not_called()

    def test_timer_failure_prevents_changes(self):
        self.arm.side_effect = guard.Refusal('timer failed')
        with self.assertRaises(guard.Refusal):
            guard.apply_plan(['tcp:22'], 'approved', 5)
        self.change.assert_not_called()
        self.assertEqual(self.state['status'], 'rolled_back')
        self.restore.assert_not_called()
        self.disarm.assert_called_once()

    def test_change_failure_restores_before_disarming(self):
        events = []
        self.change.side_effect = guard.Refusal('ufw failed')
        self.restore.side_effect = lambda state: events.append('restored')
        self.disarm.side_effect = lambda state: events.append('disarmed')
        with self.assertRaisesRegex(guard.Refusal, 'rolled back'):
            guard.apply_plan(['tcp:22'], 'approved', 5)
        self.assertEqual(events, ['restored', 'disarmed'])
        self.assertEqual(self.state['status'], 'rolled_back')

    def test_restore_failure_retains_retry_and_does_not_claim_success(self):
        self.state['status'] = 'applied'
        self.restore.side_effect = guard.Refusal('bad backup')
        with self.assertRaisesRegex(guard.Refusal, 'console'):
            guard.rollback_locked(self.state)
        self.assertEqual(self.state['status'], 'rollback_failed')
        self.disarm.assert_not_called()

    def test_confirm_requires_post_change_proof(self):
        self.state['status'] = 'applied'
        self.prove.side_effect = guard.Refusal('old connection')
        with self.assertRaises(guard.Refusal):
            guard.confirm(self.state['id'])
        self.assertEqual(self.state['status'], 'applied')
        self.disarm.assert_not_called()

    def test_wrong_sudo_user_cannot_confirm(self):
        self.state['status'] = 'applied'
        self.prove.return_value = {'uid': 1001, 'server_port': 22}
        with self.assertRaises(guard.Refusal):
            guard.confirm(self.state['id'])
        self.disarm.assert_not_called()

    def test_expired_confirmation_restores_instead_of_committing(self):
        self.state['status'] = 'applied'
        self.state['deadline'] = 199
        with self.assertRaisesRegex(guard.Refusal, 'elapsed'):
            guard.confirm(self.state['id'])
        self.assertEqual(self.state['status'], 'rolled_back')
        self.restore.assert_called_once()
        self.prove.assert_not_called()

    def test_confirm_saves_terminal_state_before_disarming(self):
        self.state['status'] = 'applied'
        self.disarm.side_effect = lambda state: self.assertEqual(self.saved[-1]['status'], 'confirmed')
        self.assertEqual(guard.confirm(self.state['id'])['status'], 'confirmed')

    def test_external_edit_leaves_rollback_armed(self):
        self.state['status'] = 'applied'
        with patch.object(guard, 'snapshot', return_value={'changed': True}), self.assertRaises(guard.Refusal):
            guard.confirm(self.state['id'])
        self.disarm.assert_not_called()

    def test_terminal_transaction_never_restores_again(self):
        for status in ('confirmed', 'rolled_back'):
            self.state['status'] = status
            self.assertEqual(guard.rollback_locked(self.state)['status'], status)
        self.restore.assert_not_called()


    def test_backup_corruption_blocks_apply_before_timer_or_changes(self):
        self.backups.side_effect = guard.Refusal('Corrupt backup')
        with self.assertRaisesRegex(guard.Refusal, 'Corrupt backup'):
            guard.apply_plan(['tcp:22'], 'approved', 5)
        self.arm.assert_not_called()
        self.change.assert_not_called()
        self.restore.assert_not_called()

    def test_drift_before_and_during_arming_never_restores_or_overwrites(self):
        for snapshots in ([{'drift': True}], [{}, {'drift': True}]):
            self.state['status'] = 'awaiting_access'
            with patch.object(guard, 'snapshot', side_effect=snapshots), self.assertRaises(guard.Refusal):
                guard.apply_plan(['tcp:22'], 'approved', 5)
            self.change.assert_not_called()
            self.restore.assert_not_called()

    def test_interrupt_during_apply_immediately_restores(self):
        self.change.side_effect = KeyboardInterrupt()
        with self.assertRaisesRegex(guard.Refusal, 'rolled back'):
            guard.apply_plan(['tcp:22'], 'approved', 5)
        self.restore.assert_called_once()
        self.assertEqual(self.state['status'], 'rolled_back')

    def test_interrupted_restore_retains_retry_and_reports_failure(self):
        self.state['status'] = 'applied'
        self.restore.side_effect = KeyboardInterrupt()
        with self.assertRaisesRegex(guard.Refusal, 'console'):
            guard.rollback_locked(self.state)
        self.assertEqual(self.state['status'], 'rollback_failed')
        self.disarm.assert_not_called()

    def test_scheduled_rollback_of_arming_never_restores(self):
        self.state['status'] = 'arming'
        result = guard.rollback_locked(self.state)
        self.assertFalse(result['changed'])
        self.restore.assert_not_called()

    def test_live_firewall_drift_prevents_confirmation(self):
        self.state['status'] = 'applied'
        self.firewall.return_value = {'ip6tables-save': ['changed']}
        with self.assertRaisesRegex(guard.Refusal, 'Live firewall changed'):
            guard.confirm(self.state['id'])
        self.disarm.assert_not_called()
        self.assertEqual(self.state['status'], 'applied')


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.state_dir = self.root / 'state'
        self.state_dir.mkdir(mode=0o700)
        self.units = self.root / 'units'
        self.units.mkdir()
        self.ssh_dir = self.root / 'ssh.d'
        self.ssh_dir.mkdir()
        self.ssh = self.root / 'sshd_config'
        self.ssh.write_text('Include /etc/ssh/sshd_config.d/*.conf\nUsePAM yes\n')
        self.drop = self.ssh_dir / '00-vpsguard.conf'
        self.original = self.ssh_dir / '50-original.conf'
        self.original.write_text('PasswordAuthentication yes\n')
        self.apt = self.root / 'apt-drop'
        self.targets = (self.ssh, self.ssh_dir, self.apt)
        for name, value in (('STATE', self.state_dir), ('UNITS', self.units), ('SSH_MAIN', self.ssh),
                            ('SSH_DIR', self.ssh_dir), ('SSH_DROP', self.drop), ('APT_DROP', self.apt),
                            ('TARGETS', self.targets)):
            self.stack.enter_context(patch.object(guard, name, value))
        # Ownership checks are covered independently; sandbox files belong to the test user.
        self.stack.enter_context(patch.object(guard, 'trusted', side_effect=lambda path, directory=False: Path(path).exists()))
        self.stack.enter_context(patch.object(guard, 'run', return_value=success('Status: active\n')))
        self.stack.enter_context(patch.object(guard, 'firewall_snapshot', return_value={}))
        self.state = {'id': 'b' * 24, 'version': 1, 'status': 'applied', 'deadline': 2_000_000_000,
                      'plan': {'files': guard.snapshot(), 'ufw_active': True, 'firewall': {}}}
        self.state['plan']['digest'] = guard.digest(self.state['plan'])
        guard.backup(self.state['plan'], self.state['id'])

    def test_backup_refuses_changed_bytes_and_new_files(self):
        self.original.write_text('drift\n')
        with self.assertRaisesRegex(guard.Refusal, 'changed during backup'):
            guard.backup(self.state['plan'], 'c' * 24)
        self.original.write_text('PasswordAuthentication yes\n')
        self.drop.write_text('new configuration\n')
        with self.assertRaisesRegex(guard.Refusal, 'changed during backup'):
            guard.backup(self.state['plan'], 'd' * 24)

    def test_partial_manifest_cannot_delete_original_files(self):
        del self.state['plan']['files'][str(self.original)]
        self.original.write_text('live change\n')
        with self.assertRaisesRegex(guard.Refusal, 'Corrupt backup plan'):
            guard.restore_configuration(self.state)
        self.assertEqual(self.original.read_text(), 'live change\n')

    def test_manifest_path_traversal_refused_before_restore(self):
        name = str(self.ssh_dir) + '/../outside'
        self.state['plan']['files'][name] = {'kind': 'absent'}
        self.state['plan'].pop('digest')
        self.state['plan']['digest'] = guard.digest(self.state['plan'])
        with self.assertRaisesRegex(guard.Refusal, 'Invalid backup manifest'):
            guard.restore_configuration(self.state)

    def test_corrupt_state_is_refused_without_restoring(self):
        path = guard.transaction_path(self.state['id']) / 'state.json'
        malformed = ['[]', '{', json.dumps(dict(self.state, status='unknown'))]
        for value in malformed:
            path.write_text(value)
            with self.subTest(value=value), self.assertRaises(guard.Refusal):
                guard.load_state(self.state['id'])

    def test_recovery_drift_and_fsync_failure_never_report_success(self):
        with patch.object(guard.os, 'chown'), patch.object(guard, 'snapshot', side_effect=[
                self.state['plan']['files'], {}]), self.assertRaisesRegex(guard.Refusal, 'differs'):
            guard.restore_configuration(self.state)
        with patch.object(guard.os, 'fsync', side_effect=OSError('disk failure')), self.assertRaises(OSError):
            guard.restore_configuration(self.state)

    def test_recovery_runtime_drift_never_reports_success(self):
        with patch.object(guard.os, 'chown'), patch.object(guard, 'firewall_snapshot', return_value={
                'ip6tables-save': ['changed']}), self.assertRaisesRegex(guard.Refusal, 'Restored live firewall'):
            guard.restore_configuration(self.state)

    def test_backup_detects_corruption_before_any_restore_write(self):
        name = str(self.original)
        backup = guard.transaction_path(self.state['id']) / 'backup' / hashlib.sha256(name.encode()).hexdigest()
        backup.write_bytes(b'corrupt')
        self.original.write_text('live change\n')
        with self.assertRaisesRegex(guard.Refusal, 'Corrupt backup'):
            guard.restore_configuration(self.state)
        self.assertEqual(self.original.read_text(), 'live change\n')

    def test_restore_recovers_original_and_removes_new_dropins(self):
        self.original.write_text('changed\n')
        self.drop.write_text(guard.SSH_TEXT)
        self.apt.write_text(guard.APT_TEXT)
        with patch.object(guard.os, 'chown'):
            guard.restore_configuration(self.state)
        self.assertEqual(self.original.read_text(), 'PasswordAuthentication yes\n')
        self.assertFalse(self.drop.exists())
        self.assertFalse(self.apt.exists())
        self.assertEqual(guard.snapshot(), self.state['plan']['files'])

    def test_durable_state_is_atomic_and_private(self):
        guard.save_state(self.state)
        loaded = guard.load_state(self.state['id'])
        self.assertEqual(loaded, self.state)
        path = guard.transaction_path(self.state['id']) / 'state.json'
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(list(path.parent.glob('.state.json.*')))

    def test_runner_is_a_private_independent_copy(self):
        runner = guard.transaction_path(self.state['id']) / 'runner.py'
        self.assertEqual(runner.read_bytes(), Path(guard.__file__).read_bytes())
        self.assertEqual(stat.S_IMODE(runner.stat().st_mode), 0o600)

    def test_timer_persists_and_uses_backup_runner_not_original_source(self):
        with patch.object(guard, 'run', return_value=success('2033-05-18 03:33:20 UTC')):
            guard.arm_rollback(self.state)
        name = guard.unit_name(self.state)
        timer = (self.units / (name + '.timer')).read_text()
        service = (self.units / (name + '.service')).read_text()
        self.assertIn('Persistent=true', timer)
        self.assertIn('OnCalendar=', timer)
        self.assertIn(str(guard.transaction_path(self.state['id']) / 'runner.py'), service)
        self.assertNotIn(guard.__file__, service)
        self.assertIn('Restart=on-failure', service)

    def test_lock_excludes_concurrent_mutation(self):
        with patch.object(guard, 'require_root'):
            with guard.locked():
                with self.assertRaisesRegex(guard.Refusal, 'Another vpsguard'):
                    with guard.locked():
                        self.fail('second lock acquired')


if __name__ == '__main__':
    unittest.main()
