import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import install
import release_utils
spec = importlib.util.spec_from_file_location('management', ROOT / 'scripts/manage.py')
management = importlib.util.module_from_spec(spec)
spec.loader.exec_module(management)


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {'ipv4': '143.244.141.199', 'port': 8443,
                       'allowedCidrs': ['143.244.141.199/32', '203.0.113.1/32'], 'secret': 'private'}
        self.gateway = self.root / 'config.json'
        self.gateway.write_text(json.dumps(self.config))
        self.gateway.chmod(0o640)
        self.answers = self.root / 'answers.env'
        self.answers.write_text('# keep\nBACKEND_ALLOWED_CIDRS=203.0.113.1/32\nEGRESS_REGISTRATION_TOKEN=private\n')
        self.answers.chmod(0o600)
        self.args = SimpleNamespace(config=str(self.answers), gateway_config=str(self.gateway),
                                    action='set', cidr=['203.0.113.2/32'], yes=True, dry_run=False)

    def test_allowlist_never_opens_all_sources_or_removes_local_health(self):
        target = management.set_allowlist(self.config, 'set', ['203.0.113.2/32'])
        self.assertEqual(target, ['143.244.141.199/32', '203.0.113.2/32'])
        for action, cidrs in [('add', ['0.0.0.0/0']), ('set', []), ('remove', ['143.244.141.199/32'])]:
            with self.assertRaises(ValueError): management.set_allowlist(self.config, action, cidrs)

    def test_acl_updates_app_and_saved_answers_and_only_exact_gateway_firewall_rules(self):
        with patch.object(management, 'snapshot'), patch.object(management, 'run') as run, patch.object(management, 'restart_and_check'), contextlib.redirect_stdout(io.StringIO()) as out:
            management.apply_allowlist(self.args, self.config)
        self.assertEqual(json.loads(self.gateway.read_text())['allowedCidrs'], ['143.244.141.199/32', '203.0.113.2/32'])
        self.assertIn('BACKEND_ALLOWED_CIDRS=203.0.113.2/32', self.answers.read_text())
        self.assertIn('# keep', self.answers.read_text())
        self.assertNotIn('private', out.getvalue())
        self.assertEqual(stat.S_IMODE(self.gateway.stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE(self.answers.stat().st_mode), 0o600)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual(len(commands), 3)
        self.assertTrue(all('8443' in command for command in commands))
        self.assertFalse(any('22' in command for command in commands))

    def test_allowlist_repairs_firewall_drift_even_when_config_already_contains_source(self):
        self.args.action = 'add'
        self.args.cidr = ['203.0.113.1/32']
        with patch.object(management, 'snapshot'), patch.object(management, 'run') as run, patch.object(management, 'restart_and_check'), contextlib.redirect_stdout(io.StringIO()):
            run.return_value.stdout = 'Rule added\n'
            management.apply_allowlist(self.args, self.config)
        self.assertIn(['ufw', 'allow', 'from', '203.0.113.1/32', 'to', 'any', 'port', '8443', 'proto', 'tcp'], [call.args[0] for call in run.call_args_list])

    def test_failed_restart_rolls_back_both_files_and_firewall_deltas(self):
        before = [self.gateway.read_bytes(), self.answers.read_bytes()]
        with patch.object(management, 'snapshot'), patch.object(management, 'run') as run, patch.object(management, 'restart_and_check', side_effect=RuntimeError('health failed')), contextlib.redirect_stdout(io.StringIO()):
            run.return_value.stdout = 'Rule added\nRule deleted\n'
            with self.assertRaises(RuntimeError): management.apply_allowlist(self.args, self.config)
        self.assertEqual([self.gateway.read_bytes(), self.answers.read_bytes()], before)
        commands = [call.args[0] for call in run.call_args_list]
        self.assertIn(['ufw', 'allow', 'from', '203.0.113.1/32', 'to', 'any', 'port', '8443', 'proto', 'tcp'], commands)
        self.assertIn(['ufw', '--force', 'delete', 'allow', 'from', '203.0.113.2/32', 'to', 'any', 'port', '8443', 'proto', 'tcp'], commands)

    def test_rollback_does_not_delete_an_allow_rule_that_already_existed(self):
        self.args.action = 'add'
        with patch.object(management, 'snapshot'), patch.object(management, 'run') as run, patch.object(management, 'restart_and_check', side_effect=RuntimeError('health failed')), contextlib.redirect_stdout(io.StringIO()):
            run.return_value.stdout = 'Skipping adding existing rule\n'
            with self.assertRaises(RuntimeError): management.apply_allowlist(self.args, self.config)
        self.assertFalse(any('delete' in call.args[0] for call in run.call_args_list))

    def test_preview_has_no_firewall_file_or_service_mutations(self):
        before = self.gateway.read_bytes()
        self.args.dry_run = True
        with patch.object(management, 'snapshot') as backup, patch.object(management, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
            management.apply_allowlist(self.args, self.config)
        run.assert_not_called()
        backup.assert_not_called()
        self.assertEqual(self.gateway.read_bytes(), before)

    def test_yes_never_bypasses_network_connectivity_confirmation(self):
        with patch.object(install, 'ASSUME_YES', True), patch.object(install.sys.stdin, 'isatty', return_value=False), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit): install.confirm('Keep network?', force=True)
        with patch.object(install, 'STAGES_APPROVED', True), patch('builtins.input') as prompt, contextlib.redirect_stdout(io.StringIO()):
            install.confirm('Restart service?')
        prompt.assert_not_called()

    def test_root_token_files_are_not_printed_and_public_or_linked_files_fail(self):
        token = self.root / 'token'
        token.write_text('a' * 32 + '\n')
        token.chmod(0o600)
        self.assertEqual(management.update_backend.read_token_file(token), 'a' * 32)
        token.chmod(0o644)
        with self.assertRaises(ValueError): management.update_backend.read_token_file(token)
        token.chmod(0o600)
        link = self.root / 'linked'
        link.symlink_to(token)
        with self.assertRaises(ValueError): management.update_backend.read_token_file(link)

    def archive(self, extra=None):
        archive = self.root / 'release.zip'
        with zipfile.ZipFile(archive, 'w') as bundle:
            for name in ['package.json', 'src/server.js', 'src/protocol.js', 'scripts/install.py', 'scripts/manage.py', 'systemd/peakalgo-egress.service']:
                bundle.writestr(name, '{}')
            if extra:
                info = zipfile.ZipInfo(extra[0])
                info.external_attr = extra[1] << 16
                bundle.writestr(info, 'bad')
        return archive, hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_release_checks_checksum_required_files_traversal_links_and_ambiguous_paths(self):
        archive, digest = self.archive()
        release_utils.extract_release(archive, self.root / 'ok', digest)
        with self.assertRaises(ValueError): release_utils.extract_release(archive, self.root / 'bad', '0' * 64)
        for name, mode in [('../escape', 0), ('src/link', stat.S_IFLNK | 0o777), ('config.json', 0), ('src//server.js', 0), ('src/device', stat.S_IFIFO)]:
            archive, digest = self.archive((name, mode))
            with self.assertRaises(ValueError): release_utils.extract_release(archive, self.root / 'bad', digest)

    def test_failed_source_upgrade_restores_symlink_unit_and_previous(self):
        base = self.root / 'base'
        old, new = base / 'releases/old', base / 'releases/new'
        for release in [old, new]:
            (release / 'systemd').mkdir(parents=True)
        (new / 'systemd/peakalgo-egress.service').write_text('new unit')
        (base / 'current').symlink_to(old)
        unit = self.root / 'service.unit'
        unit.write_text('old unit')
        backup = self.root / 'backup'
        backup.mkdir()
        (backup / 'service.unit').write_text('old unit')
        with patch.object(management, 'BASE', base), patch.object(management, 'UNIT', unit), patch.object(management, 'snapshot', return_value=backup), patch.object(management, 'run'), patch.object(management, 'restart_and_check', side_effect=RuntimeError('health failed')):
            with self.assertRaises(RuntimeError): management.switch_release(new, self.args)
        self.assertEqual((base / 'current').resolve(), old.resolve())
        self.assertEqual(unit.read_text(), 'old unit')
        self.assertFalse((base / 'previous').exists())


if __name__ == '__main__':
    unittest.main()
