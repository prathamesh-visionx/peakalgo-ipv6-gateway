import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('installer', ROOT / 'scripts/install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

class InstallerTests(unittest.TestCase):
    def test_pool_uses_124_not_64_and_reserves_primary(self):
        pool = installer.pool('2400:6180:100:d0:0:1:a1fd:d001')
        self.assertEqual(len(pool), 15)
        self.assertNotIn('2400:6180:100:d0:0:1:a1fd:d001', pool)
        self.assertIn('2400:6180:100:d0:0:1:a1fd:d000', pool)
        self.assertEqual(pool[-1], '2400:6180:100:d0:0:1:a1fd:d00f')

    def test_netplan_only_adds_addresses_preserving_primary_settings(self):
        data = json.loads(installer.netplan_text('eth0', ['2001:4860::2'], 64))
        self.assertEqual(data['network']['ethernets']['eth0'], {'addresses': ['2001:4860::2/64']})
        with self.assertRaises(ValueError):
            installer.netplan_text('eth0; touch /tmp/bad', [], 64)

    def test_allowlist_cannot_be_open(self):
        self.assertEqual(installer.validate_cidrs('203.0.113.7/32'), ['203.0.113.7/32'])
        for value in ['', '0.0.0.0/0', '::/0', 'bad']:
            with self.assertRaises(ValueError):
                installer.validate_cidrs(value)

    def test_review_decline_stops_and_only_explicit_yes_accepts(self):
        with patch('builtins.input', return_value='y'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit): installer.confirm('Install?')
        with patch('builtins.input', return_value='yes'), contextlib.redirect_stdout(io.StringIO()):
            installer.confirm('Install?')

    def test_env_is_literal_and_permissions_are_required(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'answers.env'
            config.write_text('BACKEND_BASE_URL=https://example.com\nEGRESS_REGISTRATION_TOKEN=$(do-not-execute)\n')
            config.chmod(0o644)
            with self.assertRaises(SystemExit): installer.read_env(config)
            config.chmod(0o600)
            self.assertEqual(installer.read_env(config)['EGRESS_REGISTRATION_TOKEN'], '$(do-not-execute)')

    def test_noninteractive_bootstrap_stops_before_download(self):
        result = subprocess.run(['bash', str(ROOT / 'scripts/bootstrap.sh')], input='', capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('interactive terminal', result.stderr)

    def test_optional_ip_overrides_are_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            config = Path(temp) / 'answers.env'
            config.write_text('PUBLIC_IPV4=143.244.141.199\nPRIMARY_IPV6=2400:6180:100:d0:0:1:a1fd:d001\n')
            config.chmod(0o600)
            answers = installer.read_env(config)
            self.assertEqual(answers['PUBLIC_IPV4'], '143.244.141.199')
            self.assertEqual(answers['PRIMARY_IPV6'], '2400:6180:100:d0:0:1:a1fd:d001')

    def extract(self, entries, bad_checksum=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        archive = Path(temp.name) / 'release.zip'
        with zipfile.ZipFile(archive, 'w') as z:
            for name in ['package.json', 'src/server.js', 'src/protocol.js', 'scripts/install.py', 'systemd/peakalgo-egress.service']:
                z.writestr(name, '{}')
            for name, content, mode in entries:
                entry = zipfile.ZipInfo(name)
                entry.external_attr = mode << 16
                z.writestr(entry, content)
        script = (ROOT / 'scripts/bootstrap.sh').read_text()
        block = script.split("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        digest = '0'*64 if bad_checksum else hashlib.sha256(archive.read_bytes()).hexdigest()
        result = subprocess.run([sys.executable, '-', str(archive), str(Path(temp.name)/'content'), digest], input=block, capture_output=True, text=True)
        return result, Path(temp.name)

    def test_safe_release_extracts_but_checksum_and_traversal_and_symlinks_fail(self):
        good, root = self.extract([])
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue((root / 'content/src/server.js').exists())
        wrong, _ = self.extract([], bad_checksum=True)
        self.assertNotEqual(wrong.returncode, 0)
        for name, mode in [('../escape', 0), ('/tmp/escape', 0), ('src/link', stat.S_IFLNK | 0o777), ('config.json', 0)]:
            bad, root = self.extract([(name, 'outside', mode)])
            self.assertNotEqual(bad.returncode, 0)
            self.assertFalse((root / 'escape').exists())

    def test_matching_network_overlay_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            overlay = Path(temp) / 'overlay.yaml'
            text = installer.netplan_text('eth0', ['2001:4860::2'], 64)
            overlay.write_text(text)
            with patch.object(installer, 'OVERLAY', overlay), patch.object(installer, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                installer.install_network(text, 'abcdef0123456789')
                run.assert_not_called()

    def test_network_decline_makes_no_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            overlay = Path(temp) / 'overlay.yaml'
            with patch.object(installer, 'OVERLAY', overlay), patch.object(installer, 'run') as run, patch('builtins.input', return_value='no'), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit): installer.install_network('{}', 'abcdef0123456789')
                run.assert_not_called()
                self.assertFalse(overlay.exists())

    def test_network_apply_failure_invokes_persistent_rollback(self):
        with tempfile.TemporaryDirectory() as temp:
            overlay = Path(temp) / 'overlay.yaml'
            overlay.write_text('old configuration')
            def fake_run(args, **kwargs):
                if args[:2] == ['netplan', 'generate']:
                    raise subprocess.CalledProcessError(1, args)
            with patch.object(installer, 'ETC', Path(temp)), patch.object(installer, 'OVERLAY', overlay), patch.object(installer, 'run', side_effect=fake_run) as run, patch.object(installer.shutil, 'which', return_value='/usr/sbin/netplan'), patch.object(installer.subprocess, 'run'), patch('builtins.input', return_value='yes'), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(subprocess.CalledProcessError): installer.install_network('{}', 'abcdef0123456789')
                self.assertTrue(any(call.args[0][0] == '/bin/bash' for call in run.call_args_list))
                backups = list((Path(temp) / 'backups').glob('netplan-*.yaml'))
                self.assertEqual(backups[0].read_text(), 'old configuration')

if __name__ == '__main__': unittest.main()
