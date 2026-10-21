import contextlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import install
spec = importlib.util.spec_from_file_location('update_backend', ROOT / 'scripts/update-backend.py')
update = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update)

class BackendUpdateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.answers = self.root / 'answers.env'
        self.answers.write_text('# Keep this comment\nBACKEND_BASE_URL=https://old.example\nBACKEND_ALLOWED_CIDRS=203.0.113.7/32\nEGRESS_REGISTRATION_TOKEN=' + 'a' * 32 + '\nPUBLIC_IPV4=143.244.141.199\n')
        self.answers.chmod(0o600)
        self.cert = self.root / 'gateway.pem'
        self.cert.write_text('existing pinned certificate')
        self.gateway = self.root / 'config.json'
        self.identity = {'hostId': 'do-test', 'ipv4': '143.244.141.199', 'port': 8443,
            'secret': 'b' * 64, 'primaryIpv6': '2400:6180:100:d0:0:1:a1fd:d001',
            'addresses': ['2400:6180:100:d0:0:1:a1fd:d000'],
            'allowedCidrs': ['203.0.113.7/32'], 'certPath': str(self.cert)}
        self.gateway.write_text(json.dumps(self.identity))

    def test_origin_validation_normalizes_slash_and_rejects_ambiguous_destinations(self):
        self.assertEqual(install.backend_origin('https://api.example:8443/'), 'https://api.example:8443')
        for value in ['http://api.example', 'https://user:pass@api.example', 'https://api.example/path',
                'https://api.example?token=x', 'https://api.example#x', 'https://api.example?',
                'https://api.example:bad', 'https://api.example:0', 'https://api.example\n',
                'https://api.example\\@other.example', 'https://']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                install.backend_origin(value)

    def test_success_reuses_identity_and_changes_only_saved_url(self):
        before = self.gateway.read_bytes()
        answers_before = self.answers.read_text()
        with patch.object(update, 'register') as register, contextlib.redirect_stdout(io.StringIO()) as output:
            update.update_backend('https://new.example/', self.answers, self.gateway, assume_yes=True)
        register.assert_called_once_with(self.identity, 'https://new.example', 'a' * 32)
        self.assertEqual(self.gateway.read_bytes(), before)
        self.assertEqual(self.answers.read_text(), answers_before.replace('https://old.example', 'https://new.example'))
        self.assertEqual(stat.S_IMODE(self.answers.stat().st_mode), 0o600)
        self.assertNotIn('b' * 64, output.getvalue())
        self.assertNotIn('a' * 32, output.getvalue())

    def test_failed_registration_preserves_all_files(self):
        before = {p: p.read_bytes() for p in [self.answers, self.gateway, self.cert]}
        with patch.object(update, 'register', side_effect=urllib.error.URLError('unreachable')), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(urllib.error.URLError):
                update.update_backend('https://new.example', self.answers, self.gateway, assume_yes=True)
        for p, content in before.items():
            self.assertEqual(p.read_bytes(), content)

    def test_declining_review_does_not_register_or_write(self):
        before = self.answers.read_bytes()
        with patch.object(update, 'register') as register, patch('builtins.input', return_value='no'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                update.update_backend('https://new.example', self.answers, self.gateway)
        register.assert_not_called()
        self.assertEqual(self.answers.read_bytes(), before)

    def test_insecure_answers_and_symlinks_are_rejected_before_registration(self):
        self.answers.chmod(0o644)
        with patch.object(update, 'register') as register:
            with self.assertRaises(SystemExit):
                update.update_backend('https://new.example', self.answers, self.gateway, assume_yes=True)
            self.answers.chmod(0o600)
            link = self.root / 'linked.env'
            link.symlink_to(self.answers)
            with self.assertRaises(ValueError):
                update.update_backend('https://new.example', link, self.gateway, assume_yes=True)
        register.assert_not_called()

    def test_missing_answers_creates_private_url_file_without_prompted_token(self):
        self.answers.unlink()
        with patch.object(update, 'register'), patch.object(update.getpass, 'getpass', return_value='c' * 32), contextlib.redirect_stdout(io.StringIO()):
            update.update_backend('https://new.example', self.answers, self.gateway, assume_yes=True)
        self.assertEqual(self.answers.read_text(), 'BACKEND_BASE_URL=https://new.example\n')
        self.assertEqual(stat.S_IMODE(self.answers.stat().st_mode), 0o600)

    def test_registration_sends_exact_identity_and_requires_matching_acknowledgement(self):
        good = {'success': True, 'data': {'registered': True, 'hostId': 'do-test'}}
        with patch.object(install.urllib.request, 'build_opener') as factory, contextlib.redirect_stdout(io.StringIO()):
            response = factory.return_value.open.return_value.__enter__.return_value
            response.read.return_value = json.dumps(good).encode()
            install.register(self.identity, 'https://new.example/', 'a' * 32)
            request = factory.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, 'https://new.example/api/egress/register')
            self.assertEqual(request.get_header('Authorization'), 'Bearer ' + 'a' * 32)
            payload = json.loads(request.data)
            self.assertEqual(payload['secret'], self.identity['secret'])
            self.assertEqual(payload['certificatePem'], self.cert.read_text())
            self.assertNotIn('enabled', payload)
            self.assertIsInstance(factory.call_args.args[0], install.NoRegistrationRedirect)
            for bad in [{'success': False}, {'success': True, 'data': {'registered': True, 'hostId': 'other'}}, {'success': True}]:
                response.read.return_value = json.dumps(bad).encode()
                with self.assertRaises(SystemExit):
                    install.register(self.identity, 'https://new.example', 'a' * 32)

    def test_redirect_is_not_followed(self):
        request = urllib.request.Request('https://new.example/api/egress/register', data=b'private', headers={'Authorization': 'Bearer secret'})
        opener = urllib.request.build_opener(install.NoRegistrationRedirect())
        # Exercise the complete error-handler chain, including the default HTTP error.
        with self.assertRaises(urllib.error.HTTPError):
            opener.error('http', request, io.BytesIO(b''), 302, 'Found', {'location': 'https://other.example/leak'})

    def test_replace_failure_leaves_original_answers_and_cleans_temporary_file(self):
        before = self.answers.read_bytes()
        with patch.object(update.os, 'replace', side_effect=OSError('disk failure')):
            with self.assertRaises(OSError):
                update.save_backend_url(self.answers, 'https://new.example')
        self.assertEqual(self.answers.read_bytes(), before)
        self.assertEqual(list(self.root.glob('.peakalgo-backend-*')), [])

if __name__ == '__main__':
    unittest.main()
