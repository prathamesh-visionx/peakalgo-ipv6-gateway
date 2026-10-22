#!/usr/bin/env python3
"""Re-register an installed gateway at a new HTTPS backend without reinstalling it."""
import argparse
import getpass
import json
import os
from pathlib import Path
import tempfile
import urllib.error

from install import backend_origin, confirm, read_env, register

def read_token_file(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_uid != os.geteuid():
        raise ValueError('Token file must be owned by the current user, not a symlink, and mode 600 or stricter')
    token = path.read_text().strip()
    if len(token) < 32 or '\n' in token or '\r' in token:
        raise ValueError('Token file must contain one registration token of at least 32 characters')
    return token

def save_backend_url(path, base_url):
    """Atomically change only BACKEND_BASE_URL, retaining every other answer."""
    path = Path(path)
    original = path.read_text() if path.exists() else ''
    lines = original.splitlines(keepends=True)
    replacement = 'BACKEND_BASE_URL=' + base_url + '\n'
    updated = []
    replaced = False
    for line in lines:
        if line.strip().startswith('BACKEND_BASE_URL='):
            if not replaced:
                updated.append(replacement)
                replaced = True
        else:
            updated.append(line)
    text = ''.join(updated)
    if not replaced:
        text += ('\n' if text and not text.endswith('\n') else '') + replacement
    fd, temporary = tempfile.mkstemp(prefix='.peakalgo-backend-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as target:
            target.write(text)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)

def update_backend(base_url, config_path, gateway_path, token=None, assume_yes=False):
    base_url = backend_origin(base_url)
    config_path, gateway_path = Path(config_path), Path(gateway_path)
    if config_path.is_symlink():
        raise ValueError('Installer configuration must not be a symlink')
    answers = read_env(config_path) if config_path.exists() else {}
    config = json.loads(gateway_path.read_text())
    print('Gateway: ' + config['hostId'])
    print('Previous backend: ' + answers.get('BACKEND_BASE_URL', '(not saved)'))
    print('New backend: ' + base_url)
    print('Reuses the installed identity, certificate, secret and IPv6 pool. Firewall and service are unchanged.')
    print('The destination owns its own MongoDB registration and encryption key. Existing records must decrypt with that key.')
    print('Disable the previous backend gateway before switching independent databases. Assignments are not copied.')
    if not assume_yes:
        confirm('Register this gateway with the new backend and save its URL on success? Host credentials are sent over HTTPS.')
    token = token or answers.get('EGRESS_REGISTRATION_TOKEN') or getpass.getpass('New backend EGRESS_REGISTRATION_TOKEN (hidden): ')
    register(config, base_url, token)
    save_backend_url(config_path, base_url)
    print('Saved BACKEND_BASE_URL in ' + str(config_path) + '. No gateway restart or activation was performed.')
    print('Set the same BACKEND_BASE_URL in the backend environment and update the Kite developer callback/postback URLs.')
    print('Run admin diagnostics before any later activation. A different backend source IP requires a separate allowlist update.')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend-url', required=True, help='New HTTPS backend origin (no path)')
    parser.add_argument('--config', default='/root/peakalgo-egress.env', help='Root-only installer answers and optional registration token; URL saved here after success')
    parser.add_argument('--gateway-config', default='/etc/peakalgo-egress/config.json', help='Existing gateway configuration, read only')
    parser.add_argument('--yes', action='store_true', help='Approve re-registration without an interactive review')
    parser.add_argument('--token-file', help='Private file containing the destination registration token; overrides saved token, never stored or printed')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo; installed host credentials must remain root protected')
    update_backend(args.backend_url, args.config, args.gateway_config,
                   token=read_token_file(args.token_file) if args.token_file else None, assume_yes=args.yes)

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, urllib.error.URLError) as error:
        raise SystemExit('Backend update stopped: ' + str(error))
