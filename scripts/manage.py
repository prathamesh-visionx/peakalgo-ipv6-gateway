#!/usr/bin/env python3
"""Manage an installed PeakAlgo gateway without repeating network installation.

Examples:
  peakalgo-egress status
  peakalgo-egress backend set --url https://api.example --token-file /root/prod.token --yes
  peakalgo-egress allowlist add --cidr 203.0.113.7/32 --yes
  peakalgo-egress release install --archive /root/release.zip --sha256 HEX --yes
  peakalgo-egress diagnostics --full

Use COMMAND --help for options. Mutations show one review; --yes skips it.
Backend Mongo reset is deliberately a separate server-local tool: reset-registration.cjs.
"""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import tempfile
import time

from install import backend_origin, confirm, read_env, validate_cidrs
from release_utils import extract_release

spec = importlib.util.spec_from_file_location('update_backend', Path(__file__).with_name('update-backend.py'))
update_backend = importlib.util.module_from_spec(spec)
spec.loader.exec_module(update_backend)
BASE = Path('/opt/peakalgo-egress')
ETC = Path('/etc/peakalgo-egress')
UNIT = Path('/etc/systemd/system/peakalgo-egress.service')
BACKUPS = Path('/var/backups/peakalgo-egress')
SERVICE = 'peakalgo-egress'
LAUNCHER = Path('/usr/local/bin/peakalgo-egress')


def atomic_write(path, contents, default_mode=0o600):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing to replace a symlink: ' + str(path))
    previous = path.stat() if path.exists() else None
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as target:
            if previous:
                os.fchown(target.fileno(), previous.st_uid, previous.st_gid)
            os.fchmod(target.fileno(), previous.st_mode & 0o777 if previous else default_mode)
            target.write(contents)
            target.flush()
            os.fsync(target.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def save_answer(path, key, value):
    path = Path(path)
    if path.exists():
        read_env(path)
    # Validate permissions before replacing. Preserve comments and unrelated answers.
    lines = path.read_text().splitlines() if path.exists() else []
    lines = [line for line in lines if not line.strip().startswith(key + '=')]
    lines.append(key + '=' + value)
    atomic_write(path, '\n'.join(lines) + '\n')


def snapshot(answers_path):
    BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
    BACKUPS.chmod(0o700)
    destination = BACKUPS / str(time.time_ns())
    destination.mkdir(mode=0o700)
    shutil.copytree(ETC, destination / 'config')
    if Path(answers_path).exists():
        shutil.copy2(answers_path, destination / 'answers.env')
        (destination / 'answers.env').chmod(0o600)
    if UNIT.exists():
        shutil.copy2(UNIT, destination / 'service.unit')
    (destination / 'release.txt').write_text(str((BASE / 'current').resolve()) + '\n')
    print('Private backup: ' + str(destination))
    return destination


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def approve(args, description):
    print(description)
    if args.dry_run:
        print('Preview only; nothing changed.')
        return False
    if not args.yes:
        confirm('Apply this change?')
    return True


def read_config(path):
    path = Path(path)
    if path.is_symlink() or path.stat().st_mode & 0o007 or path.stat().st_uid != 0:
        raise ValueError('Gateway configuration must be root-owned and inaccessible to other users')
    return json.loads(path.read_text())


def set_allowlist(config, action, requested):
    requested = validate_cidrs(','.join(requested))
    local = config['ipv4'] + '/32'
    current = set(config['allowedCidrs'])
    if action == 'add':
        result = current | set(requested)
    elif action == 'remove':
        if local in requested:
            raise ValueError('Cannot remove the gateway self-address used by local authenticated health checks')
        result = current - set(requested)
    else:
        result = set(requested)
    return sorted(result | {local})


def apply_allowlist(args, config):
    target = set_allowlist(config, args.action, args.cidr)
    print('Current sources: ' + ', '.join(config['allowedCidrs']))
    if not approve(args, 'New sources: ' + ', '.join(target) + '\nUpdates application ACL, matching UFW rules and saved installer answers; restarts gateway tunnels.'):
        return
    old_config = Path(args.gateway_config).read_text()
    old_answers = Path(args.config).read_text() if Path(args.config).exists() else None
    # Validate the answers file before any firewall change.
    if old_answers is not None:
        read_env(args.config)
    snapshot(args.config)
    old = set(config['allowedCidrs'])
    # Reconcile every desired rule, including config entries previously edited by
    # hand without matching UFW changes. UFW safely skips already-present rules.
    desired, removed = sorted(set(target)), sorted(old - set(target))
    completed_adds, completed_removes = [], []
    try:
        for cidr in desired:
            result = run(['ufw', 'allow', 'from', cidr, 'to', 'any', 'port', str(config['port']), 'proto', 'tcp'],
                         capture_output=True, text=True, env={**os.environ, 'LC_ALL': 'C'})
            if 'Rule added' in result.stdout:
                completed_adds.append(cidr)
        config['allowedCidrs'] = target
        atomic_write(args.gateway_config, json.dumps(config, indent=2) + '\n')
        save_answer(args.config, 'BACKEND_ALLOWED_CIDRS', ','.join(x for x in target if x != config['ipv4'] + '/32'))
        for cidr in removed:
            result = run(['ufw', '--force', 'delete', 'allow', 'from', cidr, 'to', 'any', 'port', str(config['port']), 'proto', 'tcp'],
                         capture_output=True, text=True, env={**os.environ, 'LC_ALL': 'C'})
            if 'Rule deleted' in result.stdout:
                completed_removes.append(cidr)
        restart_and_check()
    except BaseException:
        atomic_write(args.gateway_config, old_config)
        if old_answers is not None:
            atomic_write(args.config, old_answers)
        else:
            Path(args.config).unlink(missing_ok=True)
        for cidr in completed_removes:
            run(['ufw', 'allow', 'from', cidr, 'to', 'any', 'port', str(config['port']), 'proto', 'tcp'])
        for cidr in completed_adds:
            run(['ufw', '--force', 'delete', 'allow', 'from', cidr, 'to', 'any', 'port', str(config['port']), 'proto', 'tcp'])
        run(['systemctl', 'restart', SERVICE])
        raise
    print('Allowlist updated. Check any provider Cloud Firewall separately. SSH rules were preserved.')


def restart_and_check():
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'restart', SERVICE])
    # Bounded readiness check: local signed health only, no broker/network diagnostics.
    for _ in range(15):
        probe = subprocess.run([str(BASE / 'node/bin/node'), str(BASE / 'current/scripts/diagnostics.js'), '--health', '--json'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
        active = subprocess.run(['systemctl', 'is-active', '--quiet', SERVICE]).returncode == 0
        if probe.returncode == 0 and active:
            return
        time.sleep(0.3)
    raise RuntimeError('Gateway failed local authenticated health after restart')


def switch_release(release, args):
    current, previous = BASE / 'current', BASE / 'previous'
    original = current.resolve()
    if original == release:
        print('This release is already active.')
        return
    backup = snapshot(args.config)
    temporary = BASE / 'current.next'
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(release)
    temporary.replace(current)
    try:
        shutil.copy2(release / 'systemd/peakalgo-egress.service', UNIT)
        restart_and_check()
    except BaseException:
        temporary.symlink_to(original)
        temporary.replace(current)
        shutil.copy2(backup / 'service.unit', UNIT)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'restart', SERVICE])
        raise
    temporary = BASE / 'previous.next'
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(original)
    temporary.replace(previous)
    atomic_write(LAUNCHER, '#!/bin/sh\nexec python3 /opt/peakalgo-egress/current/scripts/manage.py "$@"\n', default_mode=0o755)
    LAUNCHER.chmod(0o755)
    print('Active release: ' + str(release))


def release_command(args):
    if args.action == 'rollback':
        previous = BASE / 'previous'
        if not previous.is_symlink() or not previous.resolve().is_relative_to(BASE / 'releases'):
            raise ValueError('No managed previous release is available')
        target = previous.resolve()
        if approve(args, 'Rollback source to ' + str(target) + '; preserves identity, network and config, restarts tunnels.'):
            switch_release(target, args)
        return
    with tempfile.TemporaryDirectory(prefix='peakalgo-verified-') as stage:
        content = Path(stage) / 'content'
        digest = extract_release(args.archive, content, args.sha256)
        version = json.loads((content / 'package.json').read_text())['version']
        target = BASE / 'releases' / digest[:16]
        if not approve(args, 'Install verified release v' + version + ' (' + digest[:16] + '); preserves TLS identity, secret, IPv6 and networking. Restarts tunnels.'):
            return
        if target.exists():
            # Content-addressed releases are immutable; never use an unchecked pre-existing directory.
            if target.is_symlink() or any(entry.is_symlink() for entry in target.rglob('*')):
                raise ValueError('Existing release contains a symlink')
            expected_files = {entry.relative_to(content) for entry in content.rglob('*') if entry.is_file()}
            if {entry.relative_to(target) for entry in target.rglob('*') if entry.is_file() and '__pycache__' not in entry.parts} != expected_files:
                raise ValueError('Existing release has extra or missing files')
            for entry in content.rglob('*'):
                if entry.is_file():
                    existing = target / entry.relative_to(content)
                    if existing.is_symlink() or not existing.is_file() or existing.read_bytes() != entry.read_bytes():
                        raise ValueError('Existing release contents differ; refusing upgrade')
        else:
            shutil.copytree(content, target)
            for entry in [target, *target.rglob('*')]:
                entry.chmod(0o755 if entry.is_dir() else 0o644)
        switch_release(target, args)


def mutation_flags(parser):
    parser.add_argument('--yes', action='store_true', help='Apply reviewed changes without the single confirmation prompt')
    parser.add_argument('--dry-run', action='store_true', help='Show the plan without changing files, firewall or backend')


def parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--config', default='/root/peakalgo-egress.env', help='Private installer answers; use separate files for different backend tokens')
    p.set_defaults(gateway_config=str(ETC / 'config.json'))
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('status', help='Show redacted identity, version, backend, allowlist and service state')
    sub.add_parser('backup', help='Create a root-only configuration/identity backup under /var/backups')
    diag = sub.add_parser('diagnostics', help='Run signed local health or explicit full IPv6/TLS probes; no trades')
    diag.add_argument('--full', action='store_true', help='Probe all source IPv6 addresses to Cloudflare and Kite TLS')
    backend = sub.add_parser('backend', help='Re-register an existing identity at an HTTPS backend').add_subparsers(dest='action', required=True)
    setting = backend.add_parser('set', help='Register first; save URL only after matching backend acknowledgement')
    setting.add_argument('--url', required=True, help='HTTPS origin; credentials, paths and redirects are refused')
    setting.add_argument('--token-file', help='Private destination token file; overrides the selected answers file token; never saved')
    mutation_flags(setting)
    acl = sub.add_parser('allowlist', help='Update source IP access in app ACL, UFW and installer answers').add_subparsers(dest='action', required=True)
    acl.add_parser('show', help='List allowed source IPv4 CIDRs')
    for action in ('add', 'remove', 'set'):
        command = acl.add_parser(action, help=action.capitalize() + ' explicit source CIDRs; self-address always retained')
        command.add_argument('--cidr', action='append', required=True, help='IPv4 CIDR, preferably /32; repeat for multiple sources; /0 refused')
        mutation_flags(command)
    releases = sub.add_parser('release', help='Source-only upgrade or rollback; no reinstall/netplan changes').add_subparsers(dest='action', required=True)
    upgrade = releases.add_parser('install', help='Verify a local ZIP and switch source with health rollback')
    upgrade.add_argument('--archive', required=True, help='Local source ZIP (upload with scp first)')
    upgrade.add_argument('--sha256', required=True, help='Expected SHA-256 obtained from the trusted publisher')
    mutation_flags(upgrade)
    mutation_flags(releases.add_parser('rollback', help='Switch to the retained previous release'))
    return p


def main():
    args = parser().parse_args()
    if os.geteuid() != 0:
        raise ValueError('Run with sudo; gateway identity and backend tokens are root protected')
    # Serialize changes, including separate command processes.
    with open('/run/lock/peakalgo-egress-management.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config = read_config(args.gateway_config)
        if args.command == 'status':
            answers = read_env(args.config) if Path(args.config).exists() else {}
            cert = ssl.PEM_cert_to_DER_cert(Path(config['certPath']).read_text())
            data = {k: config[k] for k in ('hostId', 'ipv4', 'port', 'primaryIpv6', 'addresses', 'allowedCidrs')}
            data.update(version=json.loads((BASE / 'current/package.json').read_text())['version'],
                        backend=answers.get('BACKEND_BASE_URL'), certificateSha256=hashlib.sha256(cert).hexdigest(),
                        release=str((BASE / 'current').resolve()))
            print(json.dumps(data, indent=2))
            run(['systemctl', 'status', SERVICE, '--no-pager'])
        elif args.command == 'backup':
            snapshot(args.config)
        elif args.command == 'backend':
            url = backend_origin(args.url)
            token = update_backend.read_token_file(args.token_file) if args.token_file else None
            if approve(args, 'Register ' + config['hostId'] + ' at ' + url + '; retains local identity and pool. No activation or assignment migration.'):
                snapshot(args.config)
                update_backend.update_backend(url, args.config, args.gateway_config, token=token, assume_yes=True)
        elif args.command == 'allowlist':
            if args.action == 'show':
                print('\n'.join(config['allowedCidrs']))
            else:
                apply_allowlist(args, config)
        elif args.command == 'release':
            release_command(args)
        elif args.command == 'diagnostics':
            run([str(BASE / 'node/bin/node'), str(BASE / 'current/scripts/diagnostics.js'), '--json'] + ([] if args.full else ['--health']),
                env={**os.environ, 'PEAKALGO_CONFIG': args.gateway_config})


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as error:
        raise SystemExit('Gateway management stopped: ' + str(error))
