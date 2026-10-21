#!/usr/bin/env python3
"""Interactive Ubuntu installer. Imported by local fixture tests without side effects."""
import argparse
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.request

BASE = Path('/opt/peakalgo-egress')
ETC = Path('/etc/peakalgo-egress')
OVERLAY = Path('/etc/netplan/90-peakalgo-egress.yaml')

def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def output(args):
    return subprocess.check_output(args, text=True).strip()

def confirm(message):
    print('\n' + message)
    if input('Type yes to approve; anything else stops safely: ').strip() != 'yes':
        raise SystemExit('Stopped by operator. Completed stages are listed above; no later stages ran.')

def read_env(path):
    if not path:
        return {}
    p = Path(path)
    if p.stat().st_mode & 0o077:
        raise SystemExit('Configuration file must be root-only: chmod 600 ' + str(p))
    result = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or not re.fullmatch('[A-Z_][A-Z0-9_]*', key):
            raise SystemExit('Invalid environment file')
        result[key] = value.strip().strip('"').strip("'")
    return result

def pool(primary):
    address = ipaddress.IPv6Address(primary)
    if not address.is_global:
        raise ValueError('Public IPv6 required')
    return [str(x) for x in ipaddress.IPv6Network((address, 124), strict=False) if x != address]

def public_ipv4(value):
    ip = ipaddress.IPv4Address(value)
    if not ip.is_global:
        raise ValueError('Public IPv4 required')
    return str(ip)

def validate_cidrs(value):
    values = [str(ipaddress.IPv4Network(x.strip(), strict=False)) for x in value.split(',') if x.strip()]
    if not values or any(ipaddress.ip_network(x).prefixlen == 0 for x in values):
        raise ValueError('Provide explicit AWS source IPv4 CIDRs, preferably /32; 0.0.0.0/0 is forbidden')
    return values

def netplan_text(netplan_id, addresses, prefixlen):
    if not re.fullmatch('[a-zA-Z0-9_.:-]+', netplan_id):
        raise ValueError('Invalid netplan interface ID')
    # JSON is a YAML subset. Only add addresses; never replace DHCP, DNS, routes or match rules.
    return json.dumps({'network': {'version': 2, 'ethernets': {netplan_id: {'addresses': [f'{x}/{prefixlen}' for x in addresses]}}}}, indent=2) + '\n'

def ask(label, default=''):
    value = input(f'{label} [{default}]: ').strip()
    return value or default

def fetch_json(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.load(response)

def install_node():
    node = BASE / 'node/bin/node'
    if node.exists() and output([str(node), '--version']).startswith('v22.'):
        return
    machine = output(['uname', '-m'])
    arch = {'x86_64': 'x64', 'aarch64': 'arm64'}.get(machine)
    if not arch:
        raise SystemExit('Unsupported CPU architecture')
    url = 'https://nodejs.org/dist/latest-v22.x/'
    with urllib.request.urlopen(url + 'SHASUMS256.txt', timeout=30) as response:
        manifest = response.read().decode()
    match = re.search(r'^([a-f0-9]{64})\s+(node-v22\.[\d.]+-linux-' + arch + r'\.tar\.xz)$', manifest, re.M)
    if not match:
        raise SystemExit('Official Node 22 release not found')
    checksum, filename = match.groups()
    archive = BASE / filename
    with urllib.request.urlopen(url + filename, timeout=120) as response, archive.open('wb') as target:
        shutil.copyfileobj(response, target)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != checksum:
        raise SystemExit('Node distribution checksum mismatch')
    destination = BASE / 'runtimes'
    destination.mkdir(exist_ok=True)
    destination.chmod(0o755)
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter='data')
    runtime = destination / filename.removesuffix('.tar.xz')
    temporary = BASE / 'node.next'
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(runtime)
    temporary.replace(BASE / 'node')
    archive.unlink()

def install_network(text, release_id):
    if OVERLAY.exists() and OVERLAY.read_text() == text:
        print('Netplan overlay already matches; keeping it.')
        return
    print('\nProposed additional-address netplan overlay:\n' + text)
    print('Existing network files are preserved. A timed rollback restores this overlay if interrupted.')
    confirm('Apply this netplan overlay? Keep a DigitalOcean console open and verify a second SSH session afterward.')
    backups = ETC / 'backups'
    backups.mkdir(exist_ok=True)
    stamp = str(time.time_ns())
    backup = backups / ('netplan-' + stamp + '.yaml')
    had_overlay = OVERLAY.exists()
    if had_overlay:
        shutil.copy2(OVERLAY, backup)
    marker = backups / ('rollback-' + stamp + '.done')
    rollback = backups / ('rollback-' + stamp + '.sh')
    restore = ('cp -- ' + shlex.quote(str(backup)) + ' ' + shlex.quote(str(OVERLAY))) if had_overlay else ('rm -f -- ' + shlex.quote(str(OVERLAY)))
    rollback.write_text('#!/bin/bash\nset -eu\n' + restore + '\n' + shlex.quote(shutil.which('netplan')) + ' apply\ntouch ' + shlex.quote(str(marker)) + '\n')
    rollback.chmod(0o700)
    unit = 'peakalgo-netplan-' + stamp
    run(['systemd-run', '--unit=' + unit, '--on-active=180s', '/bin/bash', str(rollback)])
    try:
        OVERLAY.write_text(text)
        OVERLAY.chmod(0o600)
        run(['netplan', 'generate'])
        run(['netplan', 'apply'])
        confirm('Within 180 seconds: open another SSH session, review connectivity, then confirm KEEP this network configuration.')
        if marker.exists():
            raise SystemExit('Rollback already executed. Start installation again after reviewing networking.')
        run(['systemctl', 'stop', unit + '.timer'])
        subprocess.run(['systemctl', 'stop', unit + '.service'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        print('Network configuration kept. Backup/rollback script: ' + str(rollback))
    except BaseException:
        run(['/bin/bash', str(rollback)])
        subprocess.run(['systemctl', 'stop', unit + '.timer'], check=False)
        raise

def register(config, base_url, token):
    payload = {key: config[key] for key in ['hostId', 'ipv4', 'port', 'secret', 'primaryIpv6', 'addresses']}
    payload['certificatePem'] = Path(config['certPath']).read_text()
    request = urllib.request.Request(base_url + '/api/egress/register', data=json.dumps(payload).encode(), method='POST',
        headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
    with urllib.request.urlopen(request, timeout=15) as response:
        result = json.load(response)
    if not result.get('success'):
        raise SystemExit('Registration rejected; inspect backend configuration')
    print('Host registered. It remains disabled until you run diagnostics and enable it in admin.')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--release-dir', required=True)
    parser.add_argument('--release-id', required=True)
    parser.add_argument('--config')
    args = parser.parse_args()
    if not sys.stdin.isatty() or not sys.stdout.isatty() or os.geteuid() != 0:
        raise SystemExit('Run as root from an interactive terminal')
    if not re.fullmatch('[a-fA-F0-9]{16}', args.release_id):
        raise SystemExit('Invalid release ID')
    env = read_env(args.config)
    print('Prerequisites: python3-yaml, netplan.io, openssl, curl, ca-certificates, ufw, xz-utils and the official Node 22 binary.')
    confirm('Approve prerequisite installation and the gateway files under /opt/peakalgo-egress and /etc/peakalgo-egress?')
    run(['apt-get', 'update'])
    run(['apt-get', 'install', '-y', 'python3-yaml', 'netplan.io', 'openssl', 'curl', 'ca-certificates', 'ufw', 'xz-utils'])
    import yaml
    try:
        metadata = fetch_json('http://169.254.169.254/metadata/v1.json')
    except Exception:
        metadata = {}
    public = (metadata.get('interfaces', {}).get('public') or [{}])[0]
    ipv4 = public_ipv4(ask('Droplet public IPv4', env.get('PUBLIC_IPV4') or public.get('ipv4', {}).get('ip_address', '')))
    primary = str(ipaddress.IPv6Address(ask('Primary public IPv6 (verify in DigitalOcean)', env.get('PRIMARY_IPV6') or public.get('ipv6', {}).get('ip_address', ''))))
    addresses = pool(primary)
    interface_default = json.loads(output(['ip', '-j', 'route', 'show', 'default']))[0]['dev']
    interface = ask('Public network interface', env.get('PUBLIC_INTERFACE') or interface_default)
    existing_interfaces = json.loads(output(['ip', '-j', '-6', 'addr', 'show', 'dev', interface]))
    primary_info = next((a for x in existing_interfaces for a in x.get('addr_info', []) if str(ipaddress.IPv6Address(a['local'])) == primary), None)
    if not primary_info:
        raise SystemExit('Primary IPv6 is not configured on this interface. Enable DigitalOcean IPv6 first; no network changes applied.')
    ethernets = (yaml.safe_load(output(['netplan', 'get'])) or {}).get('network', {}).get('ethernets', {})
    mac = Path('/sys/class/net', interface, 'address').read_text().strip()
    candidates = [key for key, value in ethernets.items() if key == interface or value.get('set-name') == interface or value.get('match', {}).get('macaddress', '').lower() == mac.lower() or value.get('match', {}).get('name') == interface]
    netplan_id = ask('Existing netplan interface ID (' + ', '.join(ethernets) + ')', env.get('NETPLAN_ID') or (candidates[0] if len(candidates) == 1 else ''))
    if netplan_id not in ethernets:
        raise SystemExit('Select an existing netplan ID; refusing to invent primary network configuration')
    cidrs = validate_cidrs(ask('AWS backend public source IPv4 CIDRs, comma separated', env.get('BACKEND_ALLOWED_CIDRS', '')))
    base_url = ask('Public AWS backend HTTPS origin', env.get('BACKEND_BASE_URL', '')).rstrip('/')
    from urllib.parse import urlparse
    parsed = urlparse(base_url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise SystemExit('Backend URL must be an HTTPS origin')
    ssh_config = output(['sshd', '-T'])
    ssh_ports = sorted(set(int(x) for x in re.findall(r'^port (\d+)$', ssh_config, re.M))) or [22]
    if env.get('SSH_PORTS'):
        ssh_ports = sorted(set(ssh_ports + [int(x) for x in env['SSH_PORTS'].split(',')]))
    if any(p < 1 or p > 65535 for p in ssh_ports):
        raise SystemExit('Invalid SSH port')
    existing_path = ETC / 'config.json'
    existing = json.loads(existing_path.read_text()) if existing_path.exists() else None
    host_id = existing['hostId'] if existing else 'do-' + str(metadata.get('droplet_id') or os.urandom(8).hex())
    if existing and (existing['ipv4'] != ipv4 or existing['primaryIpv6'] != primary or existing['addresses'] != addresses):
        raise SystemExit('Existing host identity/address inventory changed. Preserve the existing configuration or use a new host.')
    print(f'\nHost: {host_id}\nPublic interface: {interface} (netplan {netplan_id})\nPrimary IPv6 reserved: {primary}\nPool: ' + ', '.join(addresses))
    print('Gateway TCP port: 8443\nAllowed AWS clients: ' + ', '.join(cidrs) + '\nSSH ports preserved: ' + ', '.join(map(str, ssh_ports)))
    print('The droplet itself is also permitted for explicitly invoked local diagnostics. No connection suite or trades run automatically.')
    confirm('Approve this gateway configuration and persistent host identity?')
    BASE.mkdir(exist_ok=True)
    BASE.chmod(0o755)
    ETC.mkdir(mode=0o750, exist_ok=True)
    if subprocess.run(['id', '-u', 'peakalgo-egress'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', 'peakalgo-egress'])
    install_node()
    release = BASE / 'releases' / args.release_id.lower()
    release.parent.mkdir(exist_ok=True)
    release.parent.chmod(0o755)
    if not release.exists():
        shutil.copytree(args.release_dir, release)
    else:
        print('Release already installed; preserving existing files.')
    # Source releases contain no secrets and must be readable by the service user.
    release.chmod(0o755)
    for entry in release.rglob('*'):
        entry.chmod(0o755 if entry.is_dir() else 0o644)
    key_path = ETC / 'gateway.key'
    cert_path = ETC / 'gateway.pem'
    if key_path.exists() != cert_path.exists():
        raise SystemExit('Incomplete TLS identity. Restore both key and certificate from backup.')
    if not key_path.exists():
        run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-sha256', '-nodes', '-days', '3650',
            '-keyout', str(key_path), '-out', str(cert_path), '-subj', '/CN=' + host_id, '-addext', 'subjectAltName=IP:' + ipv4], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    config = {'hostId': host_id, 'ipv4': ipv4, 'port': 8443, 'primaryIpv6': primary, 'addresses': addresses,
        'allowedCidrs': sorted(set(cidrs + [ipv4 + '/32'])), 'secret': existing['secret'] if existing else os.urandom(32).hex(),
        'keyPath': str(key_path), 'certPath': str(cert_path)}
    existing_path.write_text(json.dumps(config, indent=2) + '\n')
    run(['chown', 'root:peakalgo-egress', str(ETC), str(existing_path), str(key_path), str(cert_path)])
    existing_path.chmod(0o640)
    key_path.chmod(0o640)
    cert_path.chmod(0o640)
    install_network(netplan_text(netplan_id, addresses, primary_info['prefixlen']), args.release_id)
    print('\nCurrent firewall rules:')
    run(['ufw', 'status', 'numbered'])
    print('Proposed firewall: preserve existing rules; deny new inbound by default; allow SSH ports above and TCP 8443 only from the configured AWS CIDRs and local diagnostics.')
    print('Review existing broad allow rules: this installer does not remove them. Remove any conflicting allow rule yourself before activating the gateway.')
    confirm('Approve adding these firewall rules and enabling UFW?')
    ufw_defaults = Path('/etc/default/ufw')
    defaults = ufw_defaults.read_text()
    if re.search(r'^IPV6=no$', defaults, re.M):
        ufw_defaults.write_text(re.sub(r'^IPV6=no$', 'IPV6=yes', defaults, flags=re.M))
    for port in ssh_ports:
        run(['ufw', 'allow', str(port) + '/tcp', 'comment', 'SSH preserved by PeakAlgo'])
    for cidr in config['allowedCidrs']:
        run(['ufw', 'allow', 'from', cidr, 'to', 'any', 'port', '8443', 'proto', 'tcp'])
    run(['ufw', 'default', 'deny', 'incoming'])
    run(['ufw', '--force', 'enable'])
    print('systemd will start the gateway and restart it after boot. Runtime health checks from AWS begin only after you enable the host in admin.')
    confirm('Approve switching the active release and starting/restarting peakalgo-egress?')
    current = BASE / 'current'
    previous = BASE / 'previous'
    if current.is_symlink() and current.resolve() != release:
        previous.unlink(missing_ok=True)
        previous.symlink_to(current.resolve())
    next_link = BASE / 'current.next'
    next_link.unlink(missing_ok=True)
    next_link.symlink_to(release)
    next_link.replace(current)
    shutil.copy2(release / 'systemd/peakalgo-egress.service', '/etc/systemd/system/peakalgo-egress.service')
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'peakalgo-egress'])
    run(['systemctl', 'restart', 'peakalgo-egress'])
    print('Service installation complete. No live connection or order tests were run.')
    confirm('Register this host with ' + base_url + '? This sends host credentials and inventory over HTTPS; it does not enable trading.')
    token = env.get('EGRESS_REGISTRATION_TOKEN') or getpass.getpass('Backend EGRESS_REGISTRATION_TOKEN (hidden): ')
    if len(token) < 32:
        raise SystemExit('Registration token must contain at least 32 characters')
    register(config, base_url, token)
    print('Next: manually inspect service/networking, run diagnostics, check reboot persistence, then enable the host in admin. See README.md.')

if __name__ == '__main__':
    try:
        main()
    except (ValueError, subprocess.CalledProcessError, urllib.error.URLError) as error:
        raise SystemExit('Installation stopped: ' + str(error))
