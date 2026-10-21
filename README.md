# PeakAlgo IPv6 order gateway

This package runs **only an authenticated CONNECT gateway** on an Ubuntu 24.04 DigitalOcean droplet. The strategy engine, database, personal Kite secrets/access tokens, OAuth callbacks and postbacks stay on AWS. The gateway forwards opaque TLS traffic to `api.kite.trade:443`, opening each outbound connection from the IPv6 selected by AWS. It cannot fall back to IPv4.

Each IPv6-enabled DO droplet has a provider-allocated `/124` (16 addresses). The primary address is reserved; the other 15 can be assigned permanently to broker accounts. This allocation is not the `/64` on-link netmask used by netplan. No automatic address recycling or host migration is performed.

## 1. Build locally and upload

From this folder, with Node 22 and Python 3 installed:

```sh
npm test
python3 -m unittest discover -s test -p '*_test.py'
npm run package
```

Upload `releases/peakalgo-egress-1.0.0.zip` to your preferred hosting service. The URL must return the ZIP bytes over HTTPS, followable by curl without an interactive login. Use a direct download URL rather than an HTML sharing page. Free services that require browser challenges will not work. Keep the generated `.zip.sha256` value.

The ZIP includes only source, scripts, systemd configuration, documentation and example configuration. It does **not** contain your real configuration, TLS keys, personal broker credentials or deployment secrets.

## 2. Configure the AWS backend first

Set these values in the backend environment; see its `.env.example` and `docs/PERSONAL_KITE_EGRESS.md`:

```dotenv
BACKEND_BASE_URL=https://your-public-backend.example
ADMIN_EMAIL=your-verified-admin@example.com
EGRESS_REGISTRATION_TOKEN=your-random-registration-token-at-least-32-characters
KITE_API_KEY=your-paid-operator-key
KITE_API_SECRET=your-paid-operator-secret
```

Generate a registration token locally using `openssl rand -hex 32`. The backend's existing encryption and JWT keys remain required. Do not put any real values in the ZIP. Complete the legacy-session migration during a maintenance window with no managed live exposure; the backend guide covers this.

Your AWS backend needs a known public IPv4 source (for example an EC2 public IP or NAT gateway IP) that can reach the droplet on TCP 8443. Supply that address as a `/32`. Also configure any DigitalOcean Cloud Firewall to allow this path and your SSH access. The installer can configure host UFW rules, **not** the provider Cloud Firewall.

## 3. Run the separate interactive installer yourself

Copy `scripts/bootstrap.sh` to your droplet, independently of the ZIP. Either edit `RELEASE_ZIP_URL` and `RELEASE_SHA256` near the top or pass them as arguments. Download the script first; do not pipe it into bash, since review prompts require an interactive terminal.

Optionally copy `config.env.example` to `/root/peakalgo-egress.env`, edit it, and run `chmod 600 /root/peakalgo-egress.env`. Omit the registration token to enter it securely at the final registration prompt. Environment-file values are parsed literally, never sourced as shell commands.

```sh
sudo bash bootstrap.sh \
  --zip-url 'https://your-host.example/peakalgo-egress-1.0.0.zip' \
  --sha256 'YOUR_64_CHARACTER_SHA256' \
  --config /root/peakalgo-egress.env
```

The bootstrap verifies the archive before running its installer. The installer asks you to review:

1. Prerequisite installation, official Node 22 download, and installation paths.
2. Discovered DO addresses, interface, existing netplan ID, AWS source CIDRs and SSH ports.
3. The additional-address netplan overlay. It preserves the original primary network files, routes, DNS and IPv4. A 180-second systemd watchdog restores the prior overlay if you do not confirm that connectivity is working. Keep the DigitalOcean console and a second SSH session available.
4. UFW rules before adding them and enabling UFW. Existing rules remain; review/remove any overly broad conflicting rules yourself. Existing SSH ports are allowed first. UFW's standard ICMPv6 rules must remain intact.
5. Switching the active source release and starting/restarting systemd.
6. Sending registration to AWS. Hosts initially remain disabled.

Every approval requires the word `yes`. Declining stops later stages; already-approved stages remain. No connection-test suite, broker login or trade is automatically run. Re-running the installer preserves its host identity, private key, certificate, secret and pool. Unexpected identity changes are refused rather than silently replacing users' IPs. Source updates can restart active tunnels; perform updates outside live trading.

The official Node binary is downloaded over HTTPS and checked against its official SHA-256 manifest. No third-party installation script is executed. The TLS certificate is self-signed and pinned in AWS at authenticated registration. Back up `/etc/peakalgo-egress` securely; losing it requires restoring identity or explicitly replacing the host. Certificate renewal/host replacement requires a reviewed backend update rather than automatic trust changes.

## 4. Manual checks — run these yourself after installation

These commands are provided for your deployment session. They are not run by the coding agent or automatically by bootstrap.

```sh
sudo systemctl status peakalgo-egress --no-pager
sudo journalctl -u peakalgo-egress -n 80 --no-pager
sudo netplan get
ip -6 address show
ip -6 route show
getent ahostsv6 api.kite.trade
timedatectl status
sudo ufw status numbered
sudo ss -lntp
```

HMAC authentication requires AWS and droplet clocks to agree within 30 seconds. If NTP is disabled, review and enable it manually using `sudo timedatectl set-ntp true`.

Check that all 16 addresses are present and not tentative/duplicate, the original default routes and SSH access still work, and the gateway listens on TCP 8443. No NAT, IPv6 forwarding, Docker, or `ip_nonlocal_bind` is required.

Run the optional diagnostics explicitly:

```sh
sudo /opt/peakalgo-egress/node/bin/node /opt/peakalgo-egress/current/scripts/diagnostics.js --health --json
sudo /opt/peakalgo-egress/node/bin/node /opt/peakalgo-egress/current/scripts/diagnostics.js --json
```

The full command sends source-bound IPv6 requests to Cloudflare's `one.one.one.one/cdn-cgi/trace` and verifies TLS to `api.kite.trade` for each address. It sends no broker credentials and places no orders. It confirms observed source addresses and IPv6/TLS connectivity; it cannot read Zerodha's whitelist setting. A FAIL must be resolved before activation.

To verify persistence, reboot manually during your deployment window, reconnect, then repeat the address/service checks. Check AWS-to-droplet access from the backend's actual public source address. In admin → **Broker infrastructure**, run **manual diagnostics** to verify the authenticated pinned-TLS path and record verified addresses. Then enable the gateway. Runtime health polling runs every 60 seconds for enabled hosts; data older than 120 seconds fails trading readiness.

Never test by placing a real order as part of bootstrap. A user must log in with their own key, copy their assigned IPv6 into their Kite developer profile's IP Whitelist, and explicitly confirm this in the mobile app. If Kite rejects the IP, PeakAlgo clears that confirmation and pauses the engine.

## Updates and rollback

Package a new ZIP and rerun bootstrap with its URL and checksum. Review all stages again. Source releases are installed under `/opt/peakalgo-egress/releases/<checksum-prefix>`; `current` is switched only after approval. An existing release directory is retained, so changing source requires a new ZIP/checksum. `/etc/peakalgo-egress` remains the stable configuration.

The installer retains the former source release as `/opt/peakalgo-egress/previous`. To roll back source yourself:

```sh
sudo systemctl stop peakalgo-egress
sudo ln -sfn "$(readlink /opt/peakalgo-egress/previous)" /opt/peakalgo-egress/current
sudo cp /opt/peakalgo-egress/current/systemd/peakalgo-egress.service /etc/systemd/system/peakalgo-egress.service
sudo systemctl daemon-reload
sudo systemctl start peakalgo-egress
```

Netplan backup and standalone restore scripts are kept under `/etc/peakalgo-egress/backups`; inspect the relevant script before running it. Do not overwrite unrelated primary netplan configuration. Firewall changes are additive; review `ufw status numbered` before removing individual PeakAlgo rules.

## Disable or uninstall manually

Disable the host in admin first. Assigned addresses must remain reserved in AWS; removing the service does not make them safe to reuse. Users with live exposure will need a valid route or must manage their positions directly at Zerodha.

Stop and disable `peakalgo-egress`, remove its systemd unit, and reload systemd. Back up configuration before removing source or secrets. If removing the netplan overlay, inspect its contents, remove only `/etc/netplan/90-peakalgo-egress.yaml`, then apply your reviewed primary configuration from the console. Remove only the gateway firewall rules, preserving SSH and ICMPv6. No uninstall script automatically deletes configuration, identities or backend assignments.
