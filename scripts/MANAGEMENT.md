# Gateway management — v1.2.0

The gateway has two independent credentials: its installed HMAC/TLS identity, and
the destination backend's registration token. `BROKER_ENCRYPTION_KEY` belongs to
the backend only; never put it in the gateway config or release ZIP.

After installing v1.2.0, run `sudo peakalgo-egress --help`. Each command supports
its own `--help`. Mutating commands have one confirmation; `--yes` approves that
specific command, and `--dry-run` previews it. Root privileges, HTTPS validation,
no-registration-redirects, HMAC, TLS pinning, and explicit source CIDRs remain.

## Daily commands on the droplet

```sh
sudo peakalgo-egress status
sudo peakalgo-egress backup
sudo peakalgo-egress diagnostics          # signed local health only
sudo peakalgo-egress diagnostics --full   # source-bound IPv6 + Kite TLS; no orders
sudo peakalgo-egress allowlist show
sudo peakalgo-egress allowlist add --cidr 18.116.121.168/32 --yes
sudo peakalgo-egress allowlist remove --cidr 203.0.113.7/32 --yes
sudo peakalgo-egress allowlist set --cidr 18.116.121.168/32 --yes
```

Allowlist commands update the gateway application ACL, matching host UFW rules
and `BACKEND_ALLOWED_CIDRS` in the selected answers file. They preserve the gateway
self-address for signed health checks and all SSH rules. `/0` is forbidden. A
restart interrupts active tunnels. Review the DigitalOcean Cloud Firewall separately;
these commands cannot change it. Existing unrelated broad UFW rules remain, while
the application ACL still restricts gateway requests. Changes create root-only
configuration backups under `/var/backups/peakalgo-egress`, repair missing UFW
rules even for CIDRs already present in the config, and roll back local
files/rules if restart health fails.

## Switch backends without reinstalling

Disable the gateway in the previous backend before switching **independent**
databases. The gateway does not query, delete or copy the old backend's records.
Switching the saved URL does not revoke the old backend's credentials. Keep the
allowlist limited to the active backend, and never leave two independent databases
allocating the same IPv6 pool concurrently. Existing provider whitelists require
review before releasing/reusing an address for another broker client.

Create a root-owned mode-600 file containing only the destination registration
token (use an editor or secret manager, not a command-line token). Then:

```sh
sudo peakalgo-egress backend set \
  --url https://devalgo.thetrinitychs.in \
  --token-file /root/main-backend.token --yes
```

The token file must be owned by root and cannot be a symlink. It is never printed
or copied into saved answers. Keep supplying `--token-file` when that destination
uses a different token, or maintain one mode-600 installer answers file per
backend and select it with the global `--config /root/main-egress.env` option.
The selected answers file's URL changes only after a matching registration
acknowledgement; failures preserve configuration. Identity, certificate and IPv6
inventory are retained. New database registrations start **disabled/unassigned**.
Shared-database registrations retain their state and require compatible encryption
keys. Run admin diagnostics and explicitly enable after checking the new backend.

For shared databases, the previous backend must stop monitoring/mutating this host
if its encryption key is incompatible. Otherwise its polling can overwrite health
with failures. Use separate development databases or consistent keys for shared
encrypted records. Changing a URL does not migrate broker credentials encrypted
with another key.

## Reset a registration after a key mismatch

Do this on the **backend server**, not the droplet. The included
`scripts/reset-registration.cjs` uses the backend's existing `mongoose`, `dotenv`,
and `MONGO_URI`. It does not decrypt any record or change the main encryption key.
There is no public deregistration/reset endpoint or registration-token bypass.

Copy the release/script to the backend server, then preview:

```sh
node /path/to/release/scripts/reset-registration.cjs \
  --backend-dir /home/ubuntu/dev-algo-backend- --host-id do-607523229
```

After reviewing the exact database, host and exposure counts, apply:

```sh
node /path/to/release/scripts/reset-registration.cjs \
  --backend-dir /home/ubuntu/dev-algo-backend- --host-id do-607523229 \
  --apply --confirm-host-id do-607523229 --release-assignments \
  --backup-file /home/ubuntu/gateway-reset-do-607523229.json
```

The backup path must be new and absolute. It contains the original host including
its encrypted secret, all its address rows, and affected users' engine flags in
Extended JSON. It is written exclusively, mode 600, and synced before deletion.
Store it privately. The tool locks affected broker users/accounts, refuses live
positions, pending orders and active attempts, disables affected engines, and
deletes exactly this host and its address rows in one Mongo transaction. Users,
broker credentials, audit/order data and other hosts are retained. Transactions
are mandatory. No `--force` bypasses live-exposure checks. Explicit assignment
release clears whitelist confirmations; verify/remove old Kite whitelist entries
before another broker account receives a released IP.

Then run `backend set` on the droplet again. The main backend encrypts the existing
gateway's HMAC secret using its own key and creates 15 fresh unassigned address
rows. Run admin diagnostics, enable the host explicitly, and reconnect/reconfirm
each personal account before turning its engine back on. This reset is destructive
by design; normal backend switches should use compatible records without resetting.

## Upgrade/rollback source without touching networking or identity

Upload the ZIP with `scp`, obtain the SHA-256 through the trusted release channel,
and run:

```sh
sudo peakalgo-egress release install --archive /root/peakalgo-egress-1.2.0.zip \
  --sha256 YOUR_64_CHARACTER_SHA256 --yes
sudo peakalgo-egress release rollback --yes
```

The archive is bounded, checksum verified and checked for path traversal, links,
duplicate/ambiguous entries and missing files. Source releases are immutable and
content-addressed. The updater changes the source symlink/systemd unit, retains
drop-ins, takes a private backup, and rolls back source/unit on failed signed local
health. It installs no packages and changes no netplan/firewall/identity. Full
IPv6 tests remain explicit. Rollback is a source rollback, not a Mongo reset undo.

For the first upgrade from v1.1.0, upload and safely extract the new release, then
invoke `python3 /path/to/new-release/scripts/manage.py release install ...` once;
the upgrade installs `/usr/local/bin/peakalgo-egress`. Future upgrades use the
normal command. Do not extract an unverified archive as root.

## Fresh installation and fewer prompts

`bootstrap.sh --help` and `install.py --help` list installation options. Interactive
installation now approves prerequisites and one combined gateway plan, rather than
asking separately for firewall, service and registration. `--yes --config FILE`
uses provided/discovered answers for non-network stages; missing inputs stop.
Netplan changes always retain separate apply/KEEP confirmations and a 180-second
rollback watchdog, even with `--yes`. An unchanged overlay requires no network
confirmation. Never pipe the installer from a network download into a shell.
