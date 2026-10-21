# Change the backend URL without reinstalling

After installing v1.1.0 or newer, run on the droplet:

```sh
sudo python3 /opt/peakalgo-egress/current/scripts/update-backend.py \
  --backend-url https://your-new-backend.example
```

The command reads the existing gateway configuration and re-registers that exact
identity and IPv6 inventory at the new backend. It retains the certificate,
private key, HMAC secret, IPv6 pool, source allowlist, firewall, and running service.
It does not enable a host or place orders. Re-registering into the same database
also preserves host activation, address ownership and whitelist confirmations.
A different database starts with a disabled host and unassigned addresses; this
command does not migrate database records.

Keep the new backend connected to the same MongoDB and `BROKER_ENCRYPTION_KEY`
to retain existing backend configuration. Configure its `BACKEND_BASE_URL` and
`EGRESS_REGISTRATION_TOKEN` before running the command. The URL must be an HTTPS
origin without credentials, a path, a query, or a fragment. Registration does not
follow redirects, to avoid disclosing credentials to another destination.

By default, installer answers and the registration token are read from
`/root/peakalgo-egress.env`. Use `--config /root/new-backend.env` for a different
root-only answers file/token, or omit the token from that file to enter it at a
hidden prompt. Do not pass tokens as command-line arguments. `--yes` skips the
review prompt for an already reviewed automation; it does not skip validation.

Only after registration succeeds, `BACKEND_BASE_URL` is saved atomically in the
selected answers file (mode 0600), preserving its other values. A missing file is
created with only the URL; a prompted token is not saved. On registration failure,
the previous file and installed gateway configuration remain unchanged. If saving
fails after successful registration, correct file access and rerun; registration
is idempotent. Later full installer runs should use that same answers file.

Update the paid operator's Kite developer redirect/postback URLs and each personal
app's URLs to match the new backend. Run manual diagnostics from admin afterward.
Changing the URL does not change the source IP used to connect to the gateway: if
the backend moves to another public IP, review/update `BACKEND_ALLOWED_CIDRS` via
the installer and any DigitalOcean Cloud Firewall as a separate networking change.

Example for a new development tunnel:

```sh
sudo python3 /opt/peakalgo-egress/current/scripts/update-backend.py \
  --backend-url https://your-new-tunnel.devtunnels.ms \
  --config /root/peakalgo-egress.env
```
