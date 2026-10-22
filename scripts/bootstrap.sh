#!/usr/bin/env bash
set -euo pipefail
# Edit these two values after uploading the ZIP produced by npm run package.
RELEASE_ZIP_URL=""
RELEASE_SHA256=""
CONFIG_FILE=""
ASSUME_YES=0
while (($#)); do
  case "$1" in
    --zip-url) RELEASE_ZIP_URL="${2:?Missing URL}"; shift 2 ;;
    --sha256) RELEASE_SHA256="${2:?Missing SHA-256}"; shift 2 ;;
    --config) CONFIG_FILE="${2:?Missing configuration file}"; shift 2 ;;
    --yes) ASSUME_YES=1; shift ;;
    --help) cat <<'HELP'
sudo bash bootstrap.sh --zip-url HTTPS_URL --sha256 HEX [--config /root/egress.env] [--yes]

Downloads a source ZIP over HTTPS, checks its SHA-256, and installs it.
  --zip-url URL   Direct HTTPS URL returning the release ZIP
  --sha256 HEX    Expected 64-character SHA-256 from the trusted publisher
  --config FILE   Root-only installer answers and optional registration token
  --yes           Approve configured non-network stages without repeated yes prompts
                  Netplan changes always require interactive apply/KEEP confirmation.

Existing gateway: use peakalgo-egress release install or backend set instead of reinstalling.
HELP
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done
[[ $ASSUME_YES == 1 || ( -t 0 && -t 1 ) ]] || { echo 'Run from an interactive terminal, not curl | bash. Download this script first.' >&2; exit 1; }
[[ $EUID -eq 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
[[ "$RELEASE_ZIP_URL" == https://* && "$RELEASE_SHA256" =~ ^[a-fA-F0-9]{64}$ ]] || { echo 'Set an HTTPS ZIP URL and its expected SHA-256.' >&2; exit 1; }
. /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]] || { echo 'This installer targets Ubuntu 24.04 only.' >&2; exit 1; }
echo 'This will download and verify your release, then open an interactive installer.'
echo 'Review the installer plan; --yes approves non-network stages. Netplan apply/KEEP always needs a console.'
if [[ $ASSUME_YES != 1 ]]; then
  read -r -p 'Continue? [type yes]: ' answer
  [[ "$answer" == yes ]] || exit 0
fi
if ! command -v curl >/dev/null || ! command -v python3 >/dev/null; then
  echo 'Prerequisites missing: install curl, python3 and ca-certificates using apt.'
  if [[ $ASSUME_YES != 1 ]]; then
    read -r -p 'Approve prerequisite installation? [type yes]: ' answer
    [[ "$answer" == yes ]] || exit 0
  fi
  apt-get update
  apt-get install -y curl python3 ca-certificates
fi
stage=$(mktemp -d /tmp/peakalgo-release.XXXXXXXX)
trap 'rm -rf -- "$stage"' EXIT
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --location --retry 2 --max-time 180 --max-filesize 10485760 --output "$stage/release.zip" "$RELEASE_ZIP_URL"
# BEGIN_SAFE_EXTRACT
python3 - "$stage/release.zip" "$stage/content" "$RELEASE_SHA256" <<'PY'
import hashlib, pathlib, stat, sys, zipfile
archive, destination, expected = sys.argv[1:]
if hashlib.sha256(pathlib.Path(archive).read_bytes()).hexdigest() != expected.lower():
    raise SystemExit('ZIP checksum mismatch; nothing installed')
root = pathlib.Path(destination)
with zipfile.ZipFile(archive) as z:
    entries = z.infolist()
    names = set()
    if len(entries) > 100 or sum(e.file_size for e in entries) > 10_485_760:
        raise SystemExit('Release archive is too large')
    for entry in entries:
        p = pathlib.PurePosixPath(entry.filename)
        mode = entry.external_attr >> 16
        if (p.is_absolute() or '..' in p.parts or '\\' in entry.filename or not p.parts or
            p.parts[0] not in {'src', 'scripts', 'systemd', 'package.json', 'README.md', 'config.env.example'} or
            stat.S_ISLNK(mode) or entry.filename in names or entry.flag_bits & 1):
            raise SystemExit('Unsafe ZIP entry: ' + entry.filename)
        names.add(entry.filename)
    required = {'package.json', 'src/server.js', 'src/protocol.js', 'scripts/install.py', 'systemd/peakalgo-egress.service'}
    if not required.issubset(names):
        raise SystemExit('Incomplete release ZIP')
    root.mkdir(mode=0o700)
    for entry in entries:
        target = root.joinpath(*pathlib.PurePosixPath(entry.filename).parts)
        if entry.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(z.read(entry))
PY
# END_SAFE_EXTRACT
args=(--release-dir "$stage/content" --release-id "${RELEASE_SHA256:0:16}")
if [[ -n "$CONFIG_FILE" ]]; then args+=(--config "$CONFIG_FILE"); fi
if [[ $ASSUME_YES == 1 ]]; then args+=(--yes); fi
python3 "$stage/content/scripts/install.py" "${args[@]}"
