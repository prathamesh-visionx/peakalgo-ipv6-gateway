#!/usr/bin/env python3
"""Create a source-only release, including no local configuration or secrets."""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
version = json.loads((ROOT / 'package.json').read_text())['version']
files = [ROOT / 'package.json', ROOT / 'config.env.example']
for folder in ['src', 'scripts', 'systemd']:
    files.extend(p for p in (ROOT / folder).rglob('*') if p.is_file() and p.suffix in {'.js', '.py', '.sh', '.service'})
output = ROOT / 'releases' / f'peakalgo-egress-{version}.zip'
output.parent.mkdir(exist_ok=True)
with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(files):
        if path.is_symlink():
            raise SystemExit('Refusing to package a symlink')
        archive.write(path, path.relative_to(ROOT))
checksum = hashlib.sha256(output.read_bytes()).hexdigest()
output.with_suffix('.zip.sha256').write_text(f'{checksum}  {output.name}\n')
print(output)
print('SHA-256: ' + checksum)
print('Upload the ZIP, then set RELEASE_ZIP_URL and RELEASE_SHA256 in scripts/bootstrap.sh.')
