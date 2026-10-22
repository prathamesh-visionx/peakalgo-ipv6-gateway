"""Checksum verification and bounded extraction shared by gateway management."""
import hashlib
from pathlib import Path, PurePosixPath
import re
import stat
import zipfile


def extract_release(archive, destination, expected):
    if not re.fullmatch(r'[a-fA-F0-9]{64}', expected):
        raise ValueError('Provide the 64-character SHA-256 from the release publisher')
    archive = Path(archive)
    if archive.stat().st_size > 10_485_760:
        raise ValueError('Release archive is too large')
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != expected.lower():
        raise ValueError('ZIP checksum mismatch; nothing installed')
    destination = Path(destination)
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > 100 or sum(e.file_size for e in entries) > 10_485_760:
            raise ValueError('Release archive is too large')
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            mode = entry.external_attr >> 16
            if (path.is_absolute() or '..' in path.parts or '\\' in entry.filename or str(path) != entry.filename.rstrip('/') or
                    not path.parts or path.parts[0] not in {'src', 'scripts', 'systemd', 'package.json', 'README.md', 'config.env.example'} or
                    stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)) or
                    entry.filename in names or entry.flag_bits & 1):
                raise ValueError('Unsafe ZIP entry: ' + entry.filename)
            names.add(entry.filename)
        required = {'package.json', 'src/server.js', 'src/protocol.js', 'scripts/install.py',
                    'scripts/manage.py', 'systemd/peakalgo-egress.service'}
        if not required.issubset(names):
            raise ValueError('Incomplete management release ZIP')
        for entry in entries:
            target = destination.joinpath(*PurePosixPath(entry.filename).parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(bundle.read(entry))
    return digest
