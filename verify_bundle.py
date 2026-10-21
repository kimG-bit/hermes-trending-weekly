"""Verify approved ZIP bytes and every allowlisted entry before writing any site file."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import sys
from zipfile import ZipFile


def verify(bundle, manifest, output):
    approved = json.loads(manifest.read_text())
    if output.exists():
        raise ValueError('Output already exists')
    if bundle.stat().st_size != approved['archive']['bytes'] or hashlib.sha256(bundle.read_bytes()).hexdigest() != approved['archive']['sha256']:
        raise ValueError('Archive approval mismatch')
    expected = approved['files']
    if not expected or len(expected) > 1000:
        raise ValueError('Invalid allowlist')
    total = sum(item['bytes'] for item in expected.values())
    if total > 20_000_000:
        raise ValueError('Approved size limit exceeded')
    validated = {}
    with ZipFile(bundle) as z:
        names = z.namelist()
        if len(set(names)) != len(names) or set(names) != set(expected):
            raise ValueError('ZIP entries differ from allowlist')
        for info in z.infolist():
            name = info.filename
            path = PurePosixPath(name)
            mode = stat.S_IFMT(info.external_attr >> 16)
            if path.is_absolute() or '..' in path.parts or '\\' in name or str(path) != name or info.is_dir() or mode not in (0, stat.S_IFREG):
                raise ValueError('Unsafe archive entry')
            item = expected[name]
            if info.file_size != item['bytes'] or info.file_size > total:
                raise ValueError('File size mismatch')
            data = z.read(info)
            if hashlib.sha256(data).hexdigest() != item['sha256']:
                raise ValueError('File hash mismatch')
            validated[name] = data
    output.mkdir(parents=True)
    for name, data in validated.items():
        target = output / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return len(validated)


if __name__ == '__main__':
    count = verify(*(Path(p) for p in sys.argv[1:]))
    print(json.dumps({'verified_files': count}))
