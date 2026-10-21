"""Verify approved ZIP bytes and every allowlisted entry before writing any site file."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import stat
import re
import urllib.request
import sys
from zipfile import ZipFile


def validate_contract(approved):
    """New manifests declare each issue/revision; legacy file-only approvals remain readable."""
    if approved.get('schema_version') != 2:
        return
    expected = {'index.html', '404.html'}
    entries = approved['entries']
    if set(approved['optional_assets']) != set(entries):
        raise ValueError('Asset declarations must match revisions')
    for key, entry in entries.items():
        issue = entry['issue_id']; prefix = entry['path'].rstrip('/')
        if not re.fullmatch(r'\d{4}-W\d{2}', issue) or not re.fullmatch(r'posts/\d{4}-W\d{2}(?:/revisions/r[1-9]\d*)?', prefix):
            raise ValueError('Invalid issue path')
        if not prefix.startswith('posts/' + issue):
            raise ValueError('Issue/path mismatch')
        assets = approved['optional_assets'][key]
        if assets not in ([], ['cover.png']):
            raise ValueError('Undeclared or unsupported optional assets')
        expected.update({prefix+'/index.html', prefix+'/assets/site.css'})
        ranks = entry['ranks']
        if not ranks or len(set(ranks)) != len(ranks) or any(type(n) is not int or not 1 <= n <= 999 for n in ranks):
            raise ValueError('Invalid detail rank list')
        expected.update(prefix+f'/details/{n:02d}.html' for n in ranks)
        expected.update(prefix+'/'+a for a in assets)
    if expected != set(approved['files']):
        raise ValueError('Files do not match declared asset contract')


def release_url(approved):
    tag, asset = approved['release_tag'], approved['asset']
    if not re.fullmatch(r'\d{4}-W\d{2}-r[1-9]\d*-[a-f0-9]{12}', tag) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,120}\.zip', asset):
        raise ValueError('Invalid approved release selector')
    return 'https://github.com/kimG-bit/hermes-trending-weekly/releases/download/' + tag + '/' + asset


def download_approved(manifest, destination):
    approved = json.loads(manifest.read_text())
    url = release_url(approved)
    if destination.exists():
        raise ValueError('Download target exists')
    if not 0 < approved['archive']['bytes'] <= 20_000_000:
        raise ValueError('Download size limit exceeded')
    with urllib.request.urlopen(url, timeout=120) as response:
        data = response.read(approved['archive']['bytes'] + 1)
    if len(data) != approved['archive']['bytes'] or hashlib.sha256(data).hexdigest() != approved['archive']['sha256']:
        raise ValueError('Downloaded archive hash mismatch')
    destination.write_bytes(data)


def verify(bundle, manifest, output, *, archive_pin=None):
    approved = json.loads(manifest.read_text())
    if output.exists():
        raise ValueError('Output already exists')
    container = approved.get('archive') or archive_pin
    if not container:
        raise ValueError('Legacy file-only manifest requires an independently approved archive pin')
    if bundle.stat().st_size != container['bytes'] or hashlib.sha256(bundle.read_bytes()).hexdigest() != container['sha256']:
        raise ValueError('Archive approval mismatch')
    validate_contract(approved)
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
    if sys.argv[1] == '--download':
        download_approved(Path(sys.argv[2]), Path(sys.argv[3]))
    else:
        count = verify(*(Path(p) for p in sys.argv[1:]))
        print(json.dumps({'verified_files': count}))
