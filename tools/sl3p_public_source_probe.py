#!/usr/bin/env python3
"""Read-only, fixed-source research probe. Never executes downloaded content.

Only source-package names and hashes, firmware inventories and comparisons are
reported. Downloads live in a TemporaryDirectory and are not uploaded by CI.
A matching expected hash is not a decoded payload or signature verification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import urllib.parse
import urllib.request
import zipfile

from sl3p_inspect import inspect, FormatError

SOURCES = {
    'sl3_420': 'https://leica-camera.com/sites/default/files/SL3__420.lfu',
    'q3_411': 'https://leica-camera.com/sites/default/files/Q3___411.lfu',
    'q3_oss': 'https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip',
}
MAX_DOWNLOAD = 400 * 1024 * 1024


def allowed_url(url: str) -> bool:
    p = urllib.parse.urlparse(url)
    return (p.scheme == 'https' and p.hostname == 'leica-camera.com'
            and p.username is None and p.password is None
            and p.port in (None, 443) and p.path.startswith('/sites/default/files/'))


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError('redirect outside fixed Leica download origin')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, destination: Path) -> dict:
    if not allowed_url(url):
        raise ValueError('unapproved download URL')
    opener = urllib.request.build_opener(SafeRedirect)
    request = urllib.request.Request(url, headers={'User-Agent': 'SL3Camera-read-only-research/1D'})
    h = hashlib.sha256()
    total = 0
    with opener.open(request, timeout=45) as response, destination.open('xb') as output:
        if not allowed_url(response.geturl()):
            raise ValueError('unapproved final origin')
        while block := response.read(1024 * 1024):
            total += len(block)
            if total > MAX_DOWNLOAD:
                raise ValueError('download exceeds bounded size')
            h.update(block)
            output.write(block)
    return {'bytes': total, 'sha256': h.hexdigest()}


def compare_sections(reference: dict, candidate: dict) -> dict:
    """Keep indexes distinct; report all same-size expected-hash relationships."""
    matches = []
    for row in candidate['sections']:
        if not row['size']:
            continue
        for baseline in reference['sections']:
            if (row['size'], row['stored_sha256']) != (baseline['size'], baseline['stored_sha256']):
                continue
            matches.append({
                'reference_index': baseline['index'], 'reference_name': baseline['name'],
                'candidate_index': row['index'], 'candidate_name': row['name'],
                'size': row['size'],
                'candidate_direct_hash_verified': row['sha256_matches'],
                'reference_flags': baseline['flags'], 'candidate_flags': row['flags'],
                'same_stored_payload': (baseline['payload_sha256_after_outer_transform'] == row['payload_sha256_after_outer_transform']),
                'reference_constant_fill': baseline['constant_fill_byte'],
                'candidate_constant_fill': row['constant_fill_byte'],
            })
    nonconstant = [m for m in matches if m['reference_constant_fill'] is None and m['candidate_constant_fill'] is None]
    return {'matches': matches, 'nonconstant_matches': nonconstant,
            'caveat': 'Expected digest equality does not prove decryption, common cipher, or portable rendering.'}


def zip_inventory(path: Path) -> dict:
    """Read directory only: do not extract or execute untrusted archive members."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if len(entries) > 100000:
            raise ValueError('too many ZIP entries')
        files = [e for e in entries if not e.is_dir()]
        keywords = ('boot', 'kernel', 'linux', 'crypt', 'ssl', 'update', 'firmware', 'mbed', 'bear', 'wolf', 'license', 'readme')
        candidates = [e for e in files if any(k in e.filename.lower() for k in keywords)]
        nested = [e for e in files if e.filename.lower().endswith(('.zip', '.gz', '.bz2', '.xz', '.tar', '.tgz'))]
        def brief(e):
            return {'path': e.filename, 'bytes': e.file_size, 'packed_bytes': e.compress_size, 'crc32': f'{e.CRC:08x}'}
        return {'entries': len(entries), 'files': len(files),
                'unpacked_size': sum(e.file_size for e in files),
                'top_level_names': sorted(set(e.filename.split('/')[0] for e in entries)),
                'nested_archives': [brief(e) for e in nested][:100],
                'candidate_count': len(candidates), 'candidate_entries': [brief(e) for e in candidates][:100],
                'listing_truncated': len(nested) > 100 or len(candidates) > 100,
                'limitations': 'Directory names only, not a code audit. No archive member extracted.'}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', choices=sorted(SOURCES), required=True)
    ap.add_argument('--baseline', type=Path)
    args = ap.parse_args()
    report = {'probe': 'PUBLIC_SOURCE1D', 'source': args.source, 'url': SOURCES[args.source]}
    try:
        with tempfile.TemporaryDirectory(prefix='sl3-public-') as td:
            local = Path(td) / 'download'
            report['download'] = download(report['url'], local)
            if args.source == 'q3_oss':
                report['archive'] = zip_inventory(local)
            else:
                candidate = inspect(local)
                report['format'] = {k: candidate[k] for k in ['input_sha256', 'input_size', 'internal_identifier', 'raw_version_bytes_hex', 'directory', 'counts']}
                if args.baseline is not None:
                    reference = json.loads(args.baseline.read_text())
                    report['comparison'] = compare_sections(reference, candidate)
                report['section_fingerprints'] = [
                    {k: row[k] for k in ['index', 'name', 'size', 'flags', 'stored_sha256']}
                    for row in candidate['sections'] if row['size'] and row['flags'] == 3]
                report['nonconstant_direct_sections'] = [
                    {k: row[k] for k in ['index', 'name', 'size', 'stored_sha256']}
                    for row in candidate['sections']
                    if row['sha256_matches'] and row['size'] and row['constant_fill_byte'] is None]
                report['section_names'] = [row['name'] for row in candidate['sections']]
            report['status'] = 'inspected'
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        report['status'] = 'failed'
        report['error_type'] = type(exc).__name__
        report['error'] = str(exc)[:400]
    print('PUBLIC_PROBE_JSON_BEGIN')
    print(json.dumps(report, indent=2))
    print('PUBLIC_PROBE_JSON_END')
    if report['status'] != 'inspected':
        raise SystemExit(1)


if __name__ == '__main__':
    main()
