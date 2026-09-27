#!/usr/bin/env python3
"""Bounded read-only search of Leica's hash-pinned public source release.

Never extracts a member to its named path, executes code, or reports key bytes.
Source membership is not evidence that a component implements SL3-P decryption.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import tempfile
import zipfile
from sl3p_public_source_probe import download, SOURCES

OSS_SHA256 = 'ab6531df4770a0dd0e67d090f470321bc294078e020b2f21286f1dc8d0e7bb18'
MEMBERS = {
    'uboot': '20260601_OSS/u-boot.tar.gz',
    'linux': '20260601_OSS/linux-4.19.124.tar.gz',
    'freertos': '20260601_OSS/FreeRTOS-202212.00.tar.bz2',
}
EXACT = ('loader1', 'compress_pr', 'postboot1_r', 'postboot2_r', 'muf_header',
         'raw_kizu_c', 'hm_d_reid', 'MC7251', 'MC7231', 'CAYMN')
VENDOR = ('leica', 'milbeaut', 'm10v', 'm20v', 'm30v', 'mb8ac', 'socionext')
CRYPTO = re.compile(rb'\b(?:aes|decrypt|encrypt|secure|sha256|rsa|ecdsa)\w*', re.I)
LIMIT_MEMBER = 4 * 1024 * 1024
LIMIT_TOTAL = 1024 * 1024 * 1024
LIMIT_FILES = 100000


def scan_tar(stream, *, total_limit=LIMIT_TOTAL, member_limit=LIMIT_MEMBER, file_limit=LIMIT_FILES):
    terms = EXACT + VENDOR + ('UPD',)
    results = {t: {'files': 0, 'examples': []} for t in terms}
    vendor_paths, vendor_crypto, selected = [], [], []
    counts = dict(entries=0, regular_files=0, scanned_files=0, skipped_large=0,
                  skipped_binary=0, skipped_nonregular=0, declared_regular_bytes=0,
                  scanned_bytes=0)
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for entry in archive:
            counts['entries'] += 1
            if counts['entries'] > file_limit:
                raise ValueError('archive member-count budget exceeded')
            if not entry.isfile():
                counts['skipped_nonregular'] += 1
                continue
            counts['regular_files'] += 1
            if entry.size < 0:
                raise ValueError('negative archive member size')
            counts['declared_regular_bytes'] += entry.size
            if counts['declared_regular_bytes'] > total_limit:
                raise ValueError('archive uncompressed-size budget exceeded')
            lowerpath = entry.name.lower()
            if any(t in lowerpath for t in VENDOR):
                vendor_paths.append(entry.name)
            if entry.size > member_limit:
                counts['skipped_large'] += 1
                continue
            source = archive.extractfile(entry)
            if source is None:
                raise ValueError('regular source member unreadable')
            with source:
                data = source.read(member_limit + 1)
            if len(data) != entry.size:
                raise ValueError('source member length mismatch')
            if b'\0' in data:
                counts['skipped_binary'] += 1
                continue
            counts['scanned_files'] += 1
            counts['scanned_bytes'] += len(data)
            lower = data.lower()
            digest = hashlib.sha256(data).hexdigest()
            lines = data.splitlines()
            present = []
            for term in terms:
                needle = term.encode()
                haystack = data
                if term in VENDOR:
                    haystack = lower
                if term == 'UPD':
                    exists = re.search(rb'\bUPD\b', data) is not None
                else:
                    exists = needle in haystack
                if not exists:
                    continue
                present.append(term)
                row = results[term]
                row['files'] += 1
                if len(row['examples']) < 30:
                    line_numbers = [i for i, line in enumerate(lines, 1)
                        if ((re.search(rb'\bUPD\b', line) is not None) if term == 'UPD'
                            else needle in (line.lower() if term in VENDOR else line))]
                    row['examples'].append({'path': entry.name, 'sha256': digest,
                                            'lines': line_numbers[:12]})
            specific = any(t in present for t in EXACT + VENDOR[:6]) or any(t in lowerpath for t in VENDOR[:6])
            if specific and CRYPTO.search(data):
                vendor_crypto.append({'path': entry.name, 'sha256': digest,
                                     'matched_terms': present})
            # Public source path/line excerpts only for direct package markers;
            # crypto lines are never emitted by this broad reconnaissance.
            if specific and len(selected) < 80:
                excerpt = []
                for i, line in enumerate(lines, 1):
                    if (any(t.encode() in line for t in EXACT) or
                        any(t.encode() in line.lower() for t in VENDOR[:6])) and not CRYPTO.search(line):
                        excerpt.append({'line': i, 'text': line.decode('utf-8', 'replace')[:180]})
                        if len(excerpt) >= 3:
                            break
                selected.append({'path': entry.name, 'sha256': digest, 'excerpts': excerpt})
    return {'counts': counts, 'term_results': results,
            'vendor_path_count': len(vendor_paths), 'vendor_paths': vendor_paths[:160],
            'vendor_crypto_count': len(vendor_crypto), 'vendor_crypto': vendor_crypto[:100],
            'specific_files': selected,
            'limits': {'member_bytes': member_limit, 'total_bytes': total_limit, 'entries': file_limit},
            'caveat': 'Read-only lexical reconnaissance, not exhaustive semantic audit or a decoder. Paths may be generic upstream support.'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--part', choices=sorted(MEMBERS), required=True)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='sl3-oss-audit-') as td:
        local = Path(td) / 'source.zip'
        downloaded = download(SOURCES['q3_oss'], local)
        if downloaded['sha256'] != OSS_SHA256:
            raise ValueError('official source archive changed; review before accepting')
        with zipfile.ZipFile(local) as archive:
            info = archive.getinfo(MEMBERS[args.part])
            if info.file_size > 200 * 1024 * 1024:
                raise ValueError('nested compressed member exceeds budget')
            with archive.open(info) as nested:
                result = scan_tar(nested)
        report = {'probe': 'OSS_AUDIT1D', 'part': args.part,
                  'source': SOURCES['q3_oss'], 'download': downloaded,
                  'member': MEMBERS[args.part], 'result': result}
        print('OSS_AUDIT_JSON_BEGIN')
        print(json.dumps(report, indent=2))
        print('OSS_AUDIT_JSON_END')

if __name__ == '__main__':
    main()
