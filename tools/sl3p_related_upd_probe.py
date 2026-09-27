#!/usr/bin/env python3
"""Inspect the official SL3-family source as data, not a presumed SL3-P decoder."""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import tempfile
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener
from sl3p_loader_source_probe import VendorRedirect, approved, acquire
from sl3p_inspect import inspect

PAGE = 'https://leica-camera.com/en-int/photography/cameras/sl/sl3-black/downloads'


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.urls = []
    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            href = dict(attrs).get('href', '')
            u = urljoin(PAGE, href)
            if approved(u) and urlparse(u).path.lower().endswith('.lfu'):
                if u not in self.urls:
                    self.urls.append(u)


def inventory_projection(inv: dict) -> dict:
    return {'input_sha256': inv['input_sha256'], 'input_size': inv['input_size'],
            'internal_identifier': inv['internal_identifier'],
            'crc_matches': inv['crc32_region']['matches'],
            'columns': ['index', 'name', 'size', 'flags', 'expected_sha256',
                        'stored_payload_sha256', 'metadata16_sha256'],
            'sections': [[s['index'], s['name'], s['size'], s['flags'],
                          s['stored_sha256'], s['payload_sha256_after_outer_transform'],
                          hashlib.sha256(bytes.fromhex(s['unknown_16_bytes'])).hexdigest()]
                         for s in inv['sections']],
            'classification_counts': dict(Counter(s['classification'] for s in inv['sections'])),
            'readable_nonconstant_indexes': [s['index'] for s in inv['sections']
                                           if s['classification'] == 'hash_verified_bytes']}


def compare(baseline: dict, other: dict) -> dict:
    matches = []
    # Compare across names/offsets; preserve duplicate names and empty/fill status.
    for a in baseline['sections']:
        for b in other['sections']:
            if a[2] and a[2] == b[2] and a[4] == b[4]:
                matches.append({'baseline_index': a[0], 'baseline_name': a[1],
                                'other_index': b[0], 'other_name': b[1], 'size': a[2],
                                'stored_bytes_hash_equal': a[5] == b[5],
                                'metadata_hash_equal': a[6] == b[6],
                                'both_flag3': a[3] == b[3] == 3})
    return {'same_size_expected_hash_pairs': matches,
            'caution': 'Expected-content equality does not identify decryption or shared runtime behavior.'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    if args.out.exists(): ap.error('refusing to overwrite output')
    report = {'tool': 'RELATED_UPD1E', 'page': PAGE, 'candidates': [],
              'temporary_binary_deleted': False, 'proprietary_bytes_published': False}
    try:
        with build_opener(VendorRedirect()).open(Request(PAGE, headers={'User-Agent': 'Mozilla/5.0'}), timeout=30) as r:
            html = r.read(4 * 1024 * 1024 + 1)
        if len(html) > 4 * 1024 * 1024: raise ValueError('page limit exceeded')
        links = Links(); links.feed(html.decode('utf-8'))
        report['official_lfu_links'] = links.urls
        if not 1 <= len(links.urls) <= 3: raise ValueError('unexpected official download count')
        for url in links.urls:
            entry = {'url': url}
            report['candidates'].append(entry)
            try:
                data = acquire(url, None)
                entry['download_bytes'] = len(data)
                entry['download_sha256'] = hashlib.sha256(data).hexdigest()
                with tempfile.TemporaryDirectory(prefix='sl3-related-') as d:
                    path = Path(d) / 'candidate.lfu'
                    path.write_bytes(data)
                    inv = inspect(path)
                projection = inventory_projection(inv)
                entry['inventory'] = projection
                if args.baseline:
                    entry['comparison'] = compare(json.loads(args.baseline.read_text()), projection)
                entry['status'] = 'container_verified'
            except Exception as exc:
                entry['status'] = 'failed'
                entry['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
        report['temporary_binary_deleted'] = True
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)[:200]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print('RELATED_UPD1E_JSON_BEGIN')
    print(json.dumps(report, indent=2))
    print('RELATED_UPD1E_JSON_END')
    if not any(x['status'] == 'container_verified' for x in report['candidates']):
        raise SystemExit(1)


if __name__ == '__main__': main()
