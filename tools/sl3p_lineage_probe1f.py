#!/usr/bin/env python3
"""Read-only, official-source UPD lineage probe. Never executes firmware.

Downloaded data stays in temporary storage. Output contains selected structural
measurements and hashes, not payload bytes or raw cryptographic metadata.
Unknown layouts are NOT accepted as UPD packages merely because markers occur.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import tempfile
from sl3p_inspect import inspect, XOR_FF
from sl3p_loader_source_probe import acquire, locations
from sl3p_related_upd_probe import inventory_projection, compare

SOURCES = {
    'sl601_41': 'https://leica-camera.com/sites/default/files/601__41_.lfu',
    'sl2_630': 'https://leica-camera.com/sites/default/files/SL2__630.lfu',
    'q2m_510': 'https://leica-camera.com/sites/default/files/q2m_510.lfu',
    'sl_lenses11': 'https://leica-camera.com/sites/default/files/SLLens11.plf',
    'sl_70200_11': 'https://leica-camera.com/sites/default/files/70200_11.plf',
}
EXACT = (b'UPD\0', b'leica\0', b'loader1', b'postboot1_r', b'compress_pr',
         b'eep_ow_a', b'lut_data', b'\x7fELF', b'PK\x03\x04')
TERMS = (b'decrypt', b'encrypt', b'bootloader', b'fwupdate', b'sha256', b'aes_')
LIMIT = 256 * 1024 * 1024


def views(data: bytes) -> tuple[str, bytes]:
    if data[:4] == b'UPD\0':
        return 'already_normalized', data
    if data[:4].translate(XOR_FF) == b'UPD\0':
        return 'outer_XOR_FF', data.translate(XOR_FF)
    return 'raw_unknown', data


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum(n / len(data) * math.log2(n / len(data)) for n in Counter(data).values())


def outline(data: bytes) -> dict:
    if not data or len(data) > LIMIT:
        raise ValueError('input size outside bounds')
    view, b = views(data)
    windows = [entropy(b[p:p+65536]) for p in range(0, len(b), 65536)]
    # Only signature bytes, counts, offsets, sizes and entropy; no string dumps.
    return {'view': view, 'magic4_hex': b[:4].hex(),
            'entropy_64k_windows': {'count': len(windows), 'min': min(windows),
                                   'max': max(windows), 'below_7_5': sum(x < 7.5 for x in windows)},
            'markers': {x.hex(): locations(b, x, cap=12) for x in EXACT},
            'terms': {x.decode('ascii'): locations(b.lower(), x, cap=8) for x in TERMS},
            'warning': 'Signatures and entropy do not establish readable code or a cipher.'}


def match_summary(baseline: dict, other: dict) -> dict:
    pairs = compare(baseline, other)['same_size_expected_hash_pairs']
    matches = [p for p in pairs if p['both_flag3']]
    indexes = sorted({p['baseline_index'] for p in matches})
    return {'protected_pairs': matches, 'distinct_baseline_protected_indexes': indexes,
            'distinct_baseline_protected_count': len(indexes),
            'clear_counterpart_pairs': [p for p in pairs
                 if next(a for a in baseline['sections'] if a[0] == p['baseline_index'])[3] == 3
                 and next(a for a in other['sections'] if a[0] == p['other_index'])[4] ==
                     next(a for a in other['sections'] if a[0] == p['other_index'])[5]],
            'warning': 'Expected-content hash matches do not establish code or runtime semantics.'}


def padded_matches(data: bytes, baseline: dict) -> list[dict]:
    """Bounded test: complete downloaded file, or that file padded at end only."""
    matches = []
    targets = [s for s in baseline['sections'] if s[2] and s[3] == 3]
    for label, b in [('raw', data), ('XOR_FF', data.translate(XOR_FF))]:
        for size in sorted({s[2] for s in targets if len(b) <= s[2] <= 32*1024*1024}):
            for fill in ([None] if len(b) == size else [0, 255]):
                h = hashlib.sha256(b)
                left = size - len(b)
                while left:
                    n = min(left, 1024*1024); h.update(bytes([fill]) * n); left -= n
                digest = h.hexdigest()
                for s in targets:
                    if s[2] == size and s[4] == digest:
                        matches.append({'baseline_index': s[0], 'baseline_name': s[1],
                                        'view': label, 'trailing_fill': fill, 'size': size})
    return matches


def inspect_bytes(data: bytes, baseline: dict) -> dict:
    result = {'download_bytes': len(data), 'download_sha256': hashlib.sha256(data).hexdigest(),
              'outline': outline(data)}
    with tempfile.TemporaryDirectory(prefix='sl3-lineage-') as d:
        p = Path(d) / 'candidate.lfu'; p.write_bytes(data)
        try:
            inv = inspect(p)
        except (ValueError, OSError) as exc:
            result['status'] = 'strict_UPD_not_validated'
            result['parse_error_type'] = type(exc).__name__
            # Unknown structures are never promoted by marker matches.
        else:
            result['status'] = 'strict_UPD_verified'
            projected = inventory_projection(inv)
            result['inventory'] = {k: v for k, v in projected.items() if k != 'sections'}
            result['section_summary_columns'] = ['index', 'name', 'size', 'flags', 'classification', 'expected_sha256']
            result['section_summary'] = [[s['index'], s['name'], s['size'], s['flags'], s['classification'], s['stored_sha256']] for s in inv['sections']]
            result['comparison'] = match_summary(baseline, projected)
            result['readable_nonconstant'] = [
                {'index': s['index'], 'name': s['name'], 'size': s['size'],
                 'sha256': s['stored_sha256'], 'outline': outline(
                    data[s['file_offset']:s['file_offset']+s['size']].translate(XOR_FF)
                    if inv['outer_transform'] == 'XOR_FF' else
                    data[s['file_offset']:s['file_offset']+s['size']])}
                for s in inv['sections'] if s['classification'] == 'hash_verified_bytes']
    result['whole_file_or_trailing_fill_matches'] = padded_matches(data, baseline) if len(data) <= 24*1024*1024 else []
    result['temporary_binary_deleted'] = True
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', choices=SOURCES, action='append', required=True)
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    if args.out.exists(): ap.error('refusing to overwrite output')
    baseline = json.loads(args.baseline.read_text())
    report = {'tool': 'UPD_LINEAGE1F', 'baseline_sha256': baseline['input_sha256'],
              'sources': [], 'firmware_executed': False, 'payload_bytes_published': False}
    for source in dict.fromkeys(args.source):
        row = {'source_id': source, 'source_url': SOURCES[source]}
        try:
            data = acquire(SOURCES[source], None)
            row.update(inspect_bytes(data, baseline))
            del data
        except Exception as exc:
            row['status'] = 'acquisition_or_inspection_failed'
            row['error_type'] = type(exc).__name__
            if getattr(exc, 'code', None): row['http_code'] = exc.code
        report['sources'].append(row)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print('UPD_LINEAGE1F_JSON_BEGIN')
    print(json.dumps(report, separators=(',', ':')))
    print('UPD_LINEAGE1F_JSON_END')
    if not any(s.get('download_bytes') for s in report['sources']):
        raise SystemExit(1)


if __name__ == '__main__': main()
