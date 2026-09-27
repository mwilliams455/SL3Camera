#!/usr/bin/env python3
"""Compare the measured SL3 4.2.0 source with SL3-P 4.2.1 fingerprints.

Pins both inputs. No firmware bytes, metadata16 values or decryption guesses
are emitted. Equality is expected-content identity, not caller semantics.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import tempfile
from sl3p_loader_source_probe import acquire
from sl3p_related_upd_probe import inventory_projection, compare
from sl3p_inspect import inspect

URL = 'https://leica-camera.com/sites/default/files/SL3__420.lfu'
SOURCE_SHA = '120a43f442036f62c0092d8976342e264082cfd45f0c3e8471c705efb40a6bc5'
SOURCE_SIZE = 195198464
BASE_SHA = 'b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8'
BASE_CANONICAL_SHA = '36180f1cdf7144d66d28a0ee20f8d3fe6d0366e6adade2814443021a7b05e269'


def canonical_sha(d: dict) -> str:
    return hashlib.sha256(json.dumps(d, separators=(',', ':')).encode()).hexdigest()


def check_digest(data: bytes, expected: str) -> None:
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError('source bytes do not match pinned measurement')


def content_summary(base: dict, candidate: dict) -> dict:
    pairs = compare(base, candidate)['same_size_expected_hash_pairs']
    protected = [p for p in pairs if p['both_flag3']]
    matching_indexes = sorted({p['baseline_index'] for p in protected})
    # Do not count the already known constant FF regions as shared code.
    nonfill = [i for i in matching_indexes if i not in (8, 10)]
    indexed = {s[0]: s for s in base['sections']}
    unmatched = [s[0] for s in base['sections'] if s[3] == 3 and s[0] not in matching_indexes]
    def by_occurrence(rows):
        counts, result = Counter(), {}
        for row in rows:
            key = (row[1], counts[row[1]])
            counts[row[1]] += 1
            result[key] = row
        return result
    aa, bb = by_occurrence(base['sections']), by_occurrence(candidate['sections'])
    size_changes = []
    for key in aa.keys() & bb.keys():
        if aa[key][2] != bb[key][2]:
            size_changes.append({'name': key[0], 'occurrence': key[1],
                                 'sl3p_bytes': aa[key][2], 'sl3_bytes': bb[key][2]})
    return {
        'same_expected_content_protected_pairs': protected,
        'matched_protected_sections': len(matching_indexes),
        'matched_protected_section_indexes': matching_indexes,
        'matched_protected_excluding_known_ff': len(nonfill),
        'matched_protected_excluding_known_ff_names': [indexed[i][1] for i in nonfill],
        'matched_protected_excluding_known_ff_stored_bytes': sum(indexed[i][2] for i in nonfill),
        'unmatched_protected_section_names': [indexed[i][1] for i in unmatched],
        'all_protected_matches_have_different_stored_hashes': bool(protected) and all(not p['stored_bytes_hash_equal'] for p in protected),
        'all_protected_matches_have_different_metadata_hashes': bool(protected) and all(not p['metadata_hash_equal'] for p in protected),
        'same_name_size_changes': sorted(size_changes, key=lambda x: x['name']),
        'sl3p_only_names': sorted({k[0] for k in aa.keys() - bb.keys()}),
        'sl3_only_names': sorted({k[0] for k in bb.keys() - aa.keys()}),
        'caution': 'Nonfill excludes only the two proven FF sections. Other matching protected regions may be defaults or reserved content; no code, neural-network or calibration semantics are inferred.'}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    if a.out.exists(): ap.error('refusing to overwrite output')
    base = json.loads(a.baseline.read_text())
    if base['input_sha256'] != BASE_SHA or canonical_sha(base) != BASE_CANONICAL_SHA:
        raise ValueError('baseline fingerprint projection differs from reviewed input')
    raw = acquire(URL, SOURCE_SIZE)
    check_digest(raw, SOURCE_SHA)
    with tempfile.TemporaryDirectory(prefix='sl3-pair-') as d:
        path = Path(d) / 'source.lfu'
        path.write_bytes(raw)
        inv = inspect(path)
    candidate = inventory_projection(inv)
    report = {'tool': 'PAIR_SOURCE1E', 'source_url': URL,
        'baseline_sha256': BASE_SHA, 'candidate_sha256': SOURCE_SHA,
        'candidate_input_size': len(raw), 'candidate_identifier': candidate['internal_identifier'],
        'candidate_crc_matches': candidate['crc_matches'],
        'candidate_section_count': len(candidate['sections']),
        'candidate_classifications': candidate['classification_counts'],
        'candidate_readable_nonconstant': candidate['readable_nonconstant_indexes'],
        'comparison': content_summary(base, candidate),
        'lut_data': [{'index': s['index'], 'size': s['size'],
                      'fill_byte': s['constant_fill_byte'], 'hash_verified': s['sha256_matches']}
                     for s in inv['sections'] if s['name'] == 'lut_data'],
        'temporary_binary_deleted': True, 'proprietary_bytes_published': False}
    a.out.parent.mkdir(parents=True, exist_ok=True)
    with a.out.open('x') as f: json.dump(report, f, indent=2); f.write('\n')
    print('PAIR_SOURCE1E_JSON_BEGIN')
    print(json.dumps(report, separators=(',', ':')))
    print('PAIR_SOURCE1E_JSON_END')


if __name__ == '__main__': main()
