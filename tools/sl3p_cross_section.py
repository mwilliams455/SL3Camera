#!/usr/bin/env python3
"""Exact pooled block/metadata relationship audit; not cipher identification.

RESEARCH1B compared blocks within sections and same-offset pairs. This tool
pools all opaque flag-3 sections and compares aligned 16-byte blocks at every
relative block position across all section pairs. It also searches the pooled
block set for each protected section's metadata16 (and explicitly stated byte
conventions). Reports offsets/counts only, never payload bytes or guessed keys.

Requires numpy. Full-file checks use the unchanged CONTAINER1A parser. Alignment
is relative to each section. No byte-sliding, near-match, plaintext, or decoded
instruction search is claimed. Default memory-bound input limit: 512 MiB of
opaque bytes. No network, extraction, camera access, or Git writes.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
from pathlib import Path
import sys
from typing import Iterable
import numpy as np
from sl3p_inspect import Firmware, inspect, raw_sha256

BLOCK = 16
MAX_BYTES = 512 * 1024 * 1024


def field_conventions(field: bytes) -> dict[str, bytes]:
    if len(field) != BLOCK:
        raise ValueError('metadata16 must contain exactly 16 bytes')
    result = {}
    for width in (1, 2, 4, 8, 16):
        value = b''.join(field[o:o+width][::-1] for o in range(0, BLOCK, width))
        result[f'reverse_words_{width}B'] = value
        result[f'reverse_words_{width}B_xor_ff'] = bytes(x ^ 255 for x in value)
    return result


def audit_blocks(sections: Iterable[tuple[int, str, bytes, bytes]],
                 max_bytes: int = MAX_BYTES, max_examples: int = 32) -> dict:
    """Input items: (stable directory index, name, stored normalized data, field16)."""
    if max_bytes < 0 or max_examples < 0:
        raise ValueError('Limits must be nonnegative')
    specs = list(sections)
    indexes = [s[0] for s in specs]
    if len(set(indexes)) != len(indexes):
        raise ValueError('Section indexes must be unique; names may repeat')
    for index, name, data, field in specs:
        if not isinstance(index, int) or index < 0:
            raise ValueError('Section indexes must be nonnegative integers')
        if len(data) % BLOCK:
            raise ValueError('All input section lengths must be divisible by 16')
        if len(field) != BLOCK:
            raise ValueError('All metadata fields must be 16 bytes')
    total_bytes = sum(len(s[2]) for s in specs)
    if total_bytes > max_bytes:
        raise ValueError('Opaque-byte limit exceeded')
    n = total_bytes // BLOCK
    values = np.empty(n, dtype='V16')
    starts = []
    ends = []
    at = 0
    for _, _, data, _ in specs:
        count = len(data) // BLOCK
        starts.append(at)
        values[at:at+count] = np.frombuffer(data, dtype='V16')
        at += count
        ends.append(at)
    order = np.argsort(values, kind='stable')
    sorted_values = values[order]
    # Equal byte strings are consecutive in this full exact sort. No hashes.
    adjacent = np.flatnonzero(sorted_values[1:] == sorted_values[:-1])
    starts_array = np.asarray(starts, dtype=np.int64)
    ends_array = np.asarray(ends, dtype=np.int64)

    def location(global_index: int) -> dict:
        slot = int(np.searchsorted(ends_array, global_index, side='right'))
        return {'index': specs[slot][0], 'name': specs[slot][1],
                'relative_offset': int((global_index - starts_array[slot]) * BLOCK)}

    def slot_for(global_index: int) -> int:
        return int(np.searchsorted(ends_array, global_index, side='right'))

    # Start/end positions of equal-value groups; no quadratic enumeration.
    groups = []
    if len(adjacent):
        boundaries = np.flatnonzero(np.diff(adjacent) != 1)
        group_starts = np.concatenate((adjacent[:1], adjacent[boundaries + 1]))
        group_ends = np.concatenate((adjacent[boundaries] + 2, adjacent[-1:] + 2))
        groups = zip(group_starts.tolist(), group_ends.tolist())
    cross_groups = 0
    cross_pair_count = 0
    within_pair_count = 0
    examples = []
    section_pairs = defaultdict(lambda: {'shared_block_values': 0, 'equal_block_pairs': 0})
    repeated_values = 0
    for begin, end in groups:
        repeated_values += 1
        members = [int(v) for v in order[begin:end]]
        counts = defaultdict(int)
        for member in members:
            counts[slot_for(member)] += 1
        within_pair_count += sum(c*(c-1)//2 for c in counts.values())
        if len(counts) < 2:
            continue
        cross_groups += 1
        slots = sorted(counts)
        for a_i, a in enumerate(slots):
            for b in slots[a_i + 1:]:
                key = (specs[a][0], specs[b][0])
                matches = counts[a] * counts[b]
                cross_pair_count += matches
                section_pairs[key]['shared_block_values'] += 1
                section_pairs[key]['equal_block_pairs'] += matches
        if len(examples) < max_examples:
            examples.append({'occurrences': len(members),
                             'locations': [location(v) for v in members[:max_examples]],
                             'locations_truncated': len(members) > max_examples})

    metadata_matches = []
    metadata_query_count = 0
    for index, name, _, field in specs:
        for convention, value in field_conventions(field).items():
            metadata_query_count += 1
            query = np.frombuffer(value, dtype='V16')[0]
            lo = int(np.searchsorted(sorted_values, query, side='left'))
            hi = int(np.searchsorted(sorted_values, query, side='right'))
            if hi > lo:
                metadata_matches.append({'metadata_owner_index': index,
                    'metadata_owner_name': name, 'convention': convention,
                    'occurrences': hi-lo,
                    'locations': [location(int(v)) for v in order[lo:min(hi, lo+max_examples)]],
                    'locations_truncated': hi-lo > max_examples})
    return {
        'sections_audited': len(specs), 'bytes_audited': total_bytes,
        'block_size': BLOCK, 'aligned_blocks': n,
        'distinct_block_values': int(n - len(adjacent)),
        'repeated_block_values': repeated_values,
        'within_section_equal_block_pairs': within_pair_count,
        'cross_section_shared_block_values': cross_groups,
        'cross_section_equal_block_pairs': cross_pair_count,
        'section_pair_matches': [dict(indexes=list(key), **value)
                                 for key, value in sorted(section_pairs.items())],
        'cross_section_examples': examples,
        'cross_section_examples_truncated': cross_groups > len(examples),
        'metadata_queries_including_convention_duplicates': metadata_query_count,
        'metadata_matches': metadata_matches,
        'scope': 'All complete section-relative aligned 16-byte blocks; exact byte equality, pooled across sections. Not a byte-sliding or cryptographic decoding test.',
    }


def run(path: Path, max_bytes: int = MAX_BYTES) -> dict:
    inv = inspect(path)
    fw = Firmware(path)
    rows = [s for s in inv['sections'] if s['flags'] == 3 and
            s['classification'] == 'opaque_not_decrypted' and s['size']]
    if sum(s['size'] for s in rows) > max_bytes:
        raise ValueError('Opaque-byte limit exceeded before payload allocation')
    result = audit_blocks([
        (s['index'], s['name'], fw.read(s['file_offset'], s['size']),
         bytes.fromhex(s['unknown_16_bytes'])) for s in rows], max_bytes=max_bytes)
    # Detect source changes during a long read. Never rewrite the original.
    if raw_sha256(path) != inv['input_sha256']:
        raise ValueError('Input changed during the audit')
    return {'tool': 'SL3P_CROSS_SECTION1D', 'input_sha256': inv['input_sha256'],
            'input_name': inv['input_name'], 'input_size': inv['input_size'],
            'internal_identifier': inv['internal_identifier'], 'crc_verified': True,
            'result': result,
            'limitations': [
                'No protected section has been decoded by this tool.',
                'No matches would only exclude literal aligned block reuse and the enumerated metadata representations.',
                'Different stored bytes do not establish a cipher, key, IV, nonce, signature, or hardware relationship.',
                'Empty and direct/fill sections are excluded to avoid counting padding as a protected-code relationship.',
                'Complete source hash was rechecked after measurement.',
            ]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('firmware', type=Path)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    try:
        if args.out.resolve() == args.firmware.resolve():
            raise ValueError('Output must not overwrite the input')
        if args.out.exists():
            raise FileExistsError('Refusing to overwrite existing output')
        result = run(args.firmware)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x', encoding='utf-8') as out:
            json.dump(result, out, indent=2)
            out.write('\n')
        print(json.dumps(result['result'], indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
