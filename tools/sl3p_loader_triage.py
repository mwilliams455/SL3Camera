#!/usr/bin/env python3
"""Read-only loader-candidate triage for the observed UPD layout; not a decoder.

Reuses the unchanged CONTAINER1A parser. Section names suggest investigation
roles, not executable architecture, target hardware, or compatibility. A matched
hash of nonconstant bytes is an inspection candidate, not proof of loader code.
No extraction, network access, flashing, or repository writes are performed.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

from sl3p_inspect import FormatError, inspect


def suggested_role(name: str) -> str | None:
    if name == 'boot' or re.fullmatch(r'loader[0-9]+', name):
        return 'boot_or_loader_name'
    if re.fullmatch(r'postboot[0-9]+_r', name):
        return 'postboot_name'
    if name in ('program', 'compress_pr'):
        return 'program_name'
    return None


def summarize(inv: dict) -> dict:
    roles = []
    direct_candidates = []
    for s in inv['sections']:
        classification = s['classification']
        if classification == 'hash_verified_bytes':
            if not s['size'] or not s['sha256_matches'] or s['constant_fill_byte'] is not None:
                raise ValueError('Inconsistent readable-candidate classification')
            direct_candidates.append(s['index'])
        role = suggested_role(s['name'])
        if role is not None:
            roles.append({
                'index': s['index'], 'name': s['name'], 'suggested_role': role,
                'file_offset': s['file_offset'], 'size': s['size'],
                'target_offset_unconfirmed': s['target_offset_unconfirmed'],
                'flags': s['flags'], 'classification': classification,
                'candidate_for_content_inspection': classification == 'hash_verified_bytes',
            })
    return {
        'tool': 'SL3P_LOADER_TRIAGE1D',
        'parser': inv['tool'], 'input_name': inv['input_name'],
        'input_sha256': inv['input_sha256'], 'input_size': inv['input_size'],
        'internal_identifier': inv['internal_identifier'],
        'crc_verified': bool(inv['crc32_region']['matches']),
        'section_count': len(inv['sections']),
        'classification_counts': dict(Counter(s['classification'] for s in inv['sections'])),
        'hash_verified_nonconstant_section_indexes': direct_candidates,
        'name_suggested_sections': roles,
        'name_suggested_readable_candidate_indexes': [
            s['index'] for s in roles if s['candidate_for_content_inspection']],
        'limitations': [
            'Recognizes only the observed UPD layout; other formats must be investigated separately.',
            'CRC and hashes do not authenticate a vendor signature.',
            'Names do not identify executable instructions, decryption routines, or shared hardware.',
            'A readable candidate still needs disassembly and caller/data-flow validation.',
            'Target offsets are not established runtime addresses.',
        ],
    }


def run(path: Path) -> dict:
    return summarize(inspect(path))


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
        print(json.dumps({k: result[k] for k in (
            'section_count', 'classification_counts',
            'name_suggested_readable_candidate_indexes')}, indent=2))
        return 0
    except (OSError, ValueError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
