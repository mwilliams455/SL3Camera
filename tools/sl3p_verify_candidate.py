#!/usr/bin/env python3
"""Verify exact length and SHA-256 of a proposed decoded section.

Does not decrypt, execute or install any code. A matching directory digest
is consistency evidence, not authentication of Leica's firmware signature.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from sl3p_inspect import inspect,raw_sha256


def verify(row:dict,candidate:Path)->dict:
    size=candidate.stat().st_size;digest=raw_sha256(candidate)
    return {'section_index':row['index'],'section_name':row['name'],'expected_size':row['size'],
            'candidate_size':size,'expected_sha256':row['stored_sha256'],'candidate_sha256':digest,
            'length_matches':size==row['size'],'sha256_matches':digest==row['stored_sha256'],
            'passes':size==row['size'] and digest==row['stored_sha256']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('index',type=int);p.add_argument('candidate',type=Path);a=p.parse_args()
    try:
        inv=inspect(a.firmware)
        if not 0<=a.index<len(inv['sections']):raise ValueError('Invalid section index')
        r=verify(inv['sections'][a.index],a.candidate);print(json.dumps(r,indent=2));raise SystemExit(0 if r['passes'] else 1)
    except (OSError,ValueError,struct.error) as e:p.exit(2,f'error: {e}\n')
