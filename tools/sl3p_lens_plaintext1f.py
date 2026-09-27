#!/usr/bin/env python3
"""Verify an independently obtainable nonconstant plaintext for SL3-P lens.

Reconstruction is read-only and in memory; no firmware bytes are published.
LENS header measurements are candidates, not an asserted record specification.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from sl3p_loader_source_probe import acquire, locations

URL = 'https://leica-camera.com/sites/default/files/SLLens11.plf'
SOURCE_BYTES = 4575234
SOURCE_SHA = '9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600'
TARGET_BYTES = 20971520
TARGET_SHA = '555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1'


def reconstruct(data: bytes, source_hash: str = SOURCE_SHA,
                source_size: int = SOURCE_BYTES, target_size: int = TARGET_BYTES,
                target_hash: str = TARGET_SHA) -> tuple[bytes, dict]:
    if len(data) != source_size or hashlib.sha256(data).hexdigest() != source_hash:
        raise ValueError('standalone source identity mismatch')
    if not data.startswith(b'LENS') or len(set(data)) < 2:
        raise ValueError('not a nonconstant LENS candidate')
    if not 0 < source_size <= target_size <= 32*1024*1024:
        raise ValueError('invalid reconstruction bounds')
    plain = data + b'\0' * (target_size-len(data))
    digest = hashlib.sha256(plain).hexdigest()
    if digest != target_hash:
        raise ValueError('complete expected plaintext hash mismatch')
    return plain, {'source_bytes':len(data), 'source_sha256':source_hash,
                   'target_bytes':len(plain), 'appended_zero_bytes':target_size-len(data),
                   'target_sha256':digest, 'complete_expected_hash_matches':True,
                   'nonconstant_plaintext':True, 'payload_decryption_performed':False}


def structure(data: bytes) -> dict:
    marks = locations(data, b'LENS', cap=64)
    records = []
    for off in marks['first_offsets']:
        # Numeric candidates immediately after the magic; no UPD crypto fields,
        # instruction bytes, arbitrary string dumps, or payload extraction.
        if off + 32 <= len(data):
            words = list(struct.unpack_from('<7I', data, off+4))
            records.append({'offset':off, 'u32le_offsets_4_to_28':words,
                            'word_values_equal_remaining_file_bytes':
                                [4+i*4 for i,x in enumerate(words) if x == len(data)-off],
                            'header_candidate_only':True})
    terms = (b'fwupdate', b'bootloader', b'decrypt', b'encrypt', b'sha256', b'aes_', b'UPD\0')
    return {'lens_magic':marks, 'header_candidates':records,
            'term_hits':{x.decode().replace('\0','\\0'):locations(data.lower(),x.lower()) for x in terms},
            'meaning':'No record boundaries, instruction architecture or update-consumer semantics established.'}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--baseline', type=Path, required=True)
    ap.add_argument('--out',type=Path,required=True)
    args = ap.parse_args()
    if args.out.exists(): ap.error('refusing to overwrite output')
    baseline = json.loads(args.baseline.read_text())
    matches = [s for s in baseline['sections'] if s[1] == 'lens' and s[2] == TARGET_BYTES and s[4] == TARGET_SHA]
    if len(matches) != 1 or matches[0][0] != 33 or matches[0][3] != 3:
        raise SystemExit('baseline does not identify exactly the expected protected lens section')
    data = acquire(URL, SOURCE_BYTES)
    plain, verification = reconstruct(data)
    report = {'tool':'LENS_PLAINTEXT1F','source_url':URL,
              'baseline_input_sha256':baseline['input_sha256'], 'baseline_section':33,
              'verification':verification, 'structure':structure(data),
              'no_binary_written':True,'no_firmware_executed':True,
              'limits':['Recovered intended contents by independent source identity, not decryption.',
                        'This is not the camera base still renderer or a validated UPD protection consumer.']}
    del plain, data
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x') as f: json.dump(report,f,indent=2); f.write('\n')
    print('LENS_PLAINTEXT1F_JSON_BEGIN')
    print(json.dumps(report,separators=(',',':')))
    print('LENS_PLAINTEXT1F_JSON_END')


if __name__ == '__main__': main()
