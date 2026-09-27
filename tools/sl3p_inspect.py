#!/usr/bin/env python3
"""Read-only SL3P_421 UPD wrapper inspector. NOT a payload decryptor or updater.

Verified against one upload only. Unknown layouts fail closed. Standard library
only; streaming reads avoid a second whole-firmware allocation. Extracted flag-3
sections remain opaque, even after the outer byte inversion is removed.
"""
from __future__ import annotations
import argparse
import collections
import csv
import hashlib
import json
import math
from pathlib import Path
import re
import struct
import sys
import zlib

XOR_FF = bytes(255 - x for x in range(256))
BLOCK = 1024 * 1024
BASE = 0x200
INNER = 0x2A0
DIRECTORY = 0x2EC
STRIDE = 0x5C

class FormatError(ValueError):
    """The input does not match the tested wrapper layout."""

class Firmware:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.size = self.path.stat().st_size
        with self.path.open('rb') as stream:
            magic = stream.read(4)
        if magic == b'UPD\0':
            self.inverted = False
        elif magic.translate(XOR_FF) == b'UPD\0':
            self.inverted = True
        else:
            raise FormatError('No supported UPD signature, including XOR-FF form')

    def chunks(self, offset: int, length: int):
        if offset < 0 or length < 0 or offset + length > self.size:
            raise FormatError(f'Out-of-bounds region: {offset:#x}+{length:#x}')
        with self.path.open('rb') as stream:
            stream.seek(offset)
            remaining = length
            while remaining:
                buf = stream.read(min(BLOCK, remaining))
                if not buf:
                    raise FormatError('Input was truncated during reading')
                remaining -= len(buf)
                yield buf.translate(XOR_FF) if self.inverted else buf

    def read(self, offset: int, length: int) -> bytes:
        return b''.join(self.chunks(offset, length))


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from('<I', data, offset)[0]


def raw_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(BLOCK), b''):
            h.update(block)
    return h.hexdigest()


def inspect(path: Path) -> dict:
    fw = Firmware(path)
    header = fw.read(0, DIRECTORY)
    if header[BASE:BASE+6] != b'leica\0' or header[INNER:INNER+4] != b'UPD\0':
        raise FormatError('Unrecognized nested wrapper layout')
    body_offset, body_size, expected_crc = struct.unpack_from('<III', header, 0x38)
    if body_offset != BASE or body_size != fw.size - BASE:
        raise FormatError('Outer size/base mismatch')
    model = header[0x0C:0x1C].split(b'\0')[0].decode('ascii')
    if header[0x0C:0x1C] != header[INNER+0x0C:INNER+0x1C]:
        raise FormatError('Nested model identifier mismatch')
    data_start = BASE + u32(header, 0x2E0)
    data_size, count = struct.unpack_from('<II', header, 0x2E4)
    if not 1 <= count <= 4096:
        raise FormatError('Implausible directory count')
    if DIRECTORY + count * STRIDE > data_start or data_start + data_size != fw.size:
        raise FormatError('Directory/data bounds mismatch')
    crc = 0
    for block in fw.chunks(BASE, body_size):
        crc = zlib.crc32(block, crc)
    crc &= 0xFFFFFFFF
    if crc != expected_crc:
        raise FormatError(f'CRC mismatch: {crc:08x} != {expected_crc:08x}')

    directory = fw.read(DIRECTORY, count * STRIDE)
    rows = []
    cursor = data_start
    for index in range(count):
        e = directory[index * STRIDE:(index + 1) * STRIDE]
        name = e[:12].split(b'\0')[0].decode('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_]+', name):
            raise FormatError(f'Unsafe/unrecognized section name at {index}')
        relative, size, target, flags = struct.unpack_from('<4I', e, 12)
        off = BASE + relative
        if flags not in (2, 3) or off != cursor or off + size > fw.size:
            raise FormatError(f'Unknown flags or noncontiguous region at {index}')
        cursor = off + size
        stored_sha = e[28:60].hex()
        h = hashlib.sha256()
        sample = b''
        fill = None
        constant = bool(size)
        for block in fw.chunks(off, size):
            h.update(block)
            if len(sample) < 65536:
                sample += block[:65536 - len(sample)]
            if fill is None:
                fill = block[0]
            if constant and block.count(fill) != len(block):
                constant = False
        digest = h.hexdigest()
        match = digest == stored_sha
        frequencies = collections.Counter(sample)
        entropy = (-sum((n/len(sample)) * math.log2(n/len(sample))
                        for n in frequencies.values())) if sample else 0.0
        if flags == 2 and not match:
            raise FormatError(f'Flag-2 section hash mismatch at {index}')
        rows.append({
            'index': index, 'name': name,
            'entry_file_offset': DIRECTORY + index * STRIDE,
            'relative_offset': relative, 'file_offset': off,
            'file_offset_hex': f'0x{off:08x}', 'size': size,
            'target_offset_unconfirmed': target, 'flags': flags,
            'stored_sha256': stored_sha, 'payload_sha256_after_outer_transform': digest,
            'sha256_matches': match, 'unknown_16_bytes': e[60:76].hex(),
            'reserved_16_bytes': e[76:92].hex(),
            'entropy_first_64KiB': entropy,
            'constant_fill_byte': fill if constant else None,
            'classification': ('empty' if not size else
                ('verified_fill' if constant and match else
                 ('hash_verified_bytes' if match else 'opaque_not_decrypted'))),
        })
    if cursor != fw.size:
        raise FormatError('Section coverage does not reach EOF')
    known_fill = []
    for row in rows:
        if row['flags'] != 3 or not row['size']:
            continue
        for fill_byte in (0, 255):
            h = hashlib.sha256()
            remaining = row['size']
            while remaining:
                n = min(BLOCK, remaining)
                h.update(bytes([fill_byte]) * n)
                remaining -= n
            if h.hexdigest() == row['stored_sha256']:
                known_fill.append({'index': row['index'], 'name': row['name'],
                                   'size': row['size'], 'fill_byte': fill_byte,
                                   'stored_sha256': row['stored_sha256']})
    return {
        'tool': 'SL3P_CONTAINER1A', 'input_name': fw.path.name,
        'input_size': fw.size, 'input_sha256': raw_sha256(fw.path),
        'outer_transform': 'XOR_FF' if fw.inverted else 'already_outer_normalized',
        'internal_identifier': model,
        'raw_version_bytes_hex': header[0x1C:0x20].hex(),
        'crc32_region': {'offset': BASE, 'size': body_size,
                         'stored': f'{expected_crc:08x}', 'computed': f'{crc:08x}',
                         'matches': True},
        'directory': {'offset': DIRECTORY, 'entry_size': STRIDE, 'entry_count': count,
                       'section_offset_base': BASE, 'data_start': data_start,
                       'data_size': data_size, 'contiguous_coverage_to_eof': True},
        'counts': {'by_flags': dict(collections.Counter(r['flags'] for r in rows)),
                   'hash_matches': sum(r['sha256_matches'] for r in rows),
                   'empty': sum(not r['size'] for r in rows),
                   'nonempty_verified_fills': sum(r['classification']=='verified_fill' for r in rows)},
        'known_fill_hash_targets_in_opaque_sections': known_fill,
        'sections': rows,
        'limitations': [
            'Only outer obfuscation is removed; protected payloads remain undecoded.',
            'Flags, target offsets and unknown fields do not establish a cipher or update semantics.',
            'CRC/hash consistency is not cryptographic vendor-signature verification.',
            'Verified against the supplied SL3P_421 upload only; not a universal LFU parser.'
        ],
    }


def write_evidence(result: dict, output: Path):
    output.mkdir(parents=True, exist_ok=True)
    (output / 'firmware_inventory.json').write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    with (output / 'sections.csv').open('w', newline='', encoding='utf-8') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(result['sections'][0]))
        writer.writeheader()
        writer.writerows(result['sections'])


def extract(path: Path, result: dict, output: Path, indexes: list[int]):
    fw = Firmware(path)
    output.mkdir(parents=True, exist_ok=True)
    for index in indexes:
        if not 0 <= index < len(result['sections']):
            raise FormatError(f'Section index out of range: {index}')
        row = result['sections'][index]
        suffix = 'opaque.bin' if not row['sha256_matches'] else 'verified.bin'
        destination = output / f"{index:02d}_{row['name']}.{suffix}"
        # Never overwrite existing content, including the input.
        with destination.open('xb') as stream:
            for block in fw.chunks(row['file_offset'], row['size']):
                stream.write(block)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('firmware', type=Path)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--extract', type=int, nargs='*', default=[], metavar='INDEX',
                   help='Optional unique section indexes. Flag-3 payloads stay opaque.')
    args = p.parse_args()
    try:
        result = inspect(args.firmware)
        write_evidence(result, args.out)
        if args.extract:
            extract(args.firmware, result, args.out/'sections', args.extract)
        print(json.dumps({k: result[k] for k in ('input_sha256', 'crc32_region', 'counts')}, indent=2))
    except (OSError, ValueError, struct.error) as exc:
        p.exit(2, f'error: {exc}\n')

if __name__ == '__main__':
    main()
