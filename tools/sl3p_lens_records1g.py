#!/usr/bin/env python3
"""Read-only LENS directory, range and checksum audit; never executes payloads.

The 1G layout is inferred from explicit table fields and coverage of complete
independently hash-pinned files. Numeric selector and kind fields intentionally
have no lens-model, code/data, address or version semantics assigned to them.
"""
from __future__ import annotations
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import struct
import zlib

SOF = b'LENS-UPDATE-FILE-SOF:'
EOH = b'LENS-UPDATE-FILE-EOH:'
RECORD = struct.Struct('>HBIIII')
MAX_FILE = 32 * 1024 * 1024


def parse_layout(data: bytes) -> dict:
    if not isinstance(data, bytes) or not 31 <= len(data) <= MAX_FILE:
        raise ValueError('invalid input type or size')
    if not data.startswith(SOF):
        raise ValueError('missing LENS start marker')
    count = int.from_bytes(data[29:31], 'big')
    if not 0 < count <= 256:
        raise ValueError('record count outside supported bounds')
    eoh = 31 + RECORD.size * count
    end = eoh + len(EOH)
    if data[eoh:end] != EOH:
        raise ValueError('table does not end at the declared header marker')
    rows = []
    unique = {}
    for i in range(count):
        ordinal, kind, selector, offset, size, check = RECORD.unpack_from(data, 31+19*i)
        if ordinal != i:
            raise ValueError('record ordinal does not match table position')
        absent_sentinel = kind == 2 and (offset, size, check) == (0xffffffff,)*3
        present = bool(size) and not absent_sentinel
        if present:
            if offset < end or offset > len(data) or size > len(data)-offset:
                raise ValueError('payload outside the declared file bounds')
            key = (offset, size)
            if key in unique and unique[key] != check:
                raise ValueError('aliases disagree on their check value')
            unique[key] = check
        elif not absent_sentinel and offset != 0 and not end <= offset <= len(data):
            raise ValueError('empty record has invalid offset')
        rows.append({'index':i, 'kind':kind, 'selector_u32':selector,
                     'offset':offset, 'size':size, 'check_u32':check,
                     'present':present, 'absent_sentinel':absent_sentinel})
    pos = end
    for offset, size in sorted(unique):
        if offset != pos:
            raise ValueError('gap or partial overlap in unique payload ranges')
        pos = offset+size
    if pos != len(data):
        raise ValueError('unexplained trailing data')
    return {'header_word_21':int.from_bytes(data[21:23], 'big'),
            'header_word_23':int.from_bytes(data[23:25], 'big'),
            'header_byte_25':data[25], 'header_byte_26':data[26],
            'header_word_27':int.from_bytes(data[27:29], 'big'),
            'record_count':count, 'header_bytes':end,
            'empty_records':sum(not r['present'] for r in rows),
            'sentinel_records':sum(r['absent_sentinel'] for r in rows),
            'unique_payload_count':len(unique),
            'kind_counts':dict(Counter(r['kind'] for r in rows)),
            'unique_payload_bytes':len(data)-end, 'exact_range_coverage':True,
            'records':rows}


def crc32_msb(data: bytes, initial: int = 0xffffffff) -> int:
    """Non-reflected polynomial 0x04C11DB7, explicit seed, no final XOR."""
    table = []
    for n in range(256):
        c = n << 24
        for _ in range(8):
            c = ((c << 1) ^ (0x04c11db7 if c & 0x80000000 else 0)) & 0xffffffff
        table.append(c)
    c = initial
    for b in data:
        c = ((c << 8) & 0xffffffff) ^ table[((c >> 24) ^ b) & 255]
    return c


def checksum_values(data: bytes) -> dict:
    crc = zlib.crc32(data)
    crc0 = zlib.crc32(data, 0xffffffff)
    msb = crc32_msb(data)
    return {'crc32_iso_hdlc':crc, 'crc32_jamcrc':crc ^ 0xffffffff,
            'crc32_reflected_init0_final0':crc0 ^ 0xffffffff,
            'crc32_reflected_init0_finalffffffff':crc0,
            'crc32_mpeg2':msb, 'crc32_bzip2':msb ^ 0xffffffff,
            'adler32':zlib.adler32(data), 'byte_sum_mod32':sum(data) & 0xffffffff}


def audit(data: bytes) -> dict:
    result = parse_layout(data)
    payloads = []
    groups = {}
    for row in result['records']:
        if row['present']:
            groups.setdefault((row['offset'], row['size']), []).append(row)
    for (offset, size), rows in sorted(groups.items()):
        payload = data[offset:offset+size]
        values = checksum_values(payload)
        expected = rows[0]['check_u32']
        # Selected fixed signatures only; no arbitrary strings or payload bytes.
        signatures = {label:payload.find(sig) for label, sig in {
            'ELF':b'\x7fELF', 'Intel_HEX_prefix':b':02000004',
            'Srecord_S0':b'S0', 'LENS_SOF':SOF, 'ARM':b'ARM',
            'Cortex':b'Cortex', 'Renesas':b'Renesas', 'FUJITSU':b'FUJITSU',
            'UPD_NUL':b'UPD\0'}.items() if payload.find(sig) >= 0}
        p = payload.lower().find(b'fwupdate')
        tokens = []
        if p >= 0:
            for m in re.finditer(rb'[A-Za-z_][A-Za-z0-9_]{3,95}', payload[max(0,p-80):p+96]):
                if b'fwupdate' in m.group().lower(): tokens.append(m.group().decode('ascii'))
        payloads.append({'offset':offset,'size':size,
                         'record_indexes':[r['index'] for r in rows],
                         'sha256':hashlib.sha256(payload).hexdigest(),
                         'check_u32':expected,
                         'checksum_matches':[name for name, val in values.items() if val == expected],
                         'selected_signature_offsets':signatures,
                         'fwupdate_offset':p if p >= 0 else None,
                         'selected_fwupdate_identifiers':tokens})
    result['payloads'] = payloads
    result['checksum_consensus'] = sorted(set.intersection(
        *(set(p['checksum_matches']) for p in payloads))) if payloads else []
    result['file_bytes'] = len(data)
    result['file_sha256'] = hashlib.sha256(data).hexdigest()
    result['limits'] = ['A selector is not established as a model ID, address or version.',
                        'Kind 0/1 semantics remain unknown; kind 2 is absent in the two measured files.',
                        'Signature matches do not establish instruction architecture.',
                        'Range coverage and unkeyed checksums are not vendor signature verification.']
    return result


def verify_lens(data: bytes) -> dict:
    """Require complete range coverage and all declared nonempty CRC-32 values."""
    result = audit(data)
    if not result['payloads'] or 'crc32_iso_hdlc' not in result['checksum_consensus']:
        raise ValueError('one or more declared payload CRC-32 values do not match')
    result['all_payload_crc32_verified'] = True
    return result


def main() -> None:
    from sl3p_loader_source_probe import acquire
    from sl3p_lens_plaintext1f import URL, SOURCE_BYTES, reconstruct
    data = acquire(URL, SOURCE_BYTES)
    plain, verification = reconstruct(data)
    del plain
    result = {'tool':'LENS_RECORDS1G', 'source_url':URL,
              'verification':verification, 'lens':verify_lens(data),
              'payload_published':False,'firmware_executed':False}
    other_url = 'https://leica-camera.com/sites/default/files/70200_11.plf'
    other = acquire(other_url, 1573978)
    if hashlib.sha256(other).hexdigest() != '4e26dce0ec3a4e64454b46e9df9d4dcdfb319be6a3cb479fb95521fe0ed70d32':
        raise ValueError('comparison file differs from previously measured identity')
    result['comparison_url'] = other_url
    try:
        result['comparison'] = verify_lens(other)
    except ValueError as exc:
        from sl3p_lens_layout_probe1g import measure
        result['comparison'] = {'strict_layout_accepted':False,
                                'reason':str(exc), 'directory_only':measure(other)}
    else:
        result['shared_payload_hash_pairs'] = [
            {'lens_records':a['record_indexes'],'other_records':b['record_indexes'],'size':a['size']}
            for a in result['lens']['payloads'] for b in result['comparison']['payloads']
            if a['size'] == b['size'] and a['sha256'] == b['sha256']]
    print('LENS_RECORDS1G_JSON_BEGIN')
    print(json.dumps(result,separators=(',',':')))
    print('LENS_RECORDS1G_JSON_END')


if __name__ == '__main__': main()
