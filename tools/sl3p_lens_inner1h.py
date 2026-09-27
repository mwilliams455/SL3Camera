#!/usr/bin/env python3
"""Bounded inner-format triage of CRC-verified LENS payloads; no execution."""
from __future__ import annotations
from collections import Counter
import hashlib
import json
import math
import re
import struct
import zlib
from sl3p_lens_records1g import verify_lens

TARGET_SHA = '970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db'
MAX_OUTPUT = 16 * 1024 * 1024


def entropy(data: bytes) -> float:
    n = len(data)
    return -sum((v/n)*math.log2(v/n) for v in Counter(data).values()) if n else 0.0


def vector_candidates(data: bytes) -> list[dict]:
    """Cortex-M hypothesis only; require SRAM SP, odd reset, mapped vectors."""
    out = []
    for off in range(0, min(len(data)-64+1, 4096), 4):
        words = struct.unpack_from('<16I', data, off)
        sp, reset = words[:2]
        if not 0x20000000 <= sp <= 0x20100000 or sp % 4 or not reset & 1:
            continue
        # Test conventional flash windows, never infer a base from reset alone.
        for base in (0, 0x8000, 0x10000, 0x08000000, 0x10000000, 0x1a000000):
            meaningful = [words[i] for i in (1,2,3,4,5,6,11,12,14,15) if words[i]]
            mapped = sum(bool(w & 1) and base <= (w & ~1) < base+len(data)-off for w in meaningful)
            if len(meaningful) >= 5 and mapped == len(meaningful):
                out.append({'vector_offset':off,'image_base_hypothesis':base,
                            'initial_sp':sp,'reset_address':reset,
                            'reset_file_offset':off+(reset & ~1)-base,
                            'mapped_exception_vectors':mapped,
                            'reserved_zero_count':sum(words[i] == 0 for i in (7,8,9,10,13))})
    return out


def zlib_candidates(data: bytes) -> list[dict]:
    """Only plausible zlib headers in first 1024 bytes, capped decoded output."""
    out = []
    for off in range(min(1024, max(0,len(data)-1))):
        a,b = data[off:off+2]
        if a & 15 != 8 or a >> 4 > 7 or ((a << 8)|b) % 31:
            continue
        dec = zlib.decompressobj()
        try:
            decoded = dec.decompress(data[off:], MAX_OUTPUT+1)
        except zlib.error:
            continue
        if dec.eof and len(decoded) <= MAX_OUTPUT:
            out.append({'offset':off,'consumed':len(data)-off-len(dec.unused_data),
                        'trailing_bytes':len(dec.unused_data),'decoded_bytes':len(decoded),
                        'decoded_sha256':hashlib.sha256(decoded).hexdigest()})
    return out


def srecord_screen(data: bytes) -> dict:
    valid = 0
    for line in re.findall(rb'(?:^|[\r\n])(S[0-9][0-9A-Fa-f]{4,514})(?=[\r\n]|$)', data):
        try:
            record = bytes.fromhex(line[2:].decode('ascii'))
        except ValueError:
            continue
        if record and record[0] == len(record)-1 and sum(record) & 255 == 255:
            valid += 1
    return {'checksum_valid_text_records':valid,'complete_srecord_file_established':False}


def inspect_payload(data: bytes, target: bool = False) -> dict:
    chunks = [entropy(data[i:i+4096]) for i in range(0,len(data),4096)]
    words = struct.unpack_from('<4I', data) if len(data) >= 16 else ()
    result = {'size':len(data),'sha256':hashlib.sha256(data).hexdigest(),
              'entropy':entropy(data),'entropy_4k_min':min(chunks,default=0),
              'entropy_4k_max':max(chunks,default=0),
              'ascii_fraction':sum(b in (9,10,13) or 32<=b<127 for b in data)/max(1,len(data)),
              'zero_bytes':data.count(0),'ff_bytes':data.count(255),
              'vectors':vector_candidates(data), 'zlib':zlib_candidates(data),
              'srecord':srecord_screen(data)}
    markers = {'ELF':b'\x7fELF','GZIP':b'\x1f\x8b\x08','XZ':b'\xfd7zXZ\x00',
               'BZ2':b'BZh','LZ4':b'\x04\x22\x4d\x18','ZSTD':b'\x28\xb5\x2f\xfd',
               'UPD':b'UPD\x00','FWUPDATE':b'fwupdate','CORTEX':b'cortex',
               'RENESAS':b'renesas','FUJITSU':b'fujitsu','TOSHIBA':b'toshiba',
               'STM32':b'stm32','FREERTOS':b'freertos','IAR':b'iar systems',
               'KEIL':b'keil','SEGGER':b'segger','LZSS':b'lzss'}
    low=data.lower()
    result['fixed_markers'] = {k:low.find(v.lower()) for k,v in markers.items() if v.lower() in low}
    if target:
        # Four scalar header candidates only, not a payload/code dump.
        result['opening_u32le_candidates'] = list(words)
        result['first_64k_entropy'] = chunks[:16]
        pos=low.find(b'fwupdate')
        result['fwupdate_null_terminated'] = pos >= 0 and data[pos+8:pos+9] == b'\x00'
        result['fwupdate_preceded_by_nul'] = pos > 0 and data[pos-1] == 0
        result['fwupdate_local_entropy'] = entropy(data[max(0,pos-128):pos+128])
    return result


def main() -> None:
    from sl3p_lens_plaintext1f import URL, SOURCE_BYTES, reconstruct
    from sl3p_loader_source_probe import acquire
    data = acquire(URL, SOURCE_BYTES)
    plain, proof = reconstruct(data)
    del plain
    package = verify_lens(data)
    rows=[]
    for entry in package['payloads']:
        offset,size=entry['offset'],entry['size']
        row=inspect_payload(data[offset:offset+size],entry['sha256']==TARGET_SHA)
        row.update({'record_indexes':entry['record_indexes'],'container_offset':offset})
        rows.append(row)
    print('LENS_INNER1H_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_INNER1H','source_proof':proof,'payloads':rows,
                      'firmware_executed':False,'payload_dumped':False,
                      'limits':['ISA candidates are hypotheses, not confirmed code.',
                                'Compression and signature search is bounded, not exhaustive.']},separators=(',',':')))
    print('LENS_INNER1H_JSON_END')


if __name__ == '__main__':
    main()
