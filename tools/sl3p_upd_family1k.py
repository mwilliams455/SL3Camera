#!/usr/bin/env python3
"""Strict common UPD-family inspector for Leica/Panasonic camera packages.

This generalizes the validated SL3-P wrapper only by not requiring the six-byte
'leica\0' marker at 0x200. It still requires the nested UPD header, duplicate
model identifier, CRC, 92-byte directory, contiguous payloads and flags 2/3.
It is a parser, not a decryptor.
"""
from __future__ import annotations
import collections, hashlib, math, re, struct, zlib
from pathlib import Path
from sl3p_inspect import Firmware, FormatError, BASE, INNER, DIRECTORY, STRIDE, BLOCK, u32, raw_sha256

def inspect_family(path: Path) -> dict:
    fw=Firmware(Path(path))
    header=fw.read(0,DIRECTORY)
    if header[INNER:INNER+4] != b'UPD\0':
        raise FormatError('Unrecognized nested UPD header')
    body_offset,body_size,expected_crc=struct.unpack_from('<III',header,0x38)
    if body_offset!=BASE or body_size!=fw.size-BASE:
        raise FormatError('Outer size/base mismatch')
    model=header[0x0C:0x1C].split(b'\0')[0].decode('ascii')
    if not model or header[0x0C:0x1C] != header[INNER+0x0C:INNER+0x1C]:
        raise FormatError('Nested model identifier mismatch')
    data_start=BASE+u32(header,0x2E0)
    data_size,count=struct.unpack_from('<II',header,0x2E4)
    if not 1<=count<=4096: raise FormatError('Implausible directory count')
    if DIRECTORY+count*STRIDE>data_start or data_start+data_size!=fw.size:
        raise FormatError('Directory/data bounds mismatch')
    crc=0
    for block in fw.chunks(BASE,body_size): crc=zlib.crc32(block,crc)
    crc&=0xffffffff
    if crc!=expected_crc: raise FormatError(f'CRC mismatch: {crc:08x} != {expected_crc:08x}')
    directory=fw.read(DIRECTORY,count*STRIDE)
    rows=[];cursor=data_start
    for index in range(count):
        e=directory[index*STRIDE:(index+1)*STRIDE]
        name=e[:12].split(b'\0')[0].decode('ascii')
        if not re.fullmatch(r'[A-Za-z0-9_]+',name):
            raise FormatError(f'Unsafe/unrecognized section name at {index}')
        relative,size,target,flags=struct.unpack_from('<4I',e,12)
        off=BASE+relative
        if flags not in (2,3) or off!=cursor or off+size>fw.size:
            raise FormatError(f'Unknown flags or noncontiguous region at {index}')
        cursor=off+size
        expected=e[28:60].hex()
        h=hashlib.sha256();sample=b'';fill=None;constant=bool(size)
        for block in fw.chunks(off,size):
            h.update(block)
            if len(sample)<65536: sample += block[:65536-len(sample)]
            if fill is None: fill=block[0]
            if constant and block.count(fill)!=len(block): constant=False
        digest=h.hexdigest();match=digest==expected
        if flags==2 and not match: raise FormatError(f'Flag-2 section hash mismatch at {index}')
        freq=collections.Counter(sample)
        entropy=(-sum((n/len(sample))*math.log2(n/len(sample)) for n in freq.values())) if sample else 0.0
        rows.append({"index":index,"name":name,"file_offset":off,"size":size,
          "target_offset_unconfirmed":target,"flags":flags,"expected_sha256":expected,
          "payload_sha256_after_outer_transform":digest,"sha256_matches":match,
          "unknown_16_bytes":e[60:76].hex(),"reserved_16_bytes":e[76:92].hex(),
          "entropy_first_64KiB":entropy,"constant_fill_byte":fill if constant else None,
          "classification":("empty" if not size else ("hash_verified_bytes" if match else "opaque_not_decrypted"))})
    if cursor!=fw.size: raise FormatError('Section coverage does not reach EOF')
    return {"tool":"UPD_FAMILY1K","input_size":fw.size,"input_sha256":raw_sha256(Path(path)),
      "outer_transform":"XOR_FF" if fw.inverted else "direct",
      "brand_marker_0x200_hex":header[BASE:BASE+16].hex(),
      "internal_identifier":model,
      "crc32_region":{"stored":f"{expected_crc:08x}","computed":f"{crc:08x}","matches":True},
      "directory":{"offset":DIRECTORY,"entry_size":STRIDE,"entry_count":count,"data_start":data_start,"data_size":data_size},
      "sections":rows,
      "counts":{"by_flags":dict(collections.Counter(r["flags"] for r in rows)),
        "hash_matches":sum(r["sha256_matches"] for r in rows)}}

if __name__=="__main__":
    import argparse,json
    p=argparse.ArgumentParser();p.add_argument("firmware",type=Path);a=p.parse_args()
    print(json.dumps(inspect_family(a.firmware),indent=2))
