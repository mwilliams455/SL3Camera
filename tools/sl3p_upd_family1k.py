#!/usr/bin/env python3
"""Strict common nested-UPD inspector for Leica/Panasonic camera packages.

Two observed nested layouts are supported:
- modern: explicit data-relative-offset/data-size/count at 0x2e0/0x2e4/0x2e8;
- legacy nested (GH3 generation): zero data offset/size, non-zero count, with the
  first 92-byte directory record defining data start and contiguous records
  required to cover exactly through EOF.

This deliberately does NOT accept older single-UPD PTool-era images. It is a
container parser, not a payload decryptor.
"""
from __future__ import annotations
import collections, hashlib, math, re, struct, zlib
from pathlib import Path
from sl3p_inspect import Firmware, FormatError, BASE, INNER, DIRECTORY, STRIDE, u32, raw_sha256

def _parse_directory_bytes(fw: Firmware, header: bytes):
    declared_relative=u32(header,0x2E0)
    declared_size=u32(header,0x2E4)
    count=u32(header,0x2E8)
    if not 1 <= count <= 4096:
        raise FormatError('Implausible directory count')
    directory_end=DIRECTORY+count*STRIDE
    if directory_end > fw.size:
        raise FormatError('Directory exceeds input')
    directory=fw.read(DIRECTORY,count*STRIDE)

    # Read record metadata first so a legacy nested file can derive its data start.
    metas=[]
    for index in range(count):
        e=directory[index*STRIDE:(index+1)*STRIDE]
        try:
            name=e[:12].split(b'\0')[0].decode('ascii')
        except UnicodeDecodeError as exc:
            raise FormatError(f'Non-ASCII section name at {index}') from exc
        if not re.fullmatch(r'[A-Za-z0-9_]+',name):
            raise FormatError(f'Unsafe/unrecognized section name at {index}')
        relative,size,target,flags=struct.unpack_from('<4I',e,12)
        if flags not in (2,3):
            raise FormatError(f'Unknown flags at {index}: {flags}')
        metas.append((index,e,name,relative,size,target,flags))

    if declared_relative or declared_size:
        layout='modern_explicit'
        data_start=BASE+declared_relative
        data_size=declared_size
        if directory_end > data_start or data_start+data_size != fw.size:
            raise FormatError('Directory/data bounds mismatch')
    else:
        layout='legacy_inferred'
        if not metas:
            raise FormatError('Legacy nested layout has no records')
        first_relative=metas[0][3]
        data_start=BASE+first_relative
        data_size=fw.size-data_start
        if first_relative == 0:
            raise FormatError('Legacy nested first record cannot start at wrapper base')
        if directory_end > data_start or data_start > fw.size:
            raise FormatError('Legacy directory/data bounds mismatch')

    return directory,metas,layout,data_start,data_size,count,declared_relative,declared_size

def inspect_family(path: Path) -> dict:
    fw=Firmware(Path(path))
    header=fw.read(0,DIRECTORY)
    if header[INNER:INNER+4] != b'UPD\0':
        raise FormatError('Unrecognized nested UPD header')
    body_offset,body_size,expected_crc=struct.unpack_from('<III',header,0x38)
    if body_offset!=BASE or body_size!=fw.size-BASE:
        raise FormatError('Outer size/base mismatch')
    try:
        model=header[0x0C:0x1C].split(b'\0')[0].decode('ascii')
    except UnicodeDecodeError as exc:
        raise FormatError('Non-ASCII model identifier') from exc
    if not model or header[0x0C:0x1C] != header[INNER+0x0C:INNER+0x1C]:
        raise FormatError('Nested model identifier mismatch')

    directory,metas,layout,data_start,data_size,count,declared_relative,declared_size = _parse_directory_bytes(fw,header)

    crc=0
    for block in fw.chunks(BASE,body_size):
        crc=zlib.crc32(block,crc)
    crc&=0xffffffff
    if crc!=expected_crc:
        raise FormatError(f'CRC mismatch: {crc:08x} != {expected_crc:08x}')

    rows=[];cursor=data_start
    for index,e,name,relative,size,target,flags in metas:
        off=BASE+relative
        if off!=cursor or off+size>fw.size:
            raise FormatError(f'Noncontiguous/out-of-bounds region at {index}')
        cursor=off+size
        expected=e[28:60].hex()
        h=hashlib.sha256();sample=b'';fill=None;constant=bool(size)
        for block in fw.chunks(off,size):
            h.update(block)
            if len(sample)<65536:
                sample += block[:65536-len(sample)]
            if fill is None:
                fill=block[0]
            if constant and block.count(fill)!=len(block):
                constant=False
        digest=h.hexdigest();match=digest==expected
        if flags==2 and not match:
            raise FormatError(f'Flag-2 section hash mismatch at {index}')
        freq=collections.Counter(sample)
        entropy=(-sum((n/len(sample))*math.log2(n/len(sample)) for n in freq.values())) if sample else 0.0
        rows.append({"index":index,"name":name,"file_offset":off,"relative_offset":relative,"size":size,
          "target_offset_unconfirmed":target,"flags":flags,"expected_sha256":expected,
          "payload_sha256_after_outer_transform":digest,"sha256_matches":match,
          "unknown_16_bytes":e[60:76].hex(),"reserved_16_bytes":e[76:92].hex(),
          "entropy_first_64KiB":entropy,"constant_fill_byte":fill if constant else None,
          "classification":("empty" if not size else ("hash_verified_bytes" if match else "opaque_not_decrypted"))})
    if cursor!=fw.size:
        raise FormatError('Section coverage does not reach EOF')
    if cursor-data_start != data_size:
        raise FormatError('Derived section coverage disagrees with data size')

    return {"tool":"UPD_FAMILY1K","input_size":fw.size,"input_sha256":raw_sha256(Path(path)),
      "outer_transform":"XOR_FF" if fw.inverted else "direct",
      "brand_marker_0x200_hex":header[BASE:BASE+16].hex(),
      "internal_identifier":model,
      "crc32_region":{"stored":f"{expected_crc:08x}","computed":f"{crc:08x}","matches":True},
      "directory":{"offset":DIRECTORY,"entry_size":STRIDE,"entry_count":count,
        "layout":layout,"declared_data_relative_offset":declared_relative,
        "declared_data_size":declared_size,"data_start":data_start,"data_size":data_size},
      "sections":rows,
      "counts":{"by_flags":dict(collections.Counter(r["flags"] for r in rows)),
        "hash_matches":sum(r["sha256_matches"] for r in rows)},
      "limitations":[
        "Nested-UPD parsing does not decrypt protected sections.",
        "Legacy data-start inference is accepted only with exact contiguous coverage to EOF.",
        "Expected hashes and CRCs are consistency checks, not vendor-signature authentication.",
      ]}

if __name__=="__main__":
    import argparse,json
    p=argparse.ArgumentParser();p.add_argument("firmware",type=Path);a=p.parse_args()
    print(json.dumps(inspect_family(a.firmware),indent=2))
