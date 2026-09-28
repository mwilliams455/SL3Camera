#!/usr/bin/env python3
"""Measure Q3 U-Boot build candidates against the protected loader1 fingerprint.

This does not decrypt firmware. It only hashes defensible candidate byte ranges
and deterministic compressed forms from a locally built U-Boot image.
"""
from __future__ import annotations
import argparse,bz2,gzip,hashlib,json,lzma,zlib
from pathlib import Path

TARGET_SIZE=131072
TARGET_SHA256="724e574baa46cb9aa6f20af241cd50e678ab115e24e6c1b3eed6fbd82af5ed97"

def sha(data:bytes)->str:
    return hashlib.sha256(data).hexdigest()

def aligned_windows(data:bytes,size:int=TARGET_SIZE)->list[dict]:
    if size<=0: raise ValueError("size must be positive")
    out=[]
    for off in range(0,max(0,len(data)-size)+1,size):
        block=data[off:off+size]
        if len(block)==size:
            out.append({"offset":off,"sha256":sha(block),"matches_target":sha(block)==TARGET_SHA256})
    return out

def candidate_forms(data:bytes)->dict:
    forms={}
    if len(data)>=TARGET_SIZE:
        for name,block in (("prefix_128k",data[:TARGET_SIZE]),("suffix_128k",data[-TARGET_SIZE:])):
            forms[name]={"bytes":len(block),"sha256":sha(block),"matches_target":sha(block)==TARGET_SHA256}
    for name,blob in (
        ("gzip_mtime0",gzip.compress(data,compresslevel=9,mtime=0)),
        ("zlib9",zlib.compress(data,9)),
        ("bz2_9",bz2.compress(data,9)),
        ("xz_9",lzma.compress(data,format=lzma.FORMAT_XZ,preset=9)),
        ("lzma_alone_9",lzma.compress(data,format=lzma.FORMAT_ALONE,preset=9)),
    ):
        item={"bytes":len(blob),"sha256":sha(blob),"matches_target":False}
        if len(blob)<=TARGET_SIZE:
            for fill in (0,255):
                padded=blob+bytes([fill])*(TARGET_SIZE-len(blob))
                h=sha(padded)
                item[f"pad_{fill:02x}_sha256"]=h
                item[f"pad_{fill:02x}_matches_target"]=h==TARGET_SHA256
                item["matches_target"] |= h==TARGET_SHA256
        forms[name]=item
    return forms

def inspect(paths:list[Path])->dict:
    outputs={}
    any_match=False
    for p in paths:
        data=p.read_bytes()
        forms=candidate_forms(data)
        windows=aligned_windows(data)
        matched=[x for x in windows if x["matches_target"]]
        any_match |= bool(matched) or any(x.get("matches_target",False) for x in forms.values())
        outputs[p.name]={
            "bytes":len(data),"sha256":sha(data),
            "forms":forms,"aligned_128k_windows":windows,
            "matched_aligned_windows":matched,
        }
    return {
        "tool":"Q3_LOADER_CANDIDATE1K",
        "loader1_expected_bytes":TARGET_SIZE,
        "loader1_expected_sha256":TARGET_SHA256,
        "outputs":outputs,
        "any_exact_candidate_match":any_match,
        "interpretation_limit":"A mismatch does not prove the loader is unrelated; build toolchain, build metadata, compression or update packaging can differ.",
    }

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths",nargs="+",type=Path)
    a=ap.parse_args()
    result=inspect(a.paths)
    print("Q3_LOADER_CANDIDATE1K_JSON_BEGIN")
    print(json.dumps(result,separators=(",",":")))
    print("Q3_LOADER_CANDIDATE1K_JSON_END")

if __name__=="__main__": main()
