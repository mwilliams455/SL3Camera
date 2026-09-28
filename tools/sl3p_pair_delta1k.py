#!/usr/bin/env python3
"""Compare official SL3-P 4.2.1/4.2.2 protected representations.

Requires exact 4.2.1 identity matching the user's baseline. Reports derived
statistics only; no firmware or ciphertext bytes are emitted.
"""
from __future__ import annotations
import hashlib,json,math,tempfile,urllib.request
from pathlib import Path
import numpy as np
from sl3p_inspect import Firmware,inspect

URL421="https://leica-camera.com/sites/default/files/SL3P_421.lfu"
URL422="https://leica-camera.com/sites/default/files/SL3P_422.lfu"
SHA421="b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8"

def fetch(url:str)->bytes:
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()

def entropy_bytes(data:bytes)->float:
    if not data:return 0.0
    c=np.bincount(np.frombuffer(data,dtype=np.uint8),minlength=256)
    p=c[c>0]/len(data)
    return float(-(p*np.log2(p)).sum())

def sample_pair(fa:Firmware,fb:Firmware,a:dict,b:dict,limit:int=1048576)->dict:
    n=min(int(a["size"]),limit)
    xa=fa.read(int(a["file_offset"]),n); xb=fb.read(int(b["file_offset"]),n)
    aa=np.frombuffer(xa,dtype=np.uint8); bb=np.frombuffer(xb,dtype=np.uint8)
    x=np.bitwise_xor(aa,bb)
    eq=int(np.count_nonzero(aa==bb))
    bits=int(np.unpackbits(x).sum())
    raw=x.tobytes()
    periodic={}
    for p in (1,2,4,8,16,32,64,256,4096):
        periodic[str(p)]=None if len(x)<=p else float(np.count_nonzero(x[:-p]==x[p:])/(len(x)-p))
    blocks=n//16
    beq=0
    if blocks:
        a16=aa[:blocks*16].reshape((-1,16));b16=bb[:blocks*16].reshape((-1,16))
        beq=int(np.count_nonzero(np.all(a16==b16,axis=1)))
    return {
      "sample_bytes":n,"equal_byte_fraction":eq/n if n else None,
      "bit_difference_fraction":bits/(8*n) if n else None,
      "xor_entropy_bits_per_byte":entropy_bytes(raw),
      "equal_aligned_16byte_blocks":beq,"aligned_16byte_blocks":blocks,
      "xor_period_equal_fraction":periodic,
    }

def main():
    d421=fetch(URL421);d422=fetch(URL422)
    if hashlib.sha256(d421).hexdigest()!=SHA421:
        raise SystemExit("official 4.2.1 identity differs from user baseline")
    with tempfile.TemporaryDirectory(prefix="sl3ppair-") as td:
        p421=Path(td)/"421.lfu";p422=Path(td)/"422.lfu";p421.write_bytes(d421);p422.write_bytes(d422)
        i421=inspect(p421);i422=inspect(p422)
        f421=Firmware(p421);f422=Firmware(p422)
        layout_equal=True; unchanged=[]; changed=[]
        for a,b in zip(i421["sections"],i422["sections"]):
            if (a["index"],a["name"],a["size"],a["target_offset_unconfirmed"],a["flags"]) != (b["index"],b["name"],b["size"],b["target_offset_unconfirmed"],b["flags"]):
                layout_equal=False
            same_plain=(a["stored_sha256"]==b["stored_sha256"] and a["size"]==b["size"] and a["flags"]==b["flags"])
            row={"index":a["index"],"name":a["name"],"size":a["size"],"target":a["target_offset_unconfirmed"]}
            if same_plain and a["flags"]==3 and a["size"]:
                row["stored_payload_same"]=a["payload_sha256_after_outer_transform"]==b["payload_sha256_after_outer_transform"]
                row["metadata16_same"]=a["unknown_16_bytes"]==b["unknown_16_bytes"]
                row["sample"]=sample_pair(f421,f422,a,b)
                unchanged.append(row)
            elif not same_plain:
                row["expected421"]=a["stored_sha256"];row["expected422"]=b["stored_sha256"];changed.append(row)
    result={
      "tool":"SL3P_PAIR_DELTA1K",
      "official_421_sha256":hashlib.sha256(d421).hexdigest(),"official_422_sha256":hashlib.sha256(d422).hexdigest(),
      "official_421_matches_user_baseline":True,
      "same_section_layout":layout_equal,
      "unchanged_protected_count":len(unchanged),"changed_expected_count":len(changed),
      "changed_expected_sections":changed,
      "unchanged_protected_stats":unchanged,
      "limits":["Statistics are sampled to at most 1 MiB per section.","Random-looking XOR does not identify a cipher or key.","No firmware bytes are published or executed."],
      "temporary_binaries_deleted":True,"binary_published":False
    }
    print("SL3P_PAIR_DELTA1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("SL3P_PAIR_DELTA1K_JSON_END")
if __name__=="__main__":main()
