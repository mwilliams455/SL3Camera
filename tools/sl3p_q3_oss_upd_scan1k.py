#!/usr/bin/env python3
"""Scan Leica Q3 published U-Boot/Linux source for exact UPD-family tokens.

Only official open-source source archives are inspected. No camera firmware
payload is downloaded or published by this tool.
"""
from __future__ import annotations
import io,json,tarfile,urllib.request,zipfile
from collections import Counter,defaultdict

URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
TOKENS=[
 b"lut_data",b"lut2_data",b"compress_pr",b"postboot1_r",b"postboot3_r",
 b"eep_ow_a",b"eep_adj",b"eep_exp_a",b"muf_header",b"osdover",b"osddata",
 b"raw_kizu_c",b"raw_kizu_d",b"hm_d_nw_1st",b"hm_d_reid",b"lpc_code",
 b"LENS-UPDATE-FILE-SOF",b"MC7251",b"MC7231",b"DC1231",
]
MAX_FILE=8*1024*1024

def scan_tar(raw:bytes,label:str)->dict:
    hits=[];files=0;bytes_scanned=0
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:*") as tf:
        for m in tf:
            if not m.isfile() or m.size>MAX_FILE: continue
            f=tf.extractfile(m)
            if not f: continue
            data=f.read(MAX_FILE+1)
            if len(data)>MAX_FILE: continue
            files+=1;bytes_scanned+=len(data)
            low=data.lower()
            for tok in TOKENS:
                count=low.count(tok.lower())
                if count:
                    hits.append({"path":m.name,"token":tok.decode("ascii"),"count":count})
    return {"archive":label,"files_scanned":files,"bytes_scanned":bytes_scanned,
            "hits":hits,"hit_counts":dict(Counter(x["token"] for x in hits))}

def select_members(names:list[str])->list[str]:
    uboot=[n for n in names if n.endswith("u-boot.tar.gz")]
    linux=[n for n in names if n.rsplit("/",1)[-1].startswith("linux-") and n.endswith(".tar.gz")]
    if len(uboot)!=1: raise ValueError(f"expected one u-boot archive, found {len(uboot)}")
    if len(linux)!=1: raise ValueError(f"expected one versioned linux archive, found {len(linux)}")
    return [uboot[0],linux[0]]

def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:blob=r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        selected=select_members(z.namelist())
        results=[scan_tar(z.read(n),n) for n in selected]
    result={"tool":"Q3_OSS_UPD_TOKEN_SCAN1K","source":URL,
            "tokens":[x.decode("ascii") for x in TOKENS],
            "results":results,
            "total_hits":sum(len(x["hits"]) for x in results),
            "limits":["Exact ASCII token scan only; absence does not prove an implementation is absent.",
                      "Files larger than 8 MiB are skipped.","Only Q3 published U-Boot and Linux archives are scanned."],
            "proprietary_firmware_downloaded":False,"binary_published":False}
    print("Q3_OSS_UPD_TOKEN_SCAN1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("Q3_OSS_UPD_TOKEN_SCAN1K_JSON_END")
if __name__=="__main__":main()
