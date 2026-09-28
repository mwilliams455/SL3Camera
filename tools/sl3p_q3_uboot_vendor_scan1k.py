#!/usr/bin/env python3
"""Inventory Q3 published U-Boot vendor/update code paths and bounded keyword hits."""
from __future__ import annotations
import io,json,re,tarfile,urllib.request,zipfile
from collections import Counter

URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
PATH_TERMS=("pvc","socionext","milbeaut","firmware","update","flash","mtd","spi","secure","crypto","aes")
CONTENT_TERMS=(b"firmware",b"update",b"decrypt",b"encrypt",b"aes",b"sha256",b"verify",b"signature",b"flash",b"mtd",b"spi",b"pvc04v",b"milbeaut",b"socionext",b"muf")
MAX_FILE=2*1024*1024

def interesting_path(name:str)->bool:
    low=name.lower()
    return any(x in low for x in PATH_TERMS)

def scan(raw:bytes)->dict:
    path_hits=[];content_hits=[]
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:*") as tf:
        for m in tf:
            if not m.isfile():continue
            if interesting_path(m.name):path_hits.append(m.name)
            # restrict content scanning to vendor/config/cmd/driver paths to reduce generic noise
            lowpath=m.name.lower()
            vendorish=any(x in lowpath for x in ("socionext","milbeaut","pvc","board/","include/configs/","cmd/","drivers/mtd/","drivers/spi/","drivers/crypto/"))
            if not vendorish or m.size>MAX_FILE:continue
            f=tf.extractfile(m)
            if not f:continue
            data=f.read(MAX_FILE+1)
            if len(data)>MAX_FILE:continue
            low=data.lower()
            hits=[]
            for t in CONTENT_TERMS:
                c=low.count(t)
                if c:hits.append({"term":t.decode(),"count":c})
            if hits:content_hits.append({"path":m.name,"hits":hits})
    return {"path_hits":path_hits,"content_hits":content_hits}

def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:blob=r.read()
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        names=[n for n in z.namelist() if n.endswith("u-boot.tar.gz")]
        if len(names)!=1:raise ValueError(f"expected one u-boot archive, found {len(names)}")
        result=scan(z.read(names[0]))
    out={"tool":"Q3_UBOOT_VENDOR_SCAN1K","source":URL,"archive":names[0],
         "path_hit_count":len(result["path_hits"]),"content_hit_file_count":len(result["content_hits"]),
         **result,
         "limits":["Path and ASCII keyword inventory only; matches are not function identifications.",
                   "Content scanning is limited to selected vendor/config/cmd/MTD/SPI/crypto paths and files <=2 MiB."],
         "camera_firmware_downloaded":False,"binary_published":False}
    print("Q3_UBOOT_VENDOR_SCAN1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("Q3_UBOOT_VENDOR_SCAN1K_JSON_END")
if __name__=="__main__":main()
