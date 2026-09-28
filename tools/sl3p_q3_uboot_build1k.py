#!/usr/bin/env python3
"""Extract selected Leica Q3 OSS U-Boot build metadata, source only."""
from __future__ import annotations
import hashlib,io,json,tarfile,urllib.request,zipfile
URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
TARGETS={
 "GNUmakefile",
 "configs/pvc04v_MC501_defconfig",
 "arch/arm/dts/pvc04v-MC501.dts",
 "arch/arm/dts/pvc04v-MC501.dtsi",
 "arch/arm/mach-milbeaut/Kconfig",
 "include/configs/sc2006a-evb.h",
}
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=180) as r:return r.read()
def main():
    zraw=fetch(URL)
    with zipfile.ZipFile(io.BytesIO(zraw)) as z:
        n=next(n for n in z.namelist() if n.endswith("u-boot.tar.gz"))
        raw=z.read(n)
    found={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():continue
            p=m.name.split("/",1)[1] if "/" in m.name else m.name
            if p in TARGETS:
                f=tf.extractfile(m); d=f.read() if f else b""
                found[p]={"bytes":len(d),"sha256":hashlib.sha256(d).hexdigest(),
                          "text":d.decode("utf-8","replace")}
    missing=sorted(TARGETS-set(found))
    print("Q3_UBOOT_BUILD1K_JSON_BEGIN")
    print(json.dumps({"tool":"Q3_UBOOT_BUILD1K","missing":missing,"files":found},separators=(",",":")))
    print("Q3_UBOOT_BUILD1K_JSON_END")
    if missing:raise SystemExit(1)
if __name__=="__main__":main()
