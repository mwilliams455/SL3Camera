#!/usr/bin/env python3
"""Inspect Leica Q3 OSS U-Boot package for retained build artifacts/configuration."""
from __future__ import annotations
import hashlib,io,json,re,tarfile,urllib.request,zipfile
URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=180) as r:return r.read()
def main():
    outer=fetch(URL)
    with zipfile.ZipFile(io.BytesIO(outer)) as z:
        n=next(n for n in z.namelist() if n.lower().endswith("u-boot.tar.gz"))
        raw=z.read(n)
    artifacts=[]; special={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():continue
            p=m.name; lp=p.lower()
            base=p.rsplit("/",1)[-1].lower()
            if (base in (".config","u-boot","u-boot.bin","u-boot.img","u-boot.elf","system.map") or
                base.startswith("u-boot") and any(base.endswith(x) for x in (".bin",".img",".elf",".map",".dtb")) or
                "/spl/" in lp and any(base.endswith(x) for x in (".bin",".elf",".map")) or
                base.endswith((".dtb",".o",".a"))):
                if len(artifacts)<400:
                    f=tf.extractfile(m); d=f.read() if f and m.size<=8_000_000 else b""
                    artifacts.append({"path":p,"bytes":m.size,
                                      "sha256":hashlib.sha256(d).hexdigest() if d else None})
            if base in ("gnumakefile","pvc04v_mc501_defconfig") or p.endswith("pvc04v-MC501.dts") or p.endswith("pvc04v-MC501.dtsi") or base=="kconfig":
                f=tf.extractfile(m)
                if f and m.size<100_000:special[p]=f.read().decode("utf-8","replace")
    print("Q3_UBOOT_ARTIFACTS1K_JSON_BEGIN")
    print(json.dumps({"tool":"Q3_UBOOT_ARTIFACTS1K","uboot_bytes":len(raw),
      "uboot_sha256":hashlib.sha256(raw).hexdigest(),"artifact_candidates":artifacts,
      "special_files":special},separators=(",",":")))
    print("Q3_UBOOT_ARTIFACTS1K_JSON_END")
if __name__=="__main__":main()
