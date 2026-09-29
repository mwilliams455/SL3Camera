#!/usr/bin/env python3
"""Extract Q3 published Linux boot/compression configuration relevant to UPD target mapping."""
from __future__ import annotations
import io,json,re,tarfile,urllib.request,zipfile
URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
KEEP=("CONFIG_KERNEL_","CONFIG_INITRAMFS","CONFIG_BLK_DEV_INITRD","CONFIG_RD_","CONFIG_DECOMPRESS_",
      "CONFIG_DEFAULT_HOSTNAME","CONFIG_CMDLINE","CONFIG_MTD","CONFIG_SQUASHFS","CONFIG_CRAMFS")
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()
def main():
    outer=fetch(URL)
    with zipfile.ZipFile(io.BytesIO(outer)) as z:
        n=next(n for n in z.namelist() if n.endswith("linux-4.19.124.tar.gz"))
        raw=z.read(n)
    wanted={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():continue
            q=m.name.split("/",1)[1] if "/" in m.name else m.name
            if q in ("arch/arm64/configs/pvc04v_DC1231_defconfig",
                     "arch/arm64/boot/dts/socionext/pvc04v-DC1231.dts",
                     "GNUmakefile"):
                f=tf.extractfile(m);wanted[q]=(f.read() if f else b"").decode("utf-8","replace")
    cfg=wanted["arch/arm64/configs/pvc04v_DC1231_defconfig"]
    selected=[]
    for line in cfg.splitlines():
        s=line.strip()
        if any(k in s for k in KEEP): selected.append(s)
    dts=wanted["arch/arm64/boot/dts/socionext/pvc04v-DC1231.dts"]
    bm=re.search(r'bootargs\s*=\s*"([^"]+)"',dts)
    mem=[x.strip() for x in dts.splitlines() if any(k in x for k in ("memory@","reg = <","shared_commem","slram"))]
    print("Q3_LINUX_LAYOUT1K_JSON_BEGIN")
    print(json.dumps({"tool":"Q3_LINUX_LAYOUT1K","selected_config":selected,
      "bootargs":bm.group(1) if bm else None,"memory_related_lines":mem[:120],
      "has_gnumakefile":"GNUmakefile" in wanted,
      "gnumakefile":wanted.get("GNUmakefile","")[:3000]},separators=(",",":")))
    print("Q3_LINUX_LAYOUT1K_JSON_END")
if __name__=="__main__":main()
