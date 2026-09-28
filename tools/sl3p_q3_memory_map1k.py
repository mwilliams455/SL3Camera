#!/usr/bin/env python3
"""Overlay Q3 UPD target ranges with addresses published in Q3 OSS boot/Linux config."""
from __future__ import annotations
import io,json,re,tempfile,urllib.request,zipfile,tarfile
from pathlib import Path
from sl3p_inspect import inspect
from sl3p_q3_boot_map1k import parse_boot_addresses,map_sections

FW="https://leica-camera.com/sites/default/files/Q3___411.lfu"
OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"

def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()

def parse_slram(bootargs:str)->list[dict]:
    m=re.search(r"slram=([^\s]+)",bootargs)
    if not m:return []
    out=[]
    for item in m.group(1).split(","):
        # entries alternate name,start,+size
        pass
    parts=m.group(1).split(",")
    if len(parts)%3:
        raise ValueError("unexpected slram tuple count")
    for i in range(0,len(parts),3):
        name,start,size=parts[i:i+3]
        if not size.startswith("+"):raise ValueError("slram size lacks +")
        s=int(start,0); n=int(size[1:],0)
        out.append({"name":name,"start":s,"size":n,"end":s+n})
    return out

def overlaps(a0,a1,b0,b1):
    lo=max(a0,b0);hi=min(a1,b1)
    return max(0,hi-lo)

def main():
    fw=fetch(FW)
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/"q3.lfu";p.write_bytes(fw); inv=inspect(p)
    oss=fetch(OSS)
    with zipfile.ZipFile(io.BytesIO(oss)) as z:
        uentry=next(n for n in z.namelist() if n.endswith("u-boot.tar.gz"))
        lentry=next(n for n in z.namelist() if n.endswith("linux-4.19.124.tar.gz"))
        uraw=z.read(uentry);lraw=z.read(lentry)
    cfg=None;dts=None
    with tarfile.open(fileobj=io.BytesIO(uraw),mode="r:gz") as tf:
        for m in tf:
            if m.isfile() and m.name.endswith("configs/pvc04v_MC501_defconfig"):
                cfg=tf.extractfile(m).read().decode("utf-8","replace")
                break
    with tarfile.open(fileobj=io.BytesIO(lraw),mode="r:gz") as tf:
        for m in tf:
            if m.isfile() and m.name.endswith("arch/arm64/boot/dts/socionext/pvc04v-DC1231.dts"):
                dts=tf.extractfile(m).read().decode("utf-8","replace")
                break
    if cfg is None or dts is None:raise RuntimeError("required OSS source missing")
    addresses=parse_boot_addresses(cfg)
    bm=re.search(r'bootargs\s*=\s*"([^"]+)"',dts)
    if not bm:raise RuntimeError("bootargs missing")
    bootargs=bm.group(1); slram=parse_slram(bootargs)
    rows=map_sections(inv["sections"],addresses["uboot"],len(inv["sections"]))
    sections=[]
    for r in rows:
        if not r["size"]:continue
        start=r["mapped_from_uboot_base"];end=start+r["size"]
        ovs=[{"name":x["name"],"bytes":overlaps(start,end,x["start"],x["end"])}
             for x in slram if overlaps(start,end,x["start"],x["end"])]
        sections.append({**r,"end":end,"slram_overlaps":ovs})
    interesting=[x for x in sections if x["name"] in ("loader1","program","compress_pr") or x["slram_overlaps"]]
    print("Q3_MEMORY_MAP1K_JSON_BEGIN")
    print(json.dumps({
      "tool":"Q3_MEMORY_MAP1K","identifier":inv["internal_identifier"],
      "addresses":addresses,"bootargs":bootargs,"slram":slram,
      "interesting_sections":interesting,
      "relations":{
        "dtb_to_slram0_gap":slram[0]["start"]-addresses["dtb"] if slram else None,
        "slram_contiguous":all(slram[i]["end"]==slram[i+1]["start"] for i in range(len(slram)-1)),
        "slram_end_equals_kernel":slram[-1]["end"]==addresses["kernel"] if slram else False,
        "program_plus_compress_start":next(x for x in sections if x["name"]=="program")["mapped_from_uboot_base"],
        "program_plus_compress_end":next(x for x in sections if x["name"]=="compress_pr")["end"],
      },
      "temporary_binaries_deleted":True,"binary_published":False
    },separators=(",",":")))
    print("Q3_MEMORY_MAP1K_JSON_END")
if __name__=="__main__":main()
