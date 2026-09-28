#!/usr/bin/env python3
"""Correlate Q3 UPD target offsets with Q3 published boot addresses.

Official Q3 firmware and OSS source only; no binaries are published.
The parsing/address helpers are pure so synthetic CI can test the mapping logic.
"""
from __future__ import annotations
import io,json,re,tempfile,urllib.request,zipfile,tarfile
from pathlib import Path
from sl3p_inspect import inspect

FW="https://leica-camera.com/sites/default/files/Q3___411.lfu"
OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"

_PATTERNS={
    "uboot":r"CONFIG_SYS_TEXT_BASE=(0x[0-9A-Fa-f]+)",
    "zkernel":r"# ZKERNEL_ADDRESS:\s*(0x[0-9A-Fa-f]+)",
    "kernel":r"# KERNEL_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",
    "dtb":r"# DTB_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",
}

def parse_boot_addresses(text:str)->dict[str,int]:
    out={}
    for name,pattern in _PATTERNS.items():
        m=re.search(pattern,text)
        if not m:
            raise ValueError(f"missing {name} address")
        out[name]=int(m.group(1),16)
    return out

def map_sections(sections:list[dict],base:int,limit:int=15)->list[dict]:
    if base<0 or limit<0:
        raise ValueError("negative base/limit")
    rows=[]
    for s in sections[:limit]:
        off=int(s["target_offset_unconfirmed"])
        size=int(s["size"])
        if off<0 or size<0:
            raise ValueError("negative offset/size")
        rows.append({"index":int(s["index"]),"name":str(s["name"]),"offset":off,"size":size,
                     "mapped_from_uboot_base":base+off})
    return rows

def mapping_relationships(rows:list[dict],addresses:dict[str,int])->dict:
    named={r["name"]:r for r in rows}
    for needed in ("loader1","program"):
        if needed not in named:
            raise ValueError(f"missing {needed} section")
    uboot=addresses["uboot"];zkernel=addresses["zkernel"]
    kernel=addresses["kernel"];dtb=addresses["dtb"]
    return {
        "zkernel_minus_uboot":zkernel-uboot,
        "dtb_minus_uboot":dtb-uboot,
        "kernel_minus_uboot":kernel-uboot,
        "loader1_maps_to_uboot":named["loader1"]["mapped_from_uboot_base"]==uboot,
        "program_maps_to_zkernel":named["program"]["mapped_from_uboot_base"]==zkernel,
        "dtb_relative_to_program_start":dtb-zkernel,
        "dtb_inside_program":0 <= dtb-zkernel < named["program"]["size"],
        "program_end":named["program"]["mapped_from_uboot_base"]+named["program"]["size"],
        "kernel_is_linux_memory_base_candidate":kernel,
    }

def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()

def main():
    f=fetch(FW)
    with tempfile.TemporaryDirectory() as td:
        p=Path(td)/"q3.lfu";p.write_bytes(f);inv=inspect(p)
    z=fetch(OSS)
    with zipfile.ZipFile(io.BytesIO(z)) as zz:
        n=next(n for n in zz.namelist() if n.endswith("u-boot.tar.gz"))
        uraw=zz.read(n)
    wanted={}
    with tarfile.open(fileobj=io.BytesIO(uraw),mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():continue
            q=m.name.split("/",1)[1] if "/" in m.name else m.name
            if q=="configs/pvc04v_MC501_defconfig":
                fobj=tf.extractfile(m)
                if fobj:
                    wanted[q]=fobj.read().decode("utf-8","replace")
    cfg=wanted["configs/pvc04v_MC501_defconfig"]
    addresses=parse_boot_addresses(cfg)
    rows=map_sections(inv["sections"],addresses["uboot"])
    result={
      "tool":"Q3_BOOT_MAP1K",
      "firmware_identifier":inv["internal_identifier"],
      "crc_matches":inv["crc32_region"]["matches"],
      "published_addresses":addresses,
      "offset_relationships":mapping_relationships(rows,addresses),
      "first_sections":rows,
      "temporary_binaries_deleted":True,"binary_published":False
    }
    print("Q3_BOOT_MAP1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("Q3_BOOT_MAP1K_JSON_END")
if __name__=="__main__":main()
