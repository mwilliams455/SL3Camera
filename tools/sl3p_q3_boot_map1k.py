#!/usr/bin/env python3
"""Correlate Q3 UPD target offsets with Q3 published boot addresses.

Official Q3 firmware and OSS source only; no binaries are published.
"""
from __future__ import annotations
import io,json,re,tempfile,urllib.request,zipfile,tarfile
from pathlib import Path
from sl3p_inspect import inspect
FW="https://leica-camera.com/sites/default/files/Q3___411.lfu"
OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
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
            if q in ("configs/pvc04v_MC501_defconfig","include/configs/sc2006a-evb.h"):
                d=tf.extractfile(m).read().decode("utf-8","replace")
                wanted[q]=d
    cfg=wanted["configs/pvc04v_MC501_defconfig"]
    def hx(pattern,text):
        x=re.search(pattern,text)
        if not x:raise RuntimeError(pattern)
        return int(x.group(1),16)
    uboot=hx(r"CONFIG_SYS_TEXT_BASE=(0x[0-9A-Fa-f]+)",cfg)
    zkernel=hx(r"# ZKERNEL_ADDRESS:\s*(0x[0-9A-Fa-f]+)",cfg)
    kernel=hx(r"# KERNEL_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",cfg)
    dtb=hx(r"# DTB_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",cfg)
    rows=[]
    for s in inv["sections"][:15]:
        off=s["target_offset_unconfirmed"]
        rows.append({"index":s["index"],"name":s["name"],"offset":off,"size":s["size"],
                     "mapped_from_uboot_base":uboot+off})
    named={r["name"]:r for r in rows}
    result={
      "tool":"Q3_BOOT_MAP1K",
      "firmware_identifier":inv["internal_identifier"],
      "crc_matches":inv["crc32_region"]["matches"],
      "published_addresses":{"uboot":uboot,"zkernel":zkernel,"kernel":kernel,"dtb":dtb},
      "offset_relationships":{
        "zkernel_minus_uboot":zkernel-uboot,
        "dtb_minus_uboot":dtb-uboot,
        "kernel_minus_uboot":kernel-uboot,
        "loader1_maps_to_uboot":named["loader1"]["mapped_from_uboot_base"]==uboot,
        "program_maps_to_zkernel":named["program"]["mapped_from_uboot_base"]==zkernel,
        "dtb_relative_to_program_start":dtb-zkernel,
        "kernel_is_linux_memory_base_candidate":kernel
      },
      "first_sections":rows,
      "temporary_binaries_deleted":True,"binary_published":False
    }
    print("Q3_BOOT_MAP1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("Q3_BOOT_MAP1K_JSON_END")
if __name__=="__main__":main()
