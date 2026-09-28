#!/usr/bin/env python3
"""Overlay every Q3 protected section with addresses and RTOS/shared-memory definitions in Leica OSS."""
from __future__ import annotations
import hashlib,io,json,re,tarfile,tempfile,urllib.request,zipfile
from pathlib import Path
from sl3p_upd_family1k import inspect_family

FW="https://leica-camera.com/sites/default/files/Q3___411.lfu"
OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"

def fetch(u):
 req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=300) as r:return r.read()

def member_text(tarraw,suffix):
 with tarfile.open(fileobj=io.BytesIO(tarraw),mode="r:gz") as tf:
  ms=[m for m in tf.getmembers() if m.isfile() and m.name.endswith(suffix)]
  if len(ms)!=1:raise RuntimeError(f"{suffix}: {len(ms)} matches")
  return tf.extractfile(ms[0]).read().decode("utf-8","replace")

def parse_base(cfg):
 m=re.search(r"CONFIG_SYS_TEXT_BASE=(0x[0-9A-Fa-f]+)",cfg)
 if not m:raise RuntimeError("U-Boot base missing")
 return int(m.group(1),16)

def selected_lines(text):
 out=[]
 for no,line in enumerate(text.splitlines(),1):
  lo=line.lower()
  if any(k in lo for k in ("rtos","shared","commem","reserved","slram","cnn","memory","reg =","mtd","ipc","mailbox","remote","rproc")):
   out.append([no,line.rstrip()])
 return out

def hex_values(text):
 vals=[]
 for no,line in enumerate(text.splitlines(),1):
  for m in re.finditer(r"0x[0-9A-Fa-f]+",line):
   v=int(m.group(),16)
   if v>=0x10000:vals.append({"line":no,"hex":m.group(),"value":v,"text":line.strip()[:240]})
 return vals

def main():
 fwraw=fetch(FW);ossraw=fetch(OSS)
 with tempfile.TemporaryDirectory(prefix="q3rtos1k-") as td:
  p=Path(td)/"q3.lfu";p.write_bytes(fwraw);inv=inspect_family(p)
 with zipfile.ZipFile(io.BytesIO(ossraw)) as z:
  u=z.read(next(n for n in z.namelist() if n.endswith("u-boot.tar.gz")))
  l=z.read(next(n for n in z.namelist() if n.endswith("linux-4.19.124.tar.gz")))
 cfg=member_text(u,"configs/pvc04v_MC501_defconfig")
 files={}
 for suffix in ("arch/arm64/boot/dts/socionext/pvc04v-DC1231-rtos.h",
                "arch/arm64/boot/dts/socionext/pvc04v-DC1231.dts",
                "arch/arm64/boot/dts/socionext/pvc04v-DC1231.dtsi"):
  txt=member_text(l,suffix);files[suffix]={"sha256":hashlib.sha256(txt.encode()).hexdigest(),
       "bytes":len(txt.encode()),"selected_lines":selected_lines(txt),"hex_values":hex_values(txt)}
 base=parse_base(cfg)
 sections=[]
 for s in inv["sections"]:
  if not s["size"]:continue
  start=base+s["target_offset_unconfirmed"];end=start+s["size"]
  sections.append({"index":s["index"],"name":s["name"],"flags":s["flags"],"size":s["size"],
    "target_offset":s["target_offset_unconfirmed"],"mapped_start":start,"mapped_end":end,
    "expected_sha256":s["expected_sha256"] if s["flags"]==3 else None})
 out={"tool":"Q3_RTOS_MAP1K","source":{"firmware_sha256":hashlib.sha256(fwraw).hexdigest(),
      "oss_sha256":hashlib.sha256(ossraw).hexdigest()},"identifier":inv["internal_identifier"],
      "uboot_base":base,"sections":sections,"published_source_files":files,
      "temporary_binaries_deleted":True,"binary_published":False,
      "limits":["Mapped starts use UPD target offsets relative to published U-Boot text base; runtime semantics are inferred, not decoded.",
                "Selected source lines/hex constants do not by themselves establish section ownership."]}
 print("Q3_RTOS_MAP1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("Q3_RTOS_MAP1K_JSON_END")
if __name__=="__main__":main()
