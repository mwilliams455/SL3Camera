#!/usr/bin/env python3
"""Static xref probe from PTool firmware/model tokens into 32-bit x86 code."""
from __future__ import annotations
import hashlib,io,json,struct,urllib.request,zipfile
import capstone as cs
from capstone.x86 import X86_OP_IMM,X86_OP_MEM
from sl3p_ptool_static1k import parse_pe

URL="https://www.personal-view.com/gh1hack/ptool3d.zip"
TARGET_BYTES={
 "UPD_NUL":b"UPD\0",
 "panasonic":b"panasonic",
 "GX1_v1_10":b"GX1 v1.10",
 "GH2_v1_11":b"GH2 v1.11",
 "Firmware_image_filter":b"Firmware image|*.bin",
 "LoadFirmware":b"LoadFirmware",
}
def fetch():
 req=urllib.request.Request(URL,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=180) as r:return r.read()
def allhits(data,p,cap=100):
 out=[];o=0
 while True:
  i=data.find(p,o)
  if i<0:break
  out.append(i);o=i+1
  if len(out)>=cap:break
 return out
def location(pe,off):
 for s in pe["sections"]:
  if s["raw_offset"]<=off<s["raw_offset"]+s["raw_size"]:
   rva=s["virtual_address"]+(off-s["raw_offset"])
   return {"section":s["name"],"rva":rva,"va":pe["image_base"]+rva}
 return {"section":None,"rva":None,"va":None}
def main():
 zraw=fetch()
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  member=next(n for n in z.namelist() if n.lower().endswith(".exe"));exe=z.read(member)
 pe=parse_pe(exe)
 targets={}
 for name,p in TARGET_BYTES.items():
  hs=allhits(exe,p);targets[name]=[{"file_offset":h,**location(pe,h)} for h in hs]
 # Disassemble .text and look for immediates/absolute memory displacements equal to target VAs.
 textsec=next(s for s in pe["sections"] if s["name"]==".text")
 raw=exe[textsec["raw_offset"]:textsec["raw_offset"]+textsec["raw_size"]]
 base=pe["image_base"]+textsec["virtual_address"]
 md=cs.Cs(cs.CS_ARCH_X86,cs.CS_MODE_32);md.detail=True
 target_map={}
 for name,items in targets.items():
  for item in items:
   if item["va"] is not None:target_map.setdefault(item["va"],[]).append(name)
 xrefs=[]
 insns=list(md.disasm(raw,base))
 for ins in insns:
  vals=[]
  for op in ins.operands:
   if op.type==X86_OP_IMM:vals.append(("imm",op.imm&0xffffffff))
   elif op.type==X86_OP_MEM and op.mem.base==0 and op.mem.index==0:vals.append(("mem_abs",op.mem.disp&0xffffffff))
  for kind,val in vals:
   if val in target_map:
    xrefs.append({"address":ins.address,"file_offset":textsec["raw_offset"]+(ins.address-base),
      "mnemonic":ins.mnemonic,"operands":ins.op_str,"kind":kind,"target_va":val,"targets":target_map[val]})
 # direct byte hits in text get local decode from preceding plausible boundaries
 raw_hits=[]
 for name,p in TARGET_BYTES.items():
  for h in allhits(exe,p):
   if textsec["raw_offset"]<=h<textsec["raw_offset"]+textsec["raw_size"]:
    va=base+(h-textsec["raw_offset"])
    start=max(base,va-24);so=textsec["raw_offset"]+(start-base)
    win=exe[so:so+72]
    decoded=[{"address":i.address,"mnemonic":i.mnemonic,"operands":i.op_str,"size":i.size}
             for i in md.disasm(win,start)][:24]
    raw_hits.append({"target":name,"file_offset":h,"va":va,"decode_from_minus24":decoded})
 out={"tool":"PTOOL_XREF1K","exe_sha256":hashlib.sha256(exe).hexdigest(),
      "targets":targets,"instruction_xrefs":xrefs,"raw_hits_in_text":raw_hits,
      "decoded_text_instruction_count":len(insns),"binary_executed":False,"binary_published":False,
      "limits":["Capstone linear disassembly can decode embedded data as instructions.",
                "Absolute-immediate xrefs do not recover indirect/data-table references.",
                "No claim that old PTool crypto applies to nested GH3/SL3-P UPD."]}
 print("PTOOL_XREF1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("PTOOL_XREF1K_JSON_END")
if __name__=="__main__":main()
