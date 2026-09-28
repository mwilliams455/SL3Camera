#!/usr/bin/env python3
"""Decode bounded header/directory fields of Panasonic GH3 nested-UPD firmware."""
from __future__ import annotations
import hashlib,io,json,struct,urllib.request,zipfile
URL="https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/GH3__V12.zip"
def fetch(u):
 req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=240) as r:return r.read()
def u32(b,o): return struct.unpack_from("<I",b,o)[0]
def main():
 zraw=fetch(URL)
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  name=next(n for n in z.namelist() if n.lower().endswith(".bin"));data=z.read(name)
 header=data[:0x3000]
 records=[]
 for i in range(32):
  at=0x2ec+i*0x5c
  e=header[at:at+0x5c]
  if len(e)<0x5c:break
  rawname=e[:12].split(b"\0")[0]
  try:n=rawname.decode("ascii")
  except:n=""
  if not n or not all(c.isalnum() or c=="_" for c in n):break
  records.append({"index":i,"at":at,"name":n,
    "u32_12_28":[u32(e,o) for o in (12,16,20,24)],
    "bytes_28_60":e[28:60].hex(),"bytes_60_76":e[60:76].hex(),"bytes_76_92":e[76:92].hex()})
 result={"tool":"GH3_NESTED_HEADER1K","url":URL,"zip_sha256":hashlib.sha256(zraw).hexdigest(),
  "bin_name":name,"bin_bytes":len(data),"bin_sha256":hashlib.sha256(data).hexdigest(),
  "outer_u32":{"0x38":u32(header,0x38),"0x3c":u32(header,0x3c),"0x40":u32(header,0x40)},
  "brand_0x200":header[0x200:0x220].hex(),
  "nested_0x2a0_0x2ec":header[0x2a0:0x2ec].hex(),
  "nested_u32":{"0x2a0":u32(header,0x2a0),"0x2a4":u32(header,0x2a4),"0x2a8":u32(header,0x2a8),
    "0x2b0":u32(header,0x2b0),"0x2d8":u32(header,0x2d8),"0x2dc":u32(header,0x2dc),
    "0x2e0":u32(header,0x2e0),"0x2e4":u32(header,0x2e4),"0x2e8":u32(header,0x2e8)},
  "records_92byte_candidates":records,
  "temporary_binaries_deleted":True,"binary_published":False}
 print("GH3_NESTED_HEADER1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("GH3_NESTED_HEADER1K_JSON_END")
if __name__=="__main__":main()
