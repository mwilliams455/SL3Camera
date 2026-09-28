#!/usr/bin/env python3
"""Test documented PTool-era Panasonic XOR mask against official G3/GX1 and PTool."""
from __future__ import annotations
import hashlib,io,json,urllib.request,zipfile

MASK=bytes.fromhex(
 "0f71299c43b5b2ddaa584c2220904ea7"
 "f09b9ff28c980de93027362ea8ef3050"
 "b7f510bd"
)
URLS={
 "g3":"https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/G3___V12.zip",
 "gx1":"https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/GX1__V11.zip",
 "ptool":"https://www.personal-view.com/gh1hack/ptool3d.zip",
}
def fetch(u):
 req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=240) as r:return r.read()
def offsets(data,pat):
 out=[];p=0
 while True:
  i=data.find(pat,p)
  if i<0:break
  out.append(i);p=i+1
 return out
def cam(name,url):
 zraw=fetch(url)
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  member=next(n for n in z.namelist() if n.lower().endswith(".bin"));d=z.read(member)
 c=d[0x200:0x200+len(MASK)]
 decoded=bytes(x^y for x,y in zip(c,MASK))
 aligns=[]
 for off in range(0,0x80):
  clear=d[off:off+len(MASK)]
  if len(clear)<len(MASK):continue
  derived=bytes(x^y for x,y in zip(c,clear))
  prefix=0
  while prefix<len(MASK) and derived[prefix]==MASK[prefix]:prefix+=1
  if prefix>=4:aligns.append({"clear_header_offset":off,"matching_mask_prefix":prefix,
    "derived_hex":derived.hex(),"clear_hex":clear.hex()})
 return {"url":url,"zip_sha256":hashlib.sha256(zraw).hexdigest(),"member":member,
   "bytes":len(d),"sha256":hashlib.sha256(d).hexdigest(),
   "cipher_0x200_hex":c.hex(),"mask_xor_decoded_hex":decoded.hex(),
   "mask_xor_decoded_ascii":"".join(chr(x) if 32<=x<127 else "." for x in decoded),
   "header_alignment_matches":aligns[:30]}
def main():
 cams={n:cam(n,u) for n,u in URLS.items() if n!="ptool"}
 zraw=fetch(URLS["ptool"])
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  member=next(n for n in z.namelist() if n.lower().endswith(".exe"));exe=z.read(member)
 pats={}
 for n in (4,8,12,16,28,len(MASK)):
  pats[str(n)]={"prefix":offsets(exe,MASK[:n])[:50],
                "suffix":offsets(exe,MASK[-n:])[:50]}
 # Search TZ6 variant with the 4-byte 43 b5 b2 dd block omitted.
 mask_no4=MASK[:4]+MASK[8:]
 pats["tz6_variant32"]={"hits":offsets(exe,mask_no4)[:50],"hex":mask_no4.hex()}
 out={"tool":"PTOOL_MASK1K",
   "historical_mask_hex":MASK.hex(),
   "historical_source":"https://www.dvxuser.com/threads/panasonic-tz10-firmware-decode.215960/page-2",
   "cameras":cams,
   "ptool":{"url":URLS["ptool"],"zip_sha256":hashlib.sha256(zraw).hexdigest(),
      "member":member,"bytes":len(exe),"sha256":hashlib.sha256(exe).hexdigest(),
      "mask_sequence_hits":pats},
   "binary_executed":False,"binary_published":False}
 print("PTOOL_MASK1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("PTOOL_MASK1K_JSON_END")
if __name__=="__main__":main()
