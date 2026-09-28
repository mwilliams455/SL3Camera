#!/usr/bin/env python3
"""Probe Panasonic G3/GH3 format transition around PTool support boundary."""
from __future__ import annotations
import hashlib,io,json,re,tempfile,urllib.request,zipfile
from pathlib import Path
from sl3p_upd_family1k import inspect_family

MODELS={
 "g3":"https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/G3___V12.zip",
 "gh3":"https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/GH3__V12.zip",
}
def fetch(u):
 req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=240) as r:return r.read(),r.geturl(),r.status,r.headers.get("Content-Type")
def probe(data):
 variants=[("direct",data[:0x20000]),("xor_ff",bytes(b^0xff for b in data[:0x20000]))]
 out={}
 for name,b in variants:
  hits={}
  for term in (b"UPD\0",b"panasonic",b"leica",b"loader1",b"program",b"compress_pr",b"postboot1",b"eep_ow_a"):
   offs=[];p=0
   while True:
    i=b.find(term,p)
    if i<0:break
    offs.append(i);p=i+1
   if offs:hits[term.decode("ascii","replace")]=offs[:30]
  out[name]={"prefix64_hex":b[:64].hex(),"hits":hits}
 return out
def main():
 results={}
 with tempfile.TemporaryDirectory(prefix="transition1k-") as td:
  for name,url in MODELS.items():
   zraw,final,status,ctype=fetch(url)
   rec={"url":url,"final_url":final,"status":status,"content_type":ctype,
        "zip_bytes":len(zraw),"zip_sha256":hashlib.sha256(zraw).hexdigest()}
   if not zipfile.is_zipfile(io.BytesIO(zraw)):
    rec["error"]="not zip";results[name]=rec;continue
   with zipfile.ZipFile(io.BytesIO(zraw)) as z:
    member=next(n for n in z.namelist() if n.lower().endswith(".bin")); data=z.read(member)
   rec.update({"member":member,"bin_bytes":len(data),"bin_sha256":hashlib.sha256(data).hexdigest(),"header_probe":probe(data)})
   p=Path(td)/(name+".bin");p.write_bytes(data)
   try:
    inv=inspect_family(p)
    rec["modern_family"]={"accepted":True,"identifier":inv["internal_identifier"],
      "outer_transform":inv["outer_transform"],"brand_marker_0x200_hex":inv["brand_marker_0x200_hex"],
      "entry_count":inv["directory"]["entry_count"],"counts":inv["counts"]}
   except Exception as e:rec["modern_family"]={"accepted":False,"error":f"{type(e).__name__}: {e}"}
   results[name]=rec
 print("PANASONIC_TRANSITION1K_JSON_BEGIN");print(json.dumps({"tool":"PANASONIC_TRANSITION1K","results":results,
   "temporary_binaries_deleted":True,"binary_published":False},separators=(",",":")));print("PANASONIC_TRANSITION1K_JSON_END")
if __name__=="__main__":main()
