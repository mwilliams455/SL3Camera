#!/usr/bin/env python3
"""Bounded header probe for official Panasonic S5M2 firmware.

Fetches vendor ZIP, inspects normalized UPD bytes, emits metadata only, deletes binary.
"""
from __future__ import annotations
import hashlib, io, json, re, urllib.request, zipfile
URL="https://av.jpn.support.panasonic.com/support/share2/eww/com/dsc/ff/zip/S5m2_V37.zip"
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=300) as r:return r.read()
def main():
    zraw=fetch(URL)
    with zipfile.ZipFile(io.BytesIO(zraw)) as z:
        name=next(n for n in z.namelist() if n.lower().endswith(".bin"))
        raw=z.read(name)
    inv=bytes((b^0xff) for b in raw[:0x20000])
    direct=raw[:0x20000]
    if direct[:4]==b"UPD\0": norm=direct; transform="direct"
    elif inv[:4]==b"UPD\0": norm=inv; transform="xor_ff"
    else: raise SystemExit("no UPD magic")
    terms=[b"UPD\0",b"loader1",b"loader2",b"loader3",b"storage",b"program",
           b"compress_pr",b"postboot1",b"eep_ow_a",b"lut_data",b"MC8223",b"leica"]
    hits={}
    for t in terms:
        offs=[]; start=0
        while True:
            i=norm.find(t,start)
            if i<0:break
            offs.append(i);start=i+1
        hits[t.decode("ascii","replace")]=offs[:50]
    ascii_strings=[]
    for m in re.finditer(rb"[ -~]{5,}",norm):
        s=m.group().decode("ascii","replace")
        if any(k in s.lower() for k in ("loader","program","postboot","eep_","lut","micon","hm_","hr_","kizu","wifi","bt_","lpc","raw_","mbr","upd")):
            ascii_strings.append([m.start(),s[:120]])
    out={"tool":"PANASONIC_S5M2_HEADER1K","zip_bytes":len(zraw),"zip_sha256":hashlib.sha256(zraw).hexdigest(),
         "bin_name":name,"bin_bytes":len(raw),"bin_sha256":hashlib.sha256(raw).hexdigest(),
         "outer_transform":transform,"normalized_prefix_512_hex":norm[:512].hex(),
         "term_hits_first_128k":hits,"selected_strings_first_128k":ascii_strings[:300],
         "temporary_binaries_deleted":True,"binary_published":False}
    print("PANASONIC_S5M2_HEADER1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("PANASONIC_S5M2_HEADER1K_JSON_END")
if __name__=="__main__":main()
