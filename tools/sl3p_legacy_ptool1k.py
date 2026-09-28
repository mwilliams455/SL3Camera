#!/usr/bin/env python3
"""Compare a PTool-supported Panasonic GX1 firmware with the modern UPD family.

Official GX1 firmware is downloaded read-only. PTool ZIP is optionally downloaded and
string-scanned but never executed. No binaries are published.
"""
from __future__ import annotations
import hashlib,io,json,re,tempfile,urllib.request,zipfile
from pathlib import Path
from sl3p_upd_family1k import inspect_family

GX1="https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/GX1__V11.zip"
PTOOL="https://www.personal-view.com/gh1hack/ptool3d.zip"

def fetch(u,timeout=240):
    req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=timeout) as r:return r.read(),r.geturl(),r.status,r.headers.get("Content-Type")

def strings(data,minlen=5):
    ascii_hits=[m.group().decode("ascii","replace") for m in re.finditer(rb"[ -~]{%d,}"%minlen,data)]
    # bounded UTF-16LE ASCII-range strings
    utf=[]
    pat=re.compile(rb"(?:(?:[ -~])\x00){%d,}"%minlen)
    for m in pat.finditer(data):
        try:utf.append(m.group()[::2].decode("ascii","replace"))
        except:pass
    return ascii_hits,utf

def selected(ss):
    terms=("panasonic","lumix","gx1","gh1","gh2","gf1","gf2","gf3","g2","g3","tz10",
           "upd","loader","program","firmware","aes","sha","crypt","encrypt","decrypt","version")
    out=[]
    for s in ss:
        if any(t in s.lower() for t in terms) and len(s)<240:
            out.append(s)
    # stable unique
    return list(dict.fromkeys(out))[:500]

def main():
    zraw,zurl,zstatus,ztype=fetch(GX1)
    result={"tool":"LEGACY_PTOOL_LINEAGE1K",
      "gx1_zip":{"url":GX1,"final_url":zurl,"status":zstatus,"content_type":ztype,
                 "bytes":len(zraw),"sha256":hashlib.sha256(zraw).hexdigest()}}
    if not zipfile.is_zipfile(io.BytesIO(zraw)): raise RuntimeError("GX1 response not ZIP")
    with zipfile.ZipFile(io.BytesIO(zraw)) as z,tempfile.TemporaryDirectory(prefix="gx1-") as td:
        member=next(n for n in z.namelist() if n.lower().endswith(".bin"))
        data=z.read(member);p=Path(td)/"gx1.bin";p.write_bytes(data)
        rec={"member":member,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
             "prefix64_hex":data[:64].hex()}
        try:
            inv=inspect_family(p)
            rec["upd_family"]={"accepted":True,"identifier":inv["internal_identifier"],
              "outer_transform":inv["outer_transform"],"brand_marker_0x200_hex":inv["brand_marker_0x200_hex"],
              "entry_count":inv["directory"]["entry_count"],"counts":inv["counts"],
              "sections":[[s["index"],s["name"],s["size"],s["flags"],s["expected_sha256"],
                           s["classification"],s["target_offset_unconfirmed"]]
                          for s in inv["sections"]]}
        except Exception as e:
            rec["upd_family"]={"accepted":False,"error":f"{type(e).__name__}: {e}"}
            a,u=strings(data[:min(len(data),2_000_000)])
            rec["selected_strings_first_2m"]=selected(a+u)
        result["gx1_bin"]=rec
    try:
        praw,purl,pstatus,ptype=fetch(PTOOL,120)
        prec={"url":PTOOL,"final_url":purl,"status":pstatus,"content_type":ptype,
              "bytes":len(praw),"sha256":hashlib.sha256(praw).hexdigest(),
              "is_zip":zipfile.is_zipfile(io.BytesIO(praw))}
        if prec["is_zip"]:
            with zipfile.ZipFile(io.BytesIO(praw)) as z:
                members=[]
                for i in z.infolist():
                    if i.is_dir():continue
                    d=z.read(i)
                    a,u=strings(d)
                    members.append({"name":i.filename,"bytes":len(d),"sha256":hashlib.sha256(d).hexdigest(),
                                    "prefix64_hex":d[:64].hex(),"selected_strings":selected(a+u)})
                prec["members"]=members
        result["ptool"]=prec
    except Exception as e:
        result["ptool"]={"url":PTOOL,"error":f"{type(e).__name__}: {e}"}
    result["temporary_binaries_deleted"]=True;result["binary_published"]=False;result["binary_executed"]=False
    print("LEGACY_PTOOL_LINEAGE1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("LEGACY_PTOOL_LINEAGE1K_JSON_END")
if __name__=="__main__":main()
