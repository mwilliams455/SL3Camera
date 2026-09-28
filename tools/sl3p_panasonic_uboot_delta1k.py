#!/usr/bin/env python3
"""Diff Panasonic-published U-Boot sources against upstream v2019.07.

GPL source only. No proprietary firmware is downloaded or inspected.
"""
from __future__ import annotations
import hashlib, io, json, tarfile, urllib.request

SOURCES={
 "GH7":"https://ospo.panasonic.com/oss/source/dsc/DC-GH7/u-boot-v2019.07.tar.gz",
 "S5M2":"https://ospo.panasonic.com/oss/source/dsc/DC-S5M2/u-boot.tar.gz",
 "UPSTREAM":"https://github.com/u-boot/u-boot/archive/refs/tags/v2019.07.tar.gz",
}
INTEREST=("milbeaut","socionext","panasonic","update","upgrade","crypto","aes","sha","secure","boot","flash","spi","mtd","nand","mmc","fit","avb")

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=120) as r:return r.read()

def archive_map(raw):
    out={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
        members=[m for m in tf if m.isfile()]
        roots=set(m.name.split("/",1)[0] for m in members)
        for m in members:
            f=tf.extractfile(m)
            if f is None: continue
            data=f.read()
            path=m.name.split("/",1)[1] if "/" in m.name else m.name
            out[path]=(hashlib.sha256(data).hexdigest(),len(data),data)
    return out,sorted(roots)

def relevant(path):
    p=path.lower()
    return any(x in p for x in INTEREST) or p.startswith(("board/","configs/","arch/arm/mach-","include/configs/"))

def main():
    blobs={}; meta={}
    for n,u in SOURCES.items():
        raw=fetch(u)
        mp,roots=archive_map(raw)
        blobs[n]=mp
        meta[n]={"url":u,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),"roots":roots,"files":len(mp)}
    upstream=blobs["UPSTREAM"]
    results={}
    for n in ("GH7","S5M2"):
        v=blobs[n]
        added=sorted(set(v)-set(upstream))
        removed=sorted(set(upstream)-set(v))
        modified=sorted(p for p in set(v)&set(upstream) if v[p][0]!=upstream[p][0])
        interesting=sorted(set(p for p in added+modified if relevant(p)))
        # selected snippets from Panasonic-changed files
        snippets=[]
        for p in interesting:
            if len(snippets)>=250: break
            data=v[p][2]
            if len(data)>1_000_000: continue
            txt=data.decode("utf-8","ignore")
            hits=[]
            for term in INTEREST:
                for line in txt.splitlines():
                    if term in line.lower():
                        hits.append(line.strip()[:220]); break
            if hits:
                snippets.append({"path":p,"status":"added" if p in added else "modified","bytes":v[p][1],"snippets":hits[:6]})
        results[n]={
          "added_count":len(added),"removed_count":len(removed),"modified_count":len(modified),
          "added":added[:500],"modified":modified[:500],"interesting":interesting[:500],"snippets":snippets
        }
    # direct vendor-vendor comparison
    a,b=blobs["GH7"],blobs["S5M2"]
    shared=set(a)&set(b)
    same=sum(1 for p in shared if a[p][0]==b[p][0])
    diff=sorted(p for p in shared if a[p][0]!=b[p][0])
    print("PANASONIC_UBOOT_DELTA1K_JSON_BEGIN")
    print(json.dumps({"tool":"PANASONIC_UBOOT_DELTA1K","meta":meta,"results":results,
      "vendor_compare":{"shared_files":len(shared),"same_hash":same,"different_hash":len(diff),"different":diff[:500]}},
      separators=(",",":")))
    print("PANASONIC_UBOOT_DELTA1K_JSON_END")
if __name__=="__main__":main()
