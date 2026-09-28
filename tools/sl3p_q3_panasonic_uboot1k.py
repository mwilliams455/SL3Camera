#!/usr/bin/env python3
"""Compare Leica Q3's official OSS U-Boot with Panasonic S5M2 and upstream.

Open-source packages only; no LFU/proprietary firmware.
"""
from __future__ import annotations
import hashlib, io, json, tarfile, tempfile, urllib.request, zipfile, os

Q3_OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
S5="https://ospo.panasonic.com/oss/source/dsc/DC-S5M2/u-boot.tar.gz"
UP="https://github.com/u-boot/u-boot/archive/refs/tags/v2019.07.tar.gz"

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=180) as r:return r.read()

def amap(raw):
    out={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
        for m in tf:
            if not m.isfile():continue
            f=tf.extractfile(m)
            if not f:continue
            d=f.read()
            p=m.name.split("/",1)[1] if "/" in m.name else m.name
            out[p]=(hashlib.sha256(d).hexdigest(),len(d),d)
    return out

def snippets(mp,paths):
    out=[]
    for p in paths:
        if p not in mp:continue
        d=mp[p][2]
        txt=d.decode("utf-8","ignore")
        lines=[x.strip() for x in txt.splitlines() if x.strip()]
        chosen=[]
        for key in ("MC","MILBEAUT","CONFIG_","Panasonic","Leica","boot","MMC","SDHCI","SOCIONEXT","pvc04"):
            for line in lines:
                if key.lower() in line.lower() and line not in chosen:
                    chosen.append(line[:240]);break
        out.append({"path":p,"bytes":len(d),"sha256":mp[p][0],"snippets":chosen[:10]})
    return out

def main():
    qzip=fetch(Q3_OSS)
    with zipfile.ZipFile(io.BytesIO(qzip)) as z:
        candidates=[n for n in z.namelist() if n.lower().endswith("u-boot.tar.gz")]
        if len(candidates)!=1:raise RuntimeError(f"expected one Q3 u-boot, got {candidates}")
        qraw=z.read(candidates[0])
    sraw=fetch(S5); uraw=fetch(UP)
    q,s,u=amap(qraw),amap(sraw),amap(uraw)
    def diff(a,b):
        added=sorted(set(a)-set(b)); removed=sorted(set(b)-set(a))
        modified=sorted(p for p in set(a)&set(b) if a[p][0]!=b[p][0])
        return added,removed,modified
    qa,qr,qm=diff(q,u)
    sa,sr,sm=diff(s,u)
    qsa,qsr,qsm=diff(q,s)
    select=sorted(set(qa+qm+qsa+qsm))
    print("Q3_PANASONIC_UBOOT1K_JSON_BEGIN")
    print(json.dumps({
      "tool":"Q3_PANASONIC_UBOOT1K",
      "sources":{
       "q3_oss":{"url":Q3_OSS,"outer_bytes":len(qzip),"outer_sha256":hashlib.sha256(qzip).hexdigest(),
                 "entry":candidates[0],"uboot_bytes":len(qraw),"uboot_sha256":hashlib.sha256(qraw).hexdigest(),"files":len(q)},
       "s5m2":{"url":S5,"bytes":len(sraw),"sha256":hashlib.sha256(sraw).hexdigest(),"files":len(s)},
       "upstream":{"url":UP,"bytes":len(uraw),"sha256":hashlib.sha256(uraw).hexdigest(),"files":len(u)}
      },
      "q3_vs_upstream":{"added":qa,"removed_count":len(qr),"modified":qm},
      "s5_vs_upstream":{"added":sa,"removed_count":len(sr),"modified":sm},
      "q3_vs_s5m2":{"added_q3":qsa,"removed_q3":qsr,"modified":qsm,
                    "shared":len(set(q)&set(s)),
                    "same_hash":sum(1 for p in set(q)&set(s) if q[p][0]==s[p][0])},
      "selected_files":snippets(q,select)
    },separators=(",",":")))
    print("Q3_PANASONIC_UBOOT1K_JSON_END")
if __name__=="__main__":main()
