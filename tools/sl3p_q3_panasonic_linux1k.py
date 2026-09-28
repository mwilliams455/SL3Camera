#!/usr/bin/env python3
"""Compare Leica Q3 and Panasonic S5M2 published Linux 4.19.124 sources.

Open-source source archives only. No camera firmware is downloaded or inspected.
"""
from __future__ import annotations
import hashlib, io, json, re, tarfile, tempfile, urllib.request, zipfile, os

Q3_OSS="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
S5_LINUX="https://ospo.panasonic.com/oss/source/dsc/DC-S5M2/linux-4.19.124.tar.gz"
FOCUS=("milbeaut","socionext","pvc04","panasonic","leica","firmware","update","upgrade",
       "secure","trusted","optee","tee","crypto","aes","sha","mmc","mtd","spi","boot")
TEXT_EXT=(".c",".h",".s",".S",".dts",".dtsi",".config",".cfg",".mk",".txt",".md",".sh")

def fetch_to(url,path):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    h=hashlib.sha256(); n=0
    with urllib.request.urlopen(req,timeout=240) as r, open(path,"wb") as f:
        while True:
            b=r.read(1024*1024)
            if not b: break
            f.write(b); h.update(b); n+=len(b)
    return n,h.hexdigest()

def norm(path):
    return path.split("/",1)[1] if "/" in path else path

def tar_index(raw_path):
    idx={}
    with tarfile.open(raw_path,mode="r:gz") as tf:
        for m in tf:
            if not m.isfile(): continue
            f=tf.extractfile(m)
            if not f: continue
            h=hashlib.sha256(); total=0
            while True:
                b=f.read(1024*1024)
                if not b: break
                h.update(b); total+=len(b)
            idx[norm(m.name)]=(h.hexdigest(),total)
    return idx

def read_member(raw_path,target):
    with tarfile.open(raw_path,mode="r:gz") as tf:
        for m in tf:
            if m.isfile() and norm(m.name)==target:
                f=tf.extractfile(m)
                return f.read() if f else b""
    return None

def main():
    with tempfile.TemporaryDirectory(prefix="linux1k-") as td:
        qzip_path=os.path.join(td,"q3oss.zip")
        s5_path=os.path.join(td,"s5-linux.tar.gz")
        qzip_bytes,qzip_sha=fetch_to(Q3_OSS,qzip_path)
        s5_bytes,s5_sha=fetch_to(S5_LINUX,s5_path)
        with zipfile.ZipFile(qzip_path) as z:
            names=[n for n in z.namelist() if n.endswith("linux-4.19.124.tar.gz")]
            if len(names)!=1: raise RuntimeError(f"expected one Q3 Linux archive, got {names}")
            qraw_path=os.path.join(td,"q3-linux.tar.gz")
            with z.open(names[0]) as src, open(qraw_path,"wb") as dst:
                h=hashlib.sha256(); n=0
                while True:
                    b=src.read(1024*1024)
                    if not b: break
                    dst.write(b); h.update(b); n+=len(b)
            qlinux_bytes=n; qlinux_sha=h.hexdigest()
        q=tar_index(qraw_path); s=tar_index(s5_path)
        added=sorted(set(q)-set(s)); removed=sorted(set(s)-set(q))
        modified=sorted(p for p in set(q)&set(s) if q[p][0]!=s[p][0])
        focus=sorted(p for p in set(added+removed+modified) if any(x in p.lower() for x in FOCUS))
        selected=[]
        for p in focus[:300]:
            qv=q.get(p); sv=s.get(p)
            rec={"path":p,"q3":qv[:2] if qv else None,"s5m2":sv[:2] if sv else None}
            source_path=qraw_path if qv else s5_path
            data=read_member(source_path,p)
            if data is not None and len(data)<=1_000_000 and p.endswith(TEXT_EXT):
                text=data.decode("utf-8","ignore")
                snippets=[]
                for term in FOCUS:
                    for line in text.splitlines():
                        if term in line.lower():
                            snippets.append(line.strip()[:220]); break
                    if len(snippets)>=8: break
                rec["snippets"]=snippets
            selected.append(rec)
        result={
          "tool":"Q3_PANASONIC_LINUX1K",
          "sources":{
            "q3_oss":{"url":Q3_OSS,"outer_bytes":qzip_bytes,"outer_sha256":qzip_sha,
                      "entry":names[0],"linux_bytes":qlinux_bytes,"linux_sha256":qlinux_sha,"files":len(q)},
            "s5m2":{"url":S5_LINUX,"bytes":s5_bytes,"sha256":s5_sha,"files":len(s)}
          },
          "comparison":{
            "shared_files":len(set(q)&set(s)),
            "same_hash":sum(1 for p in set(q)&set(s) if q[p][0]==s[p][0]),
            "added_q3_count":len(added),"removed_q3_count":len(removed),"modified_count":len(modified),
            "added_q3":added[:400],"removed_q3":removed[:400],"modified":modified[:400],
            "focus_changed":focus[:400],"selected":selected
          }
        }
        print("Q3_PANASONIC_LINUX1K_JSON_BEGIN")
        print(json.dumps(result,separators=(",",":")))
        print("Q3_PANASONIC_LINUX1K_JSON_END")
if __name__=="__main__": main()
