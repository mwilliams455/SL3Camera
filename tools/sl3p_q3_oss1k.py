#!/usr/bin/env python3
"""Inventory Leica's official Q3 open-source software package.

Downloads only Leica's published OSS ZIP, inventories nested source archives,
and prints bounded matches for update/boot/crypto/Milbeaut-related source.
No proprietary camera firmware is downloaded or published.
"""
from __future__ import annotations
import hashlib, io, json, os, re, tarfile, tempfile, urllib.request, zipfile

URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
TERMS=(b"milbeaut",b"socionext",b"upd",b"postboot",b"eep_ow",b"lut_data",
       b"hm_d_nw",b"firmware",b"update",b"upgrade",b"decrypt",b"encrypt",
       b"aes",b"sha256",b"secure boot",b"u-boot",b"freertos")
PATH_TERMS=("u-boot","uboot","linux","freertos","milbeaut","socionext","boot","crypto","firmware","update")

def download(url,path):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    h=hashlib.sha256(); n=0
    with urllib.request.urlopen(req,timeout=180) as r, open(path,"wb") as f:
        while True:
            b=r.read(1024*1024)
            if not b:break
            f.write(b);h.update(b);n+=len(b)
    return n,h.hexdigest()

def text_hits(path,data,limit=8):
    if len(data)>2_000_000:return []
    low=data.lower()
    hits=[]
    txt=data.decode("utf-8","ignore")
    lines=txt.splitlines()
    for t in TERMS:
        if t in low:
            term=t.decode("ascii","ignore")
            sample=None
            for line in lines:
                if term.lower() in line.lower():
                    sample=line.strip()[:240];break
            hits.append({"term":term,"line":sample})
            if len(hits)>=limit:break
    return hits

def nested_inventory(name,data):
    result={"name":name,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
            "kind":None,"members":0,"interesting_paths":[],"content_matches":[]}
    def add(path,payload):
        result["members"]+=1
        lp=path.lower()
        if any(x in lp for x in PATH_TERMS) and len(result["interesting_paths"])<300:
            result["interesting_paths"].append(path)
        if re.search(r"\.(c|h|s|dts|dtsi|cfg|config|mk|txt|md|sh|py)$",lp):
            h=text_hits(path,payload)
            if h and len(result["content_matches"])<200:
                result["content_matches"].append({"path":path,"hits":h})
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            result["kind"]="zip"
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for info in z.infolist():
                    if info.is_dir():continue
                    if info.file_size>2_000_000:
                        result["members"]+=1
                        lp=info.filename.lower()
                        if any(x in lp for x in PATH_TERMS) and len(result["interesting_paths"])<300:
                            result["interesting_paths"].append(info.filename)
                        continue
                    try:add(info.filename,z.read(info))
                    except Exception:pass
            return result
    except Exception:pass
    try:
        with tarfile.open(fileobj=io.BytesIO(data),mode="r:*") as tf:
            result["kind"]="tar"
            for m in tf:
                if not m.isfile():continue
                if m.size>2_000_000:
                    result["members"]+=1
                    lp=m.name.lower()
                    if any(x in lp for x in PATH_TERMS) and len(result["interesting_paths"])<300:
                        result["interesting_paths"].append(m.name)
                    continue
                f=tf.extractfile(m)
                if f:
                    try:add(m.name,f.read())
                    except Exception:pass
            return result
    except Exception as e:
        result["kind"]="opaque_or_other"
        result["error"]=f"{type(e).__name__}: {e}"
        return result

def main():
    with tempfile.TemporaryDirectory() as td:
        p=os.path.join(td,"q3_oss.zip")
        n,sha=download(URL,p)
        outer={"url":URL,"bytes":n,"sha256":sha,"entries":[],"nested":[]}
        with zipfile.ZipFile(p) as z:
            for info in z.infolist():
                if info.is_dir():continue
                entry={"name":info.filename,"bytes":info.file_size,"compressed":info.compress_size}
                outer["entries"].append(entry)
                lp=info.filename.lower()
                if info.file_size<=120_000_000 and (
                    lp.endswith((".tar.gz",".tgz",".tar.bz2",".tar.xz",".tar",".zip")) or
                    any(x in lp for x in PATH_TERMS)
                ):
                    try:
                        data=z.read(info)
                        outer["nested"].append(nested_inventory(info.filename,data))
                    except Exception as e:
                        outer["nested"].append({"name":info.filename,"error":f"{type(e).__name__}: {e}"})
        print("LEICA_Q3_OSS1K_JSON_BEGIN")
        print(json.dumps({"tool":"LEICA_Q3_OSS1K","outer":outer},separators=(",",":")))
        print("LEICA_Q3_OSS1K_JSON_END")
if __name__=="__main__":main()
