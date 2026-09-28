#!/usr/bin/env python3
"""Compare official Leica Q3 4.1.1 and SL3 4.2.0 UPD expected-content fingerprints."""
from __future__ import annotations
import hashlib,json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect
SOURCES={
 "q3":"https://leica-camera.com/sites/default/files/Q3___411.lfu",
 "sl3":"https://leica-camera.com/sites/default/files/SL3__420.lfu",
}
def get(url,path):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    h=hashlib.sha256();n=0
    with urllib.request.urlopen(req,timeout=240) as r,open(path,"wb") as f:
        while True:
            b=r.read(1024*1024)
            if not b:break
            f.write(b);h.update(b);n+=len(b)
    return n,h.hexdigest()
def project(inv):
    return [{"i":s["index"],"name":s["name"],"size":s["size"],"flags":s["flags"],
             "expected":s["stored_sha256"],"class":s["classification"]} for s in inv["sections"]]
def main():
    with tempfile.TemporaryDirectory(prefix="q3sl3-") as td:
        data={}
        for k,u in SOURCES.items():
            p=Path(td)/(k+".lfu")
            n,sha=get(u,p); inv=inspect(p)
            data[k]={"url":u,"bytes":n,"sha256":sha,"identifier":inv["internal_identifier"],
                     "crc_matches":inv["crc32_region"]["matches"],"sections":project(inv)}
        matches=[]
        for a in data["q3"]["sections"]:
            for b in data["sl3"]["sections"]:
                if a["size"] and a["size"]==b["size"] and a["expected"]==b["expected"]:
                    matches.append({"q3_index":a["i"],"q3_name":a["name"],"sl3_index":b["i"],
                                    "sl3_name":b["name"],"size":a["size"],
                                    "q3_flags":a["flags"],"sl3_flags":b["flags"],
                                    "protected_both":a["flags"]==b["flags"]==3})
        result={"tool":"Q3_SL3_COMPARE1K","sources":data,
                "matches":matches,
                "protected_match_count":sum(x["protected_both"] for x in matches),
                "protected_q3_names":sorted({x["q3_name"] for x in matches if x["protected_both"]}),
                "binary_published":False,"temporary_binaries_deleted":True}
        # compact output: source metadata and matches only, not full directories
        result["sources"]={k:{kk:v[kk] for kk in ("url","bytes","sha256","identifier","crc_matches")} for k,v in data.items()}
        print("Q3_SL3_COMPARE1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("Q3_SL3_COMPARE1K_JSON_END")
if __name__=="__main__":main()
