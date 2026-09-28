#!/usr/bin/env python3
"""Compare GH3 legacy nested protected-content fingerprints to modern Leica/Panasonic family."""
from __future__ import annotations
import hashlib,io,json,tempfile,urllib.request,zipfile
from pathlib import Path
from sl3p_upd_family1k import inspect_family

URLS={
 "gh3":"https://av.jpn.support.panasonic.com/support/share/eww/en/dsc/fts/mac/GH3__V12.zip",
 "s5m2":"https://av.jpn.support.panasonic.com/support/share2/eww/com/dsc/ff/zip/S5m2_V37.zip",
 "q3":"https://leica-camera.com/sites/default/files/Q3___411.lfu",
 "sl3":"https://leica-camera.com/sites/default/files/SL3__420.lfu",
}
def fetch(u):
 req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=300) as r:return r.read()
def load(name,url,td):
 raw=fetch(url)
 source={"url":url}
 if name in ("gh3","s5m2"):
  source["zip_bytes"]=len(raw);source["zip_sha256"]=hashlib.sha256(raw).hexdigest()
  with zipfile.ZipFile(io.BytesIO(raw)) as z:
   member=next(n for n in z.namelist() if n.lower().endswith(".bin"));data=z.read(member)
  source.update({"member":member,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
  p=Path(td)/(name+".bin");p.write_bytes(data)
 else:
  data=raw;source.update({"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()})
  p=Path(td)/(name+".lfu");p.write_bytes(data)
 return inspect_family(p),source
def protected(inv):
 return [s for s in inv["sections"] if s["flags"]==3 and s["size"]]
def fingerprint_set(inv):
 return {(s["size"],s["expected_sha256"]):s for s in protected(inv)}
def compare(a,b):
 ga=fingerprint_set(a);gb=fingerprint_set(b);matches=[]
 for key in sorted(set(ga)&set(gb)):
  x=ga[key];y=gb[key]
  matches.append({"size":key[0],"expected_sha256":key[1],
    "a":[x["index"],x["name"],x["target_offset_unconfirmed"]],
    "b":[y["index"],y["name"],y["target_offset_unconfirmed"]],
    "same_name":x["name"]==y["name"],
    "protected_payload_equal":x["payload_sha256_after_outer_transform"]==y["payload_sha256_after_outer_transform"],
    "metadata16_equal":x["unknown_16_bytes"]==y["unknown_16_bytes"]})
 return {"match_count":len(matches),"matched_bytes":sum(m["size"] for m in matches),"matches":matches}
def baseline():
 b=json.loads(Path("evidence/SL3P_421_COMPARISON_BASELINE.json").read_text())
 cols=b["columns"];rows=[]
 for vals in b["sections"]:
  d=dict(zip(cols,vals));rows.append(d)
 return b["internal_identifier"],rows
def compare_baseline(a,rows):
 ga=fingerprint_set(a);gb={(r["size"],r["expected_sha256"]):r for r in rows if r["flags"]==3 and r["size"]}
 matches=[]
 for key in sorted(set(ga)&set(gb)):
  x=ga[key];y=gb[key]
  matches.append({"size":key[0],"expected_sha256":key[1],
    "a":[x["index"],x["name"],x["target_offset_unconfirmed"]],"b":[y["index"],y["name"]],
    "same_name":x["name"]==y["name"],
    "protected_payload_equal":x["payload_sha256_after_outer_transform"]==y["stored_payload_sha256"],
    "metadata16_equal":hashlib.sha256(bytes.fromhex(x["unknown_16_bytes"])).hexdigest()==y["metadata16_sha256"]})
 return {"match_count":len(matches),"matched_bytes":sum(m["size"] for m in matches),"matches":matches}
def main():
 with tempfile.TemporaryDirectory(prefix="legacycompare1k-") as td:
  inv={};src={}
  for n,u in URLS.items():inv[n],src[n]=load(n,u,td)
 sl3pid,sl3prows=baseline()
 out={"tool":"GH3_MODERN_COMPARE1K","sources":src,
   "inventories":{n:{"identifier":v["internal_identifier"],"layout":v["directory"]["layout"],
       "entry_count":v["directory"]["entry_count"],"protected_count":len(protected(v)),
       "protected_names":[s["name"] for s in protected(v)]} for n,v in inv.items()},
   "comparisons":{"gh3_s5m2":compare(inv["gh3"],inv["s5m2"]),
                  "gh3_q3":compare(inv["gh3"],inv["q3"]),
                  "gh3_sl3":compare(inv["gh3"],inv["sl3"]),
                  "gh3_sl3p":compare_baseline(inv["gh3"],sl3prows)},
   "sl3p_identifier":sl3pid,"temporary_binaries_deleted":True,"binary_published":False}
 print("GH3_MODERN_COMPARE1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("GH3_MODERN_COMPARE1K_JSON_END")
if __name__=="__main__":main()
