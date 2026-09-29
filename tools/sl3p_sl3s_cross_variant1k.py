#!/usr/bin/env python3
"""Compare SL3-P 4.2.1 expected content hashes with public SL3-S 4.2.0.

Goal: detect protected SL3-P content that is distributed unprotected in the close sibling.
No firmware bytes are published.
"""
from __future__ import annotations
import json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect

URL="https://leica-camera.com/sites/default/files/SL3S_420.lfu"
BASELINE=Path(__file__).resolve().parents[1]/"evidence/SL3P_421_COMPARISON_BASELINE.json"

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()

def main():
    base=json.loads(BASELINE.read_text(encoding="utf-8"))
    cols=base["columns"]; ix={k:i for i,k in enumerate(cols)}
    p_rows=[{
       "index":r[ix["index"]],"name":r[ix["name"]],"size":r[ix["size"]],
       "flags":r[ix["flags"]],"expected_sha256":r[ix["expected_sha256"]]
    } for r in base["sections"]]
    data=fetch(URL)
    with tempfile.TemporaryDirectory(prefix="sl3s-") as td:
        p=Path(td)/"sl3s.lfu"; p.write_bytes(data); s=inspect(p)
    by_hash={}
    for r in s["sections"]:
        by_hash.setdefault((r["size"],r["stored_sha256"]),[]).append(r)
    matches=[]; recoveries=[]
    for p in p_rows:
        for q in by_hash.get((p["size"],p["expected_sha256"]),[]):
            rec={"sl3p_index":p["index"],"sl3p_name":p["name"],"sl3p_flags":p["flags"],
                 "sl3s_index":q["index"],"sl3s_name":q["name"],"sl3s_flags":q["flags"],
                 "size":p["size"],"expected_sha256":p["expected_sha256"],
                 "sl3s_classification":q["classification"],"sl3s_sha256_matches":q["sha256_matches"]}
            matches.append(rec)
            if p["flags"]==3 and q["flags"]==2 and q["sha256_matches"]:
                recoveries.append(rec)
    named=[]
    q_by_name={}
    for q in s["sections"]: q_by_name.setdefault(q["name"],[]).append(q)
    for p in p_rows:
        for q in q_by_name.get(p["name"],[]):
            named.append({"name":p["name"],"sl3p_index":p["index"],"sl3s_index":q["index"],
                          "sl3p_size":p["size"],"sl3s_size":q["size"],
                          "sl3p_flags":p["flags"],"sl3s_flags":q["flags"],
                          "same_expected_hash":p["expected_sha256"]==q["stored_sha256"]})
    print("SL3S_CROSS_VARIANT1K_JSON_BEGIN")
    print(json.dumps({"tool":"SL3S_CROSS_VARIANT1K",
      "sl3p":{"identifier":base["internal_identifier"],"bytes":base["input_size"],"sha256":base["input_sha256"]},
      "sl3s":{"identifier":s["internal_identifier"],"bytes":s["input_size"],"sha256":s["input_sha256"],
              "crc_matches":s["crc32_region"]["matches"],"counts":s["counts"]},
      "content_matches":matches,"named_comparisons":named,
      "protected_to_unprotected_recoveries":recoveries,
      "temporary_binary_deleted":True,"binary_published":False},separators=(",",":")))
    print("SL3S_CROSS_VARIANT1K_JSON_END")
if __name__=="__main__":main()
