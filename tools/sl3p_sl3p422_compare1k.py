#!/usr/bin/env python3
"""Fetch official SL3-P 4.2.2 and compare its UPD inventory to committed 4.2.1 fingerprints."""
from __future__ import annotations
import hashlib,json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect

URL="https://leica-camera.com/sites/default/files/SL3P_422.lfu"

def load_baseline(path:Path)->dict:
    d=json.loads(path.read_text("utf-8"))
    cols=d["columns"]
    return {int(row[0]):dict(zip(cols,row)) for row in d["sections"]}

def compare(inv:dict, base:dict)->dict:
    rows=[]
    counts={"same_expected_same_stored":0,"same_expected_different_stored":0,"changed_expected":0,"missing_or_reindexed":0}
    for s in inv["sections"]:
        i=int(s["index"]); b=base.get(i)
        if not b or b["name"]!=s["name"]:
            cat="missing_or_reindexed"
        else:
            same_expected=(b["expected_sha256"]==s["stored_sha256"] and int(b["size"])==int(s["size"]) and int(b["flags"])==int(s["flags"]))
            same_stored=(b["stored_payload_sha256"]==s["payload_sha256_after_outer_transform"])
            if same_expected:
                cat="same_expected_same_stored" if same_stored else "same_expected_different_stored"
            else:
                cat="changed_expected"
        counts[cat]+=1
        rows.append({
          "index":i,"name":s["name"],"size_422":s["size"],"target_422":s["target_offset_unconfirmed"],"flags_422":s["flags"],
          "expected_sha256_422":s["stored_sha256"],"stored_payload_sha256_422":s["payload_sha256_after_outer_transform"],
          "metadata16_sha256_422":hashlib.sha256(bytes.fromhex(s["unknown_16_bytes"])).hexdigest(),
          "category":cat,
          "size_421":None if not b else b["size"],"expected_sha256_421":None if not b else b["expected_sha256"],
        })
    return {"counts":counts,"rows":rows}

def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r: data=r.read()
    h=hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix="sl3p422-") as td:
        p=Path(td)/"SL3P_422.lfu";p.write_bytes(data);inv=inspect(p)
    baseline=load_baseline(Path("evidence/SL3P_421_COMPARISON_BASELINE.json"))
    cmp=compare(inv,baseline)
    result={
      "tool":"SL3P_422_COMPARE1K","url":URL,"bytes":len(data),"sha256":h,
      "identifier":inv["internal_identifier"],"crc_matches":inv["crc32_region"]["matches"],
      "entry_count":inv["directory"]["entry_count"],"counts":inv["counts"],
      "comparison_counts":cmp["counts"],"rows":cmp["rows"],
      "temporary_binary_deleted":True,"binary_published":False
    }
    print("SL3P_422_COMPARE1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("SL3P_422_COMPARE1K_JSON_END")

if __name__=="__main__": main()
