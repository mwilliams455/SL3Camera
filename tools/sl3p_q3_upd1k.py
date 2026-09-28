#!/usr/bin/env python3
"""Parse Leica Q3 4.1.1 with the tested UPD inspector and emit compact fingerprints."""
from __future__ import annotations
import hashlib,json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect
URL="https://leica-camera.com/sites/default/files/Q3___411.lfu"
def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=180) as r:data=r.read()
    with tempfile.TemporaryDirectory(prefix="q3upd-") as td:
        p=Path(td)/"q3.lfu";p.write_bytes(data);inv=inspect(p)
    compact={
      "tool":"Q3_UPD1K","url":URL,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
      "identifier":inv["internal_identifier"],"crc_matches":inv["crc32_region"]["matches"],
      "entry_count":inv["directory"]["entry_count"],"counts":inv["counts"],
      "sections":[[s["index"],s["name"],s["size"],s["flags"],s["stored_sha256"],s["classification"]]
                  for s in inv["sections"]],
      "temporary_binary_deleted":True,"binary_published":False
    }
    print("Q3_UPD1K_JSON_BEGIN");print(json.dumps(compact,separators=(",",":")));print("Q3_UPD1K_JSON_END")
if __name__=="__main__":main()
