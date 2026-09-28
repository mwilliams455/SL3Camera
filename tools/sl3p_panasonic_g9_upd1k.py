#!/usr/bin/env python3
"""Inspect official Panasonic G9 2.7 update for UPD-family lineage.

Temporary vendor firmware is parsed read-only, summarized, then deleted by runner.
No proprietary bytes are published.
"""
from __future__ import annotations
import hashlib,io,json,zipfile,urllib.request,tempfile
from pathlib import Path
from sl3p_inspect import inspect
URL="https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/G9___V27.zip"
def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=180) as r:raw=r.read()
    result={"tool":"PANASONIC_G9_UPD1K","url":URL,"zip_bytes":len(raw),
            "zip_sha256":hashlib.sha256(raw).hexdigest(),"members":[]}
    if not zipfile.is_zipfile(io.BytesIO(raw)):
        result["error"]="response is not a zip"
    else:
        with zipfile.ZipFile(io.BytesIO(raw)) as z, tempfile.TemporaryDirectory() as td:
            for info in z.infolist():
                if info.is_dir():continue
                d=z.read(info)
                rec={"name":info.filename,"bytes":len(d),"sha256":hashlib.sha256(d).hexdigest()}
                if info.filename.lower().endswith(".bin"):
                    p=Path(td)/"firmware.bin";p.write_bytes(d)
                    try:
                        inv=inspect(p)
                        rec["upd"]={"identifier":inv["internal_identifier"],
                                    "crc_matches":inv["crc32_region"]["matches"],
                                    "entry_count":inv["directory"]["entry_count"],
                                    "counts":inv["counts"],
                                    "sections":[[s["index"],s["name"],s["size"],s["flags"],s["classification"]]
                                                for s in inv["sections"]]}
                    except Exception as e:
                        rec["parse_error"]=f"{type(e).__name__}: {e}"
                result["members"].append(rec)
    result["temporary_binaries_deleted"]=True;result["binary_published"]=False
    print("PANASONIC_G9_UPD1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("PANASONIC_G9_UPD1K_JSON_END")
if __name__=="__main__":main()
