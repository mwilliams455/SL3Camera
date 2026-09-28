#!/usr/bin/env python3
"""Fetch official S5M2 firmware through Panasonic's agreement form and inspect UPD structure.

Read-only research: temporary ZIP/BIN bytes are hashed and discarded; no binary output.
"""
from __future__ import annotations
import hashlib, io, json, tempfile, urllib.parse, urllib.request, zipfile
from pathlib import Path
from sl3p_inspect import inspect

PAGE="https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/ff/dl/s5m2_dl.html"
ACTION="https://av.jpn.support.panasonic.com/support/cgi-bin/global_cs/dsc/download_s.cgi"
MODEL="S5m2_V37.zip"

def post_download():
    data=urllib.parse.urlencode({"MODEL":MODEL,"submit":"Accepted"}).encode()
    req=urllib.request.Request(ACTION,data=data,headers={
        "User-Agent":"Mozilla/5.0 SL3Camera-research/1K",
        "Referer":PAGE,
        "Content-Type":"application/x-www-form-urlencoded",
    })
    with urllib.request.urlopen(req,timeout=300) as r:
        raw=r.read()
        return raw,r.geturl(),r.status,r.headers.get("Content-Type"),r.headers.get("Content-Disposition")

def compact_inventory(inv):
    return {
      "identifier":inv["internal_identifier"],"crc_matches":inv["crc32_region"]["matches"],
      "entry_count":inv["directory"]["entry_count"],"counts":inv["counts"],
      "sections":[[s["index"],s["name"],s["size"],s["flags"],s["stored_sha256"],
                   s["payload_sha256_after_outer_transform"],s["classification"],
                   s["target_offset_unconfirmed"],s["unknown_16_bytes"]]
                  for s in inv["sections"]]
    }

def main():
    raw,final,status,ctype,cdisp=post_download()
    out={"tool":"PANASONIC_S5M2_UPD1K","page":PAGE,"action":ACTION,"model":MODEL,
         "status":status,"final_url":final,"content_type":ctype,"content_disposition":cdisp,
         "response_bytes":len(raw),"response_sha256":hashlib.sha256(raw).hexdigest()}
    if zipfile.is_zipfile(io.BytesIO(raw)):
        out["response_kind"]="zip"; members=[]
        with zipfile.ZipFile(io.BytesIO(raw)) as z,tempfile.TemporaryDirectory(prefix="s5m2upd-") as td:
            for info in z.infolist():
                if info.is_dir(): continue
                d=z.read(info)
                rec={"name":info.filename,"bytes":len(d),"sha256":hashlib.sha256(d).hexdigest()}
                if info.filename.lower().endswith(".bin"):
                    p=Path(td)/"firmware.bin";p.write_bytes(d)
                    try: rec["upd"]=compact_inventory(inspect(p))
                    except Exception as e: rec["parse_error"]=f"{type(e).__name__}: {e}"
                members.append(rec)
        out["members"]=members
    else:
        out["response_kind"]="not_zip"
        out["prefix_hex"]=raw[:64].hex()
        out["html_hint"]=raw[:4096].decode("utf-8","replace")
    out["temporary_binaries_deleted"]=True;out["binary_published"]=False
    print("PANASONIC_S5M2_UPD1K_JSON_BEGIN")
    print(json.dumps(out,separators=(",",":")))
    print("PANASONIC_S5M2_UPD1K_JSON_END")
if __name__=="__main__":main()
