#!/usr/bin/env python3
"""Compare Leica Q3 OSS U-Boot/Linux source with Panasonic S1RM2 OSS source.

Only published open-source archives are used. Reports path/content identity
counts and model/platform-specific differences, not proprietary firmware.
"""
from __future__ import annotations
import hashlib,io,json,tarfile,urllib.request,zipfile
from pathlib import PurePosixPath

Q3="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
S1R_UBOOT="https://ospo.panasonic.com/oss/source/dsc/DC-S9/u-boot-v2019.07.tar.gz"
S1R_LINUX="https://ospo.panasonic.com/oss/source/dsc/DC-S9/linux-4.19.124.tar.gz"
MAX_REPORT_DIFFS=300

def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=300) as r:return r.read()

def tar_map(blob:bytes)->dict[str,str]:
    out={}
    with tarfile.open(fileobj=io.BytesIO(blob),mode="r:*") as tf:
        for m in tf:
            if not m.isfile():continue
            f=tf.extractfile(m)
            if not f:continue
            data=f.read()
            parts=PurePosixPath(m.name).parts
            # Normalize away top-level source directory.
            rel="/".join(parts[1:]) if len(parts)>1 else parts[0]
            out[rel]=hashlib.sha256(data).hexdigest()
    return out

def compare(a,b):
    ka=set(a);kb=set(b);common=ka&kb
    same=[p for p in common if a[p]==b[p]]
    changed=[p for p in common if a[p]!=b[p]]
    return {"a_files":len(a),"b_files":len(b),"shared_paths":len(common),
            "identical_shared":len(same),"modified_shared":len(changed),
            "a_only":len(ka-kb),"b_only":len(kb-ka),
            "modified_paths":changed[:MAX_REPORT_DIFFS],
            "a_only_paths":sorted(ka-kb)[:MAX_REPORT_DIFFS],
            "b_only_paths":sorted(kb-ka)[:MAX_REPORT_DIFFS]}

def q3_parts(blob):
    with zipfile.ZipFile(io.BytesIO(blob)) as z:
        un=[n for n in z.namelist() if n.endswith("u-boot.tar.gz")]
        ln=[n for n in z.namelist() if n.endswith("linux-4.19.124.tar.gz")]
        if len(un)!=1 or len(ln)!=1:raise ValueError("unexpected Q3 OSS inventory")
        return z.read(un[0]),z.read(ln[0])

def main():
    q3=fetch(Q3);q3u,q3l=q3_parts(q3)
    s1u=fetch(S1R_UBOOT);s1l=fetch(S1R_LINUX)
    result={"tool":"Q3_S1RM2_OSS_COMPARE1K",
      "sources":{
        "q3_outer":{"url":Q3,"bytes":len(q3),"sha256":hashlib.sha256(q3).hexdigest()},
        "q3_uboot":{"bytes":len(q3u),"sha256":hashlib.sha256(q3u).hexdigest()},
        "q3_linux":{"bytes":len(q3l),"sha256":hashlib.sha256(q3l).hexdigest()},
        "s1rm2_uboot":{"url":S1R_UBOOT,"bytes":len(s1u),"sha256":hashlib.sha256(s1u).hexdigest()},
        "s1rm2_linux":{"url":S1R_LINUX,"bytes":len(s1l),"sha256":hashlib.sha256(s1l).hexdigest()}},
      "uboot":compare(tar_map(q3u),tar_map(s1u)),
      "linux":compare(tar_map(q3l),tar_map(s1l)),
      "limits":["Published OSS source comparison only; proprietary camera firmware is not accessed.",
                "Equal source files do not prove equal build options or runtime behavior.",
                f"Path detail lists are capped at {MAX_REPORT_DIFFS} entries."],
      "binary_published":False}
    print("Q3_S1RM2_OSS_COMPARE1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("Q3_S1RM2_OSS_COMPARE1K_JSON_END")
if __name__=="__main__":main()
