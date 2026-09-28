#!/usr/bin/env python3
"""Hash Q3 published-source Linux build layouts against the protected program fingerprint."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path

PROGRAM_SIZE=46923776
PROGRAM_SHA256="dbc36fa7877e624982523cf1ffd0feafdabf4ad5a128369798e99ca95a86ef86"
DTB_OFFSET=0x1090000

def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()

def place(parts:list[tuple[int,bytes]],fill:int)->bytes:
    out=bytearray([fill])*PROGRAM_SIZE
    for off,data in parts:
        if off<0 or off+len(data)>PROGRAM_SIZE:raise ValueError("part outside program candidate")
        out[off:off+len(data)]=data
    return bytes(out)

def inspect(image:bytes,gzip_image:bytes,dtb:bytes)->dict:
    forms={}
    specs={
      "gzip_fill00":[(0,gzip_image)],
      "gzip_fillff":[(0,gzip_image)],
      "gzip_dtb_at_documented_fill00":[(0,gzip_image),(DTB_OFFSET,dtb)],
      "gzip_dtb_at_documented_fillff":[(0,gzip_image),(DTB_OFFSET,dtb)],
      "image_fill00":[(0,image)],
      "image_fillff":[(0,image)],
    }
    for name,parts in specs.items():
        fill=0xff if name.endswith("fillff") else 0
        try:
            b=place(parts,fill)
            h=sha(b)
            forms[name]={"sha256":h,"matches_program":h==PROGRAM_SHA256}
        except ValueError as e:
            forms[name]={"error":str(e),"matches_program":False}
    return {"program_bytes":PROGRAM_SIZE,"program_expected_sha256":PROGRAM_SHA256,
            "image_bytes":len(image),"image_sha256":sha(image),
            "gzip_bytes":len(gzip_image),"gzip_sha256":sha(gzip_image),
            "dtb_bytes":len(dtb),"dtb_sha256":sha(dtb),"dtb_offset":DTB_OFFSET,
            "forms":forms,"any_full_match":any(x["matches_program"] for x in forms.values())}

def main():
    ap=argparse.ArgumentParser();ap.add_argument("--image",type=Path,required=True);ap.add_argument("--gzip",type=Path,required=True);ap.add_argument("--dtb",type=Path,required=True)
    a=ap.parse_args()
    r=inspect(a.image.read_bytes(),a.gzip.read_bytes(),a.dtb.read_bytes())
    print("Q3_PROGRAM_BUILD_CANDIDATE1K_JSON_BEGIN");print(json.dumps(r,separators=(",",":")));print("Q3_PROGRAM_BUILD_CANDIDATE1K_JSON_END")
if __name__=="__main__":main()
