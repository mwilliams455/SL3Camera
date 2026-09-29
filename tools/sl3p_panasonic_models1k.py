#!/usr/bin/env python3
"""Inventory internal Milbeaut submodel identifiers in current Panasonic OSS U-Boot archives.

Public GPL source only. No proprietary firmware is downloaded or published.
"""
from __future__ import annotations
import io, json, re, tarfile, urllib.error, urllib.request

MODELS = ["DC-S1M2ES","DC-S1RM2","DC-S9","DC-GH7","DC-S5M2","DC-S1M2NT"]
NAMES = ["u-boot.tar.gz","u-boot-v2019.07.tar.gz"]

def fetch(url: str) -> bytes:
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=120) as r:
        data=r.read()
    if len(data)<1024:
        raise RuntimeError(f"archive too small: {len(data)}")
    return data

def parse_text(text: str) -> dict:
    out={}
    pats={
      "text_base":r"CONFIG_SYS_TEXT_BASE\s*=\s*(0x[0-9A-Fa-f]+)",
      "kernel":r"#\s*KERNEL_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",
      "zkernel":r"#\s*ZKERNEL_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",
      "dtb":r"#\s*DTB_ADDRESS\s*:\s*(0x[0-9A-Fa-f]+)",
    }
    for k,p in pats.items():
        m=re.search(p,text)
        if m: out[k]=m.group(1)
    return out

def inspect(model: str) -> dict:
    errors=[]
    for name in NAMES:
        url=f"https://ospo.panasonic.com/oss/source/dsc/{model}/{name}"
        try:
            raw=fetch(url)
        except Exception as e:
            errors.append({"url":url,"error":f"{type(e).__name__}: {e}"})
            continue
        defconfigs=[]; dts=[]; selected={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as tf:
            for m in tf:
                if not m.isfile(): continue
                p=m.name
                q=p.split("/",1)[1] if "/" in p else p
                b=q.rsplit("/",1)[-1]
                if q.startswith("configs/") and b.startswith("pvc04v_") and b.endswith("_defconfig"):
                    f=tf.extractfile(m); data=f.read() if f else b""
                    text=data.decode("utf-8","replace")
                    defconfigs.append({"path":q,"bytes":len(data),"addresses":parse_text(text),
                                       "code":b[len("pvc04v_"):-len("_defconfig")]})
                if q.startswith("arch/arm/dts/") and "pvc04v-" in b and b.endswith((".dts",".dtsi")):
                    dts.append(q)
                if q=="GNUmakefile":
                    f=tf.extractfile(m); data=f.read() if f else b""
                    selected[q]=data.decode("utf-8","replace")[:3000]
        return {"model":model,"url":url,"bytes":len(raw),
                "defconfigs":defconfigs,"dts":dts[:80],"selected":selected,"errors":errors}
    return {"model":model,"errors":errors}

def main():
    rows=[inspect(m) for m in MODELS]
    codes=sorted({d["code"] for r in rows for d in r.get("defconfigs",[])})
    target=[c for c in codes if c in ("MC7231","MC7251") or c.startswith("MC72")]
    print("PANASONIC_MODELS1K_JSON_BEGIN")
    print(json.dumps({"tool":"PANASONIC_MODELS1K","rows":rows,
                      "all_submodel_codes":codes,"mc72_matches":target},separators=(",",":")))
    print("PANASONIC_MODELS1K_JSON_END")
if __name__=="__main__": main()
