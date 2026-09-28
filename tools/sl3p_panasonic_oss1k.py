#!/usr/bin/env python3
"""Scan Panasonic-published OSS U-Boot archives for camera-update lineage evidence.

Downloads only GPL source archives from Panasonic's OSS distribution service.
Does not download or inspect proprietary camera firmware.
"""
from __future__ import annotations
import hashlib, io, json, re, tarfile, urllib.request

SOURCES = {
    "GH7_u_boot": "https://ospo.panasonic.com/oss/source/dsc/DC-GH7/u-boot-v2019.07.tar.gz",
    "S5M2_u_boot": "https://ospo.panasonic.com/oss/source/dsc/DC-S5M2/u-boot.tar.gz",
}
TERMS = [
    b"UPD", b"postboot", b"eep_ow", b"lut_data", b"hm_d_nw",
    b"decrypt", b"encrypt", b"aes", b"sha256", b"secure boot",
    b"firmware update", b"fwupdate", b"update", b"upgrade",
    b"panasonic", b"milbeaut", b"socionext", b"fujitsu",
]
PATH_HINTS = ("board/", "configs/", "arch/arm/", "cmd/", "common/", "drivers/crypto", "drivers/mtd", "drivers/spi")

def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req, timeout=90) as r:
        data = r.read()
    if len(data) < 1024:
        raise RuntimeError(f"source unexpectedly small: {len(data)}")
    return data

def printable(data: bytes) -> str:
    return data.decode("utf-8", "ignore")

def scan(name: str, url: str) -> dict:
    raw = fetch(url)
    out = {
        "name": name, "url": url, "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "members": 0, "regular_files": 0,
        "path_matches": [], "content_matches": [],
        "defconfigs": [], "board_paths": [], "arch_paths": [],
    }
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tf:
        for m in tf:
            out["members"] += 1
            p = m.name
            lp = p.lower()
            if any(h in lp for h in PATH_HINTS):
                if "/configs/" in lp and p.endswith("defconfig") and len(out["defconfigs"]) < 200:
                    out["defconfigs"].append(p)
                if "/board/" in lp and len(out["board_paths"]) < 200:
                    out["board_paths"].append(p)
                if "/arch/arm/" in lp and len(out["arch_paths"]) < 200:
                    out["arch_paths"].append(p)
            if any(t.decode("ascii","ignore").lower() in lp for t in TERMS):
                if len(out["path_matches"]) < 300:
                    out["path_matches"].append(p)
            if not m.isfile():
                continue
            out["regular_files"] += 1
            if m.size > 2_000_000:
                continue
            interesting_path = any(h in lp for h in PATH_HINTS)
            if not interesting_path and not re.search(r"\.(c|h|S|dts|dtsi|cfg|config|mk|txt)$", p):
                continue
            f = tf.extractfile(m)
            if f is None:
                continue
            data = f.read()
            low = data.lower()
            hits = []
            for t in TERMS:
                if t.lower() in low:
                    hits.append(t.decode("ascii","ignore"))
            if hits and len(out["content_matches"]) < 500:
                snippets=[]
                text=printable(data)
                for term in hits[:8]:
                    for line in text.splitlines():
                        if term.lower() in line.lower():
                            snippets.append(line.strip()[:240])
                            break
                out["content_matches"].append({"path":p,"terms":hits,"snippets":snippets[:8]})
    # compact path views, deduped
    for key in ("defconfigs","board_paths","arch_paths","path_matches"):
        seen=[]; s=set()
        for x in out[key]:
            if x not in s:
                s.add(x); seen.append(x)
        out[key]=seen
    return out

def main():
    results=[]
    for name,url in SOURCES.items():
        try:
            results.append(scan(name,url))
        except Exception as e:
            results.append({"name":name,"url":url,"error":f"{type(e).__name__}: {e}"})
    print("PANASONIC_OSS1K_JSON_BEGIN")
    print(json.dumps({"tool":"PANASONIC_OSS1K","results":results}, separators=(",",":")))
    print("PANASONIC_OSS1K_JSON_END")

if __name__ == "__main__":
    main()
