#!/usr/bin/env python3
"""Compare Panasonic S5M2 with Leica Q3/SL3/SL3-P at expected-plaintext level."""
from __future__ import annotations
import hashlib,io,json,tempfile,urllib.request,zipfile
from pathlib import Path
from sl3p_upd_family1k import inspect_family

URLS={
 "q3":"https://leica-camera.com/sites/default/files/Q3___411.lfu",
 "sl3":"https://leica-camera.com/sites/default/files/SL3__420.lfu",
 "s5m2":"https://av.jpn.support.panasonic.com/support/share2/eww/com/dsc/ff/zip/S5m2_V37.zip",
}
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=300) as r:return r.read()
def load_public(name,u,td):
    raw=fetch(u)
    if name=="s5m2":
        zsha=hashlib.sha256(raw).hexdigest()
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            member=next(n for n in z.namelist() if n.lower().endswith(".bin"));data=z.read(member)
        p=Path(td)/"s5m2.bin";p.write_bytes(data)
        inv=inspect_family(p); src={"url":u,"zip_sha256":zsha,"member":member,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}
    else:
        p=Path(td)/(name+".lfu");p.write_bytes(raw);inv=inspect_family(p);src={"url":u,"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
    return inv,src
def groups(inv):
    out={}
    for s in inv["sections"]:
        if s["flags"]==3 and s["size"]:
            out.setdefault((s["size"],s["expected_sha256"]),[]).append(s)
    return out
def baseline(path):
    b=json.loads(path.read_text())
    cols=b["columns"]; rows=[]
    for vals in b["sections"]:
        d=dict(zip(cols,vals));d["expected_sha256"]=d.pop("expected_sha256");rows.append(d)
    return {"internal_identifier":b["internal_identifier"],"sections":rows}
def bgroups(b):
    out={}
    for s in b["sections"]:
        if s["flags"]==3 and s["size"]:out.setdefault((s["size"],s["expected_sha256"]),[]).append(s)
    return out
def compare(a,b,b_is_baseline=False):
    ga=groups(a);gb=bgroups(b) if b_is_baseline else groups(b);matches=[]
    for key in sorted(set(ga)&set(gb)):
        for x in ga[key]:
            for y in gb[key]:
                if b_is_baseline:
                    payload_equal=x["payload_sha256_after_outer_transform"]==y["stored_payload_sha256"]
                    meta_equal=hashlib.sha256(bytes.fromhex(x["unknown_16_bytes"])).hexdigest()==y["metadata16_sha256"]
                else:
                    payload_equal=x["payload_sha256_after_outer_transform"]==y["payload_sha256_after_outer_transform"]
                    meta_equal=x["unknown_16_bytes"]==y["unknown_16_bytes"]
                matches.append({"size":key[0],"expected_sha256":key[1],"a":[x["index"],x["name"],x.get("target_offset_unconfirmed")],
                  "b":[y["index"],y["name"],y.get("target_offset_unconfirmed")],"same_name":x["name"]==y["name"],
                  "protected_payload_equal":payload_equal,"metadata16_equal":meta_equal})
    unique={(m["size"],m["expected_sha256"]) for m in matches}
    return {"pair_matches":matches,"unique_expected_contents":len(unique),
      "unique_expected_bytes":sum(k[0] for k in unique),
      "same_name_pairs":sum(m["same_name"] for m in matches),
      "protected_payload_equal_pairs":sum(m["protected_payload_equal"] for m in matches),
      "metadata16_equal_pairs":sum(m["metadata16_equal"] for m in matches)}
def main():
    with tempfile.TemporaryDirectory(prefix="family1k-") as td:
        inv={};src={}
        for n,u in URLS.items():inv[n],src[n]=load_public(n,u,td)
    bp=baseline(Path("evidence/SL3P_421_COMPARISON_BASELINE.json"))
    result={"tool":"PANASONIC_LEICA_FAMILY1K","sources":src,
      "inventories":{n:{"identifier":v["internal_identifier"],"outer_transform":v["outer_transform"],
        "brand_marker_0x200_hex":v["brand_marker_0x200_hex"],"entry_count":v["directory"]["entry_count"],
        "flag_counts":v["counts"]["by_flags"]} for n,v in inv.items()},
      "comparisons":{
        "s5m2_q3":compare(inv["s5m2"],inv["q3"]),
        "s5m2_sl3":compare(inv["s5m2"],inv["sl3"]),
        "s5m2_sl3p":compare(inv["s5m2"],bp,True),
        "q3_sl3p":compare(inv["q3"],bp,True)},
      "temporary_binaries_deleted":True,"binary_published":False}
    print("PANASONIC_LEICA_FAMILY1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("PANASONIC_LEICA_FAMILY1K_JSON_END")
if __name__=="__main__":main()
