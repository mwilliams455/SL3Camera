#!/usr/bin/env python3
"""Build a protected-section lineage matrix across Leica Q3, SL3 and SL3-P.

Uses official public Q3/SL3/SL3-P 4.2.2 packages plus the committed exact
expected-content fingerprints from the user's SL3-P 4.2.1 baseline. No
protected bytes are emitted or retained.
"""
from __future__ import annotations
import collections,hashlib,json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect

URLS={
 "q3":"https://leica-camera.com/sites/default/files/Q3___411.lfu",
 "sl3":"https://leica-camera.com/sites/default/files/SL3__420.lfu",
 "sl3p422":"https://leica-camera.com/sites/default/files/SL3P_422.lfu",
}
BASE421=Path("evidence/SL3P_421_COMPARISON_BASELINE.json")

def fetch(url:str)->bytes:
    req=urllib.request.Request(url,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()

def key_named(row:dict)->tuple:
    return (str(row["name"]),int(row["size"]),str(row["expected"]))

def load_421(path:Path)->list[dict]:
    d=json.loads(path.read_text("utf-8")); cols=d["columns"]
    out=[]
    for raw in d["sections"]:
        x=dict(zip(cols,raw))
        out.append({"index":int(x["index"]),"name":x["name"],"size":int(x["size"]),
                    "flags":int(x["flags"]),"expected":x["expected_sha256"]})
    return out

def normalize(inv:dict)->list[dict]:
    return [{"index":int(s["index"]),"name":s["name"],"size":int(s["size"]),
             "flags":int(s["flags"]),"expected":s["stored_sha256"],
             "target":int(s["target_offset_unconfirmed"])}
            for s in inv["sections"]]

def multiset(rows:list[dict],named:bool=True)->collections.Counter:
    if named:return collections.Counter(key_named(x) for x in rows)
    return collections.Counter((int(x["size"]),str(x["expected"])) for x in rows)

def consume(counter:collections.Counter,key)->bool:
    if counter[key]>0:
        counter[key]-=1;return True
    return False

def classify(rows421,q3,sl3,p422):
    q3n=multiset(q3);s3n=multiset(sl3)
    q3h=multiset(q3,False);s3h=multiset(sl3,False)
    p422_by_index={x["index"]:x for x in p422}
    result=[]
    for x in rows421:
        nk=key_named(x); hk=(x["size"],x["expected"])
        q_named=consume(q3n,nk); s_named=consume(s3n,nk)
        q_hash=consume(q3h,hk); s_hash=consume(s3h,hk)
        y=p422_by_index.get(x["index"])
        unchanged422=bool(y and y["name"]==x["name"] and y["size"]==x["size"] and y["expected"]==x["expected"])
        if q_named and s_named: cls="shared_q3_sl3_sl3p"
        elif s_named: cls="shared_sl3_sl3p"
        elif q_named: cls="shared_q3_sl3p"
        else: cls="sl3p_no_same_name_match"
        result.append({
          **x,
          "target_422":None if not y else y["target"],
          "q3_same_name_content":q_named,"sl3_same_name_content":s_named,
          "q3_any_same_size_content":q_hash,"sl3_any_same_size_content":s_hash,
          "unchanged_421_to_422":unchanged422,
          "changed_421_to_422":not unchanged422,
          "lineage_class":cls,
        })
    return result

def main():
    baseline=load_421(BASE421)
    blobs={k:fetch(v) for k,v in URLS.items()}
    invs={}
    with tempfile.TemporaryDirectory(prefix="lineage1k-") as td:
        for k,data in blobs.items():
            p=Path(td)/(k+".lfu");p.write_bytes(data);invs[k]=inspect(p)
    rows=classify(baseline,normalize(invs["q3"]),normalize(invs["sl3"]),normalize(invs["sl3p422"]))
    prot=[x for x in rows if x["flags"]==3 and x["size"]]
    class_counts=collections.Counter(x["lineage_class"] for x in prot)
    changed=[x["name"] for x in rows if x["changed_421_to_422"]]
    priority_names={"program","compress_pr","postboot1_r","postboot2_r","postboot3_r","postboot4_r","postboot5_r",
                    "osdover","osddata","eep_adj","eep_fix","eep_exp_a","eep_exp_b","raw_kizu_c","raw_kizu_d",
                    "muf_header","lpc_data","lpc_code"}
    focused=[x for x in rows if x["name"] in priority_names]
    result={
      "tool":"LEICA_LINEAGE_MATRIX1K",
      "sources":{k:{"url":URLS[k],"bytes":len(blobs[k]),"sha256":hashlib.sha256(blobs[k]).hexdigest(),
                    "identifier":invs[k]["internal_identifier"],"sections":invs[k]["directory"]["entry_count"],
                    "crc_matches":invs[k]["crc32_region"]["matches"]} for k in URLS},
      "sl3p421_sha256":json.loads(BASE421.read_text("utf-8"))["input_sha256"],
      "protected_lineage_counts":dict(class_counts),
      "changed_421_to_422_names":changed,
      "focused_rows":focused,
      "all_rows":rows,
      "limits":[
        "Same-name/content means same name, size and expected-content SHA-256; it is not a functional proof.",
        "Any-content matches ignore names but still require equal size and expected-content SHA-256.",
        "No protected payload is decrypted or published by this tool.",
        "Different firmware versions and models can share or change content for reasons unrelated to photographic rendering."
      ],
      "temporary_binaries_deleted":True,"binary_published":False
    }
    print("LEICA_LINEAGE_MATRIX1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("LEICA_LINEAGE_MATRIX1K_JSON_END")
if __name__=="__main__":main()
