#!/usr/bin/env python3
"""Compare SL3-P 4.2.1 expected-content fingerprints with official SL3-S 4.2.0."""
from __future__ import annotations
import collections,hashlib,json,tempfile,urllib.request
from pathlib import Path
from sl3p_inspect import inspect

URL="https://leica-camera.com/sites/default/files/SL3S_420.lfu"
BASE=Path("evidence/SL3P_421_COMPARISON_BASELINE.json")

def load_base():
    d=json.loads(BASE.read_text("utf-8")); cols=d["columns"]
    return [dict(zip(cols,r)) for r in d["sections"]]

def project(inv):
    return [{"index":s["index"],"name":s["name"],"size":s["size"],"flags":s["flags"],
             "expected_sha256":s["stored_sha256"],"target":s["target_offset_unconfirmed"]} for s in inv["sections"]]

def compare(base,other):
    c=collections.Counter((x["name"],int(x["size"]),x["expected_sha256"]) for x in other)
    rows=[]
    for x in base:
        k=(x["name"],int(x["size"]),x["expected_sha256"])
        match=c[k]>0
        if match:c[k]-=1
        rows.append({"index":int(x["index"]),"name":x["name"],"size":int(x["size"]),"flags":int(x["flags"]),
                     "same_name_content_sl3s":match})
    return rows

def main():
    req=urllib.request.Request(URL,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:data=r.read()
    with tempfile.TemporaryDirectory(prefix="sl3s-") as td:
        p=Path(td)/"sl3s.lfu";p.write_bytes(data);inv=inspect(p)
    rows=compare(load_base(),project(inv))
    prot=[x for x in rows if x["flags"]==3 and x["size"]]
    focused_names={"loader1","program","compress_pr","postboot1_r","postboot2_r","postboot3_r","postboot4_r","postboot5_r",
                   "eep_ow_a","eep_ow_b","eep_adj","eep_fix","eep_act_a","eep_act_b","eep_exp_a","eep_exp_b",
                   "osdover","osddata","tc_fpga","hm_c_ddr","hm_d_ddr","hr_c_prog","hr_d_prog","hr_c_ddr",
                   "lpc_data","lpc_code","raw_kizu_c","raw_kizu_d",
                   "hm_d_nw_1st","hm_d_nw_2nd","hm_d_nw_3rd","hm_d_nw_4th","hm_d_nw_5th","hm_d_nw_6th","hm_d_nw_7th","hm_d_nw_8th","hm_d_reid","welcom_fs"}
    result={"tool":"SL3P_SL3S_COMPARE1K",
      "source":{"url":URL,"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest(),
                "identifier":inv["internal_identifier"],"sections":inv["directory"]["entry_count"],
                "crc_matches":inv["crc32_region"]["matches"]},
      "protected_same_name_content_count":sum(x["same_name_content_sl3s"] for x in prot),
      "protected_same_name_content_names":[x["name"] for x in prot if x["same_name_content_sl3s"]],
      "focused_rows":[x for x in rows if x["name"] in focused_names],
      "all_rows":rows,
      "limits":["Same-name/content requires same name, size and expected-content SHA-256.","Cross-model equality does not establish function.","No protected bytes are emitted or decrypted."],
      "temporary_binary_deleted":True,"binary_published":False}
    print("SL3P_SL3S_COMPARE1K_JSON_BEGIN");print(json.dumps(result,separators=(",",":")));print("SL3P_SL3S_COMPARE1K_JSON_END")
if __name__=="__main__":main()
