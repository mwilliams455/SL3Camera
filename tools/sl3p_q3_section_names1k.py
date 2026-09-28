#!/usr/bin/env python3
"""Search Leica Q3 OSS source for exact names used by the camera UPD directory."""
from __future__ import annotations
import io,json,re,tarfile,urllib.request,zipfile
URL="https://leica-camera.com/sites/default/files/pm-19562-OSS_codes.zip"
TERMS=[
"loader1","compress_pr","postboot1_r","postboot2_r","postboot3_r","postboot4_r","postboot5_r",
"eep_ow_a","eep_ow_b","eep_adj","eep_fix","eep_act_a","eep_exp_a","history","lens_hist",
"osdover","osddata","wifi_info","menu_save","kizu_data","vkizu_data","usbcharge",
"hm_c_prog","hm_d_prog","hm_c_ddr","hm_d_ddr","hm_d_nw","hm_d_nw_sng",
"hr_c_prog","hr_d_prog","hr_c_ddr","pzm_data","lns_micon","lns_micon_e",
"lut_data","lut2_data","dsp_kizu_c","dsp_kizu_d","bt_info","lpc_data","lpc_code",
"raw_kizu_c","raw_kizu_d","ext_ver","hm_d_nw_1st","hm_d_reid","welcom_fs","mbr_dummy_d"
]
ARCHIVES=("u-boot.tar.gz","linux-4.19.124.tar.gz","FreeRTOS-202212.00.tar.bz2","mtd-utils-2.0.1+AUTOINC+9c6173559f.tar.bz2")
def fetch(u):
    req=urllib.request.Request(u,headers={"User-Agent":"SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=240) as r:return r.read()
def scan_tar(label,raw):
    matches=[]
    needles=[(t,t.encode()) for t in TERMS]
    with tarfile.open(fileobj=io.BytesIO(raw),mode="r:*") as tf:
        for m in tf:
            if not m.isfile() or m.size>2_000_000:continue
            lp=m.name.lower()
            if not re.search(r"\.(c|h|s|dts|dtsi|cfg|config|mk|txt|md|sh|py|in)$",lp):continue
            f=tf.extractfile(m)
            if not f:continue
            data=f.read()
            low=data.lower()
            hits=[t for t,b in needles if b.lower() in low]
            if hits:
                text=data.decode("utf-8","ignore")
                snippets=[]
                for t in hits:
                    for line in text.splitlines():
                        if t.lower() in line.lower():
                            snippets.append({"term":t,"line":line.strip()[:280]});break
                matches.append({"path":m.name,"hits":hits,"snippets":snippets})
    return {"archive":label,"matches":matches}
def main():
    outer=fetch(URL)
    reports=[]
    with zipfile.ZipFile(io.BytesIO(outer)) as z:
        for suffix in ARCHIVES:
            names=[n for n in z.namelist() if n.endswith(suffix)]
            if len(names)!=1:
                reports.append({"archive":suffix,"error":f"found {len(names)} candidates"});continue
            reports.append(scan_tar(names[0],z.read(names[0])))
    print("Q3_SECTION_NAMES1K_JSON_BEGIN")
    print(json.dumps({"tool":"Q3_SECTION_NAMES1K","reports":reports},separators=(",",":")))
    print("Q3_SECTION_NAMES1K_JSON_END")
if __name__=="__main__":main()
