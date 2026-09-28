#!/usr/bin/env python3
"""Discover official Panasonic camera-firmware download URLs from vendor pages."""
from __future__ import annotations
import html,json,re,urllib.parse,urllib.request
PAGES={
 "g9":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/g9_dl.html",
 "gh5":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/gh5_dl.html",
 "s5m2":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/ff/dl/s5m2.html",
}
def get(u):
    req=urllib.request.Request(u,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=60) as r:return r.read().decode("utf-8","replace"),r.geturl()
def main():
    out={}
    for name,url in PAGES.items():
        text,final=get(url)
        values=set()
        for pat in (r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''',r'''["']([^"']+\.(?:zip|bin|exe)(?:\?[^"']*)?)["']'''):
            for x in re.findall(pat,text,re.I):
                x=html.unescape(x)
                if any(k in x.lower() for k in ("zip","bin","download","iframe","dl")):
                    values.add(urllib.parse.urljoin(final,x))
        lines=[]
        for line in text.splitlines():
            if any(k in line.lower() for k in (".zip",".bin","download","iframe","agree","license")):
                lines.append(re.sub(r"\s+"," ",line.strip())[:400])
        out[name]={"page":url,"final":final,"links":sorted(values),"selected_lines":lines[:120]}
    print("PANASONIC_DL_DISCOVERY1K_JSON_BEGIN")
    print(json.dumps({"tool":"PANASONIC_DL_DISCOVERY1K","pages":out},separators=(",",":")))
    print("PANASONIC_DL_DISCOVERY1K_JSON_END")
if __name__=="__main__":main()
