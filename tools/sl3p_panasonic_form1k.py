#!/usr/bin/env python3
"""Inspect Panasonic firmware download agreement forms without downloading firmware."""
from __future__ import annotations
import json, urllib.request, urllib.parse
from html.parser import HTMLParser

PAGES={
 "s5m2":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/ff/dl/s5m2_dl.html",
 "g9":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/g9_dl.html",
 "gh5":"https://av.jpn.support.panasonic.com/support/global/cs/dsc/download/fts/dl/gh5_dl.html",
}
class P(HTMLParser):
    def __init__(self):
        super().__init__(); self.forms=[]; self.cur=None
    def handle_starttag(self,tag,attrs):
        d=dict(attrs)
        if tag.lower()=="form":
            self.cur={"action":d.get("action"),"method":d.get("method","get"),"inputs":[]}
            self.forms.append(self.cur)
        elif tag.lower()=="input" and self.cur is not None:
            self.cur["inputs"].append({k:d.get(k) for k in ("type","name","value","checked") if k in d})
def fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
    with urllib.request.urlopen(req,timeout=90) as r:
        return r.read().decode("utf-8","replace"), r.geturl(), r.status
def main():
    out={}
    for name,url in PAGES.items():
        text,final,status=fetch(url); p=P(); p.feed(text)
        out[name]={"status":status,"final":final,"forms":p.forms}
    print("PANASONIC_FORM1K_JSON_BEGIN")
    print(json.dumps({"tool":"PANASONIC_FORM1K","pages":out},separators=(",",":")))
    print("PANASONIC_FORM1K_JSON_END")
if __name__=="__main__":main()
