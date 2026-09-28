#!/usr/bin/env python3
"""Static PE/crypto-constant probe of public PTool; never executes the binary."""
from __future__ import annotations
import collections,hashlib,io,json,math,re,struct,urllib.request,zipfile

URL="https://www.personal-view.com/gh1hack/ptool3d.zip"

AES_SBOX_PREFIX=bytes.fromhex(
"637c777bf26b6fc53001672bfed7ab76"
"ca82c97dfa5947f0adc4a272c0b7fd93"
"26363ff7cc34a5e5f171d8311504c723"
"c31896059a071280e2eb27b27509832c")
# Reconstruct canonical constants using words for endian searches.
WORDS={
 "TEA_DELTA":[0x9e3779b9],
 "SHA1_IV":[0x67452301,0xefcdab89,0x98badcfe,0x10325476,0xc3d2e1f0],
 "SHA256_IV":[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
 "MD5_IV":[0x67452301,0xefcdab89,0x98badcfe,0x10325476],
 "BLOWFISH_P4":[0x243f6a88,0x85a308d3,0x13198a2e,0x03707344],
 "RC5_PQ":[0xb7e15163,0x9e3779b9],
}
def fetch():
 req=urllib.request.Request(URL,headers={"User-Agent":"Mozilla/5.0 SL3Camera-research/1K"})
 with urllib.request.urlopen(req,timeout=180) as r:return r.read(),r.geturl(),r.status,r.headers.get("Content-Type")
def entropy(b):
 if not b:return 0.0
 c=collections.Counter(b);n=len(b)
 return -sum((v/n)*math.log2(v/n) for v in c.values())
def u16(b,o):return struct.unpack_from("<H",b,o)[0]
def u32(b,o):return struct.unpack_from("<I",b,o)[0]
def cstr(b,o,limit=512):
 e=b.find(b"\0",o,min(len(b),o+limit))
 if e<0:return None
 try:return b[o:e].decode("ascii")
 except:return None
def parse_pe(data):
 if data[:2]!=b"MZ":raise ValueError("not MZ")
 pe=u32(data,0x3c)
 if data[pe:pe+4]!=b"PE\0\0":raise ValueError("no PE signature")
 machine,nsects=struct.unpack_from("<HH",data,pe+4)
 opt_size=u16(data,pe+20);opt=pe+24;magic=u16(data,opt)
 if magic==0x10b:
  image_base=u32(data,opt+28);dd=opt+96;ptrsz=4
 elif magic==0x20b:
  image_base=struct.unpack_from("<Q",data,opt+24)[0];dd=opt+112;ptrsz=8
 else:raise ValueError(f"optional magic {magic:#x}")
 sec_off=opt+opt_size;sections=[]
 for i in range(nsects):
  o=sec_off+i*40;name=data[o:o+8].split(b"\0")[0].decode("ascii","replace")
  vs,va,rawsize,rawptr=struct.unpack_from("<IIII",data,o+8)
  chunk=data[rawptr:rawptr+rawsize]
  sections.append({"name":name,"virtual_address":va,"virtual_size":vs,"raw_offset":rawptr,"raw_size":rawsize,
                   "entropy":entropy(chunk),"sha256":hashlib.sha256(chunk).hexdigest()})
 def rvaoff(rva):
  for s in sections:
   span=max(s["virtual_size"],s["raw_size"])
   if s["virtual_address"]<=rva<s["virtual_address"]+span:
    return s["raw_offset"]+(rva-s["virtual_address"])
  return rva if rva<len(data) else None
 imports=[]
 imp_rva,imp_size=struct.unpack_from("<II",data,dd+8) # directory index 1
 io_=rvaoff(imp_rva) if imp_rva else None
 if io_ is not None:
  for k in range(512):
   o=io_+k*20
   if o+20>len(data):break
   oft,ts,fc,name_rva,ft=struct.unpack_from("<IIIII",data,o)
   if not any((oft,ts,fc,name_rva,ft)):break
   no=rvaoff(name_rva);dll=cstr(data,no) if no is not None else None
   names=[];thunk=oft or ft;to=rvaoff(thunk)
   if to is not None:
    for j in range(4096):
     p=to+j*ptrsz
     if p+ptrsz>len(data):break
     val=struct.unpack_from("<I" if ptrsz==4 else "<Q",data,p)[0]
     if not val:break
     ordinal_flag=0x80000000 if ptrsz==4 else 0x8000000000000000
     if val&ordinal_flag:names.append(f"ordinal:{val&0xffff}");continue
     hn=rvaoff(val); nm=cstr(data,hn+2) if hn is not None else None
     if nm:names.append(nm)
   imports.append({"dll":dll,"functions":names})
 return {"pe_offset":pe,"machine":machine,"sections":sections,"image_base":image_base,"imports":imports}
def findall(data,pat,cap=40):
 out=[];p=0
 while True:
  i=data.find(pat,p)
  if i<0:break
  out.append(i);p=i+1
  if len(out)>=cap:break
 return out
def constants(data):
 out={"AES_SBOX_PREFIX64":findall(data,AES_SBOX_PREFIX)}
 for name,words in WORDS.items():
  le=b"".join(struct.pack("<I",x) for x in words);be=b"".join(struct.pack(">I",x) for x in words)
  out[name]={"little":findall(data,le),"big":findall(data,be)}
 return out
def selected_strings(data):
 ss=[]
 for enc,pattern,decode in [
  ("ascii",rb"[ -~]{5,}",lambda x:x.decode("ascii","replace")),
  ("utf16le",rb"(?:(?:[ -~])\x00){5,}",lambda x:x[::2].decode("ascii","replace"))]:
  for m in re.finditer(pattern,data):
   s=decode(m.group())
   if any(t in s.lower() for t in ("upd","decrypt","encrypt","crypt","aes","sha","firmware","panasonic","gx1","gh2","gf3","tz10","version")) and len(s)<300:
    ss.append({"encoding":enc,"offset":m.start(),"text":s})
 return ss[:800]
def main():
 zraw,final,status,ctype=fetch()
 if not zipfile.is_zipfile(io.BytesIO(zraw)):raise RuntimeError("PTool response not ZIP")
 with zipfile.ZipFile(io.BytesIO(zraw)) as z:
  member=next(n for n in z.namelist() if n.lower().endswith(".exe"));exe=z.read(member)
 pe=parse_pe(exe)
 crypto_imports=[]
 for imp in pe["imports"]:
  fs=[f for f in imp["functions"] if any(t in f.lower() for t in ("crypt","bcrypt","hash","sha","aes"))]
  if fs:crypto_imports.append({"dll":imp["dll"],"functions":fs})
 out={"tool":"PTOOL_STATIC1K","source":{"url":URL,"final_url":final,"status":status,"content_type":ctype,
      "zip_bytes":len(zraw),"zip_sha256":hashlib.sha256(zraw).hexdigest(),
      "member":member,"exe_bytes":len(exe),"exe_sha256":hashlib.sha256(exe).hexdigest()},
      "pe":pe,"crypto_related_imports":crypto_imports,"crypto_constant_hits":constants(exe),
      "selected_strings":selected_strings(exe),"binary_executed":False,"binary_published":False}
 print("PTOOL_STATIC1K_JSON_BEGIN");print(json.dumps(out,separators=(",",":")));print("PTOOL_STATIC1K_JSON_END")
if __name__=="__main__":main()
