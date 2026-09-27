#!/usr/bin/env python3
"""Exact bounded 512-byte default-record hypothesis, not general decryption."""
import argparse,hashlib,json
from pathlib import Path
from sl3p_inspect import inspect
p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
r=inspect(a.firmware)['sections'][19]
if r['size']!=512:raise SystemExit('Expected 512-byte section19')
target=bytes.fromhex(r['stored_sha256']);n=512;count=0;hits=[]
for fill in range(256):
 b=bytes([fill])*n;count+=1
 if hashlib.sha256(b).digest()==target:hits.append({'fill':fill})
for fill in [0,255]:
 b=bytearray([fill])*n
 for off in range(n):
  for value in range(256):
   if value==fill:continue
   b[off]=value;count+=1
   if hashlib.sha256(b).digest()==target:hits.append({'fill':fill,'offset':off,'value':value})
  b[off]=fill
r={'target_section':19,'target_sha256':target.hex(),'tested':count,'scope':'256 constant fills plus every single-byte perturbation of all-00 and all-FF, 512 bytes only','hits':hits}
a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
