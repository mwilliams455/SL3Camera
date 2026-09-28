#!/usr/bin/env python3
"""Bounded constructor/table probe. Firmware is read, never executed."""
from __future__ import annotations
import json, struct
from sl3p_lens_callsite1i import acquire_image, bl_target
from sl3p_lens_interfaces1j import window


def inspect(image):
    checks={0xadaa:0xda04,0xb1ac:0x10870}
    for address,target in checks.items():
        if bl_target(image.read(address,4) or b'',address)!=target:
            raise ValueError(f'constructor call changed at {address:#x}')
    constructors=[]
    for start,stop,slots in [(0xda04,0xda70,[12,16]),(0x10870,0x108a0,[8])]:
        rows=window(image,start,stop,48)
        tables=[]
        for r in rows:
            hit=r.get('literal')
            if not hit:continue
            table=hit['value'];data=image.read(table,24)
            if data is None:continue
            words=list(struct.unpack('<6I',data))
            if not all(words[s//4]&1 and image.read(words[s//4]&~1,4) is not None for s in slots):continue
            methods=[]
            for slot in slots:
                addr=words[slot//4]&~1
                following=[v&~1 for v in words if v&1 and addr<v&~1<addr+512]
                stop_method=min(following) if following else addr+160
                methods.append({'slot':slot,'entry':addr,'window':window(image,addr,stop_method,100)})
            tables.append({'literal_load':r['address'],'table':table,'words':words,'methods':methods,'candidate_only':True})
        constructors.append({'entry':start,'window':rows,'candidate_tables':tables})
    return {'constructors':constructors,'checked_initialization_calls':checks,
            'initialization_window':window(image,0xb170,0xb1b0,28),
            'limits':['Table candidates require constructor-store and argument tracking.',
                      'Bounded disassembly may include pools; no runtime identity or hardware action established.']}


def main():
    image,proof=acquire_image()
    print('LENS_STORAGE1J_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_STORAGE1J','source_proof':proof,'analysis':inspect(image),
                      'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_STORAGE1J_JSON_END')

if __name__=='__main__':main()
