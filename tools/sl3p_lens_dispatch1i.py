#!/usr/bin/env python3
"""Targeted follow-up to the measured command table and ASCII comparator.

Only mapped bytes, bounded instruction windows and explicitly selected name
locations are inspected. Does not run or modify firmware or upload binaries.
"""
from __future__ import annotations
import json
import struct
from sl3p_lens_callsite1i import acquire_image, bl_target
from sl3p_sparse_code1h import literal


def cstring(image,address:int,limit:int=64) -> str | None:
    if not 1<=limit<=128:raise ValueError('name limit outside 1..128')
    out=bytearray()
    for i in range(limit):
        b=image.read(address+i,1)
        if b is None:return None
        if b==b'\0':return out.decode('ascii')
        if not 32<=b[0]<127:return None
        out+=b
    return None


def inspect(image):
    import capstone as cs
    md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB|cs.CS_MODE_MCLASS)
    md.detail=True
    def one(a):
        raw=image.read(a,4) or image.read(a,2)
        return next(md.disasm(raw,a,count=1),None) if raw else None
    def window(a,count=24,end=None):
        rows=[]
        for _ in range(count):
            if end is not None and a>=end:break
            ins=one(a)
            if ins is None:break
            r={'address':a,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
            h=literal(image,a)
            if h:r['literal']=h
            rows.append(r);a+=ins.size
        return rows
    targets={0x40130,0x40128,0x41a30,0x1db19}
    refs=[]
    for a,b in image.regions:
        for address in range(a+a%2,a+len(b)-3,2):
            h=literal(image,address)
            if h and h['value'] in targets:
                ins=one(address)
                if ins is not None and ins.mnemonic.startswith('ldr'):
                    refs.append({'instruction':address,**h,'candidate_only':True})
    names=[{'address':a,'name':cstring(image,a)} for a in (0x41a30,0x41458,0x1de30,0x1de34)]
    prologue=[]
    for a in range(0x1db18-256,0x1db18,2):
        ins=one(a)
        if ins is not None and ins.mnemonic.startswith('push') and 'lr' in ins.op_str:
            prologue.append(a)
    return {'ascii_helper':window(0x2e830,12,0x2e83c),
            'tokenizer':window(0x25b74,40,0x25bba),
            'dispatch_start':window(0x1db18,42),
            'fwupdate_branch':window(0x1e63e,40,0x1e68e),
            'name_method':window(0x1e68e,2),
            'selected_names':names,
            'descriptor_references':refs,
            'descriptor_reference_windows':[{'reference':r['instruction'],'instructions':window(r['instruction']-8,18)} for r in refs[:6]],
            'preceding_prologues':prologue,
            'memory_constructor':window(0x1daf8,16,0x1db18),
            'constructor_caller_context':window(0xb878,52),
            'limits':['Descriptor references are static candidates, not proof of runtime object identity.',
                      'Selected name method and comparator do not establish an update transport.']}


def main():
    image,proof=acquire_image()
    print('LENS_DISPATCH1I_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_DISPATCH1I','source_proof':proof,'analysis':inspect(image),'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_DISPATCH1I_JSON_END')


if __name__=='__main__':main()
