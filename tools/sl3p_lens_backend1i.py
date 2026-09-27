#!/usr/bin/env python3
"""Inspect two constructor-resolved lens backend methods; static read only."""
from __future__ import annotations
import json
import struct
from sl3p_lens_callsite1i import acquire_image, bl_target
from sl3p_lens_dispatch1i import cstring
from sl3p_sparse_code1h import literal


def inspect(image):
    import capstone as cs
    md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB|cs.CS_MODE_MCLASS)
    md.detail=True
    def window(start,stop):
        rows=[]
        while start<stop and len(rows)<160:
            raw=image.read(start,4) or image.read(start,2)
            ins=next(md.disasm(raw,start,count=1),None) if raw else None
            if ins is None:break
            row={'address':start,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
            hit=literal(image,start)
            if hit:row['literal']=hit
            rows.append(row);start+=ins.size
        return rows
    raw=image.read(0x3ecb4,20)
    expected=[0x11b93,0x11c43,0x11d41,0x11e39,0x11e4b]
    if raw is None or list(struct.unpack('<5I',raw))!=expected:
        raise ValueError('backend table differs from recorded identity')
    checks={0xb8a6:0x11b78,0xb8b4:0x1daf8,0x1e648:0x25bc0}
    for address,target in checks.items():
        if bl_target(image.read(address,4) or b'',address)!=target:
            raise ValueError('recorded constructor/dispatch call differs')
    if literal(image,0x11b86)['value']!=0x3ecb4 or cstring(image,0x41a30)!='Memory':
        raise ValueError('constructor or name identity differs')
    return {'backend_table_address':0x3ecb4,'backend_table_words':expected,
            'constructor_entry':0x11b78,
            'slot8_method':window(0x11d40,0x11e38),
            'slot12_method':window(0x11e38,0x11e4a),
            'selected_constructor_and_call_checks_pass':True,
            'limits':['Virtual targets are resolved for the measured constructor chain, not every possible runtime object.',
                      'Windows are bounded by neighboring table entries; embedded pools may still be data.',
                      'No firmware execution or camera-UPD semantics are asserted.']}


def main():
    image,proof=acquire_image()
    print('LENS_BACKEND1I_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_BACKEND1I','source_proof':proof,'analysis':inspect(image),'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_BACKEND1I_JSON_END')


if __name__=='__main__':main()
