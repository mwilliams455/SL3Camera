#!/usr/bin/env python3
"""Read-only follow-up for lens source/destination interface constructors.

No firmware execution, device access, binary output or automatic key search.
Static windows are candidates until data-flow and table identities agree.
"""
from __future__ import annotations
import json
from sl3p_lens_callsite1i import acquire_image
from sl3p_sparse_code1h import literal


def scan_literals(image, targets: set[int], lower: int, upper: int):
    if not 0 <= lower < upper <= 0x100000000 or upper-lower > 0x100000:
        raise ValueError('invalid bounded scan interval')
    hits=[]
    for start, body in image.regions:
        lo=max(start,lower); hi=min(start+len(body),upper)
        lo += lo % 2
        for address in range(lo,hi-1,2):
            hit=literal(image,address)
            if hit and hit['value'] in targets:
                hits.append({'instruction':address,**hit,'candidate_only':True})
    return hits


def window(image, start: int, stop: int, limit: int=100):
    if not 0 <= start < stop <= 0x100000000 or not 1 <= limit <= 512:
        raise ValueError('invalid bounded window')
    import capstone as cs
    md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB|cs.CS_MODE_MCLASS)
    rows=[]
    while start<stop and len(rows)<limit:
        raw=image.read(start,min(4,stop-start))
        if raw is None:raw=image.read(start,min(2,stop-start))
        ins=next(md.disasm(raw,start,count=1),None) if raw else None
        if ins is None or start+ins.size>stop:break
        row={'address':start,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
        hit=literal(image,start)
        if hit:row['literal']=hit
        rows.append(row);start+=ins.size
    return rows


def inspect(image):
    targets={0x2000ada0,0x2000ac9c}
    refs=scan_literals(image,targets,0x8000,0x421c9)
    return {'object_operand_references':refs,
            'constructor_candidate_windows':[{'reference':r,'window':window(image,max(0x8000,r['instruction']-24),r['instruction']+40,28)} for r in refs[:12]],
            'reference_output_capped':len(refs)>12,
            'limits':['Literal scans do not prove instruction alignment or reachability.',
                      'Constructor, storage and hardware identities are not assigned by object address alone.']}


def main():
    image,proof=acquire_image()
    print('LENS_INTERFACES1J_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_INTERFACES1J','source_proof':proof,'analysis':inspect(image),
                      'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_INTERFACES1J_JSON_END')

if __name__=='__main__':main()
