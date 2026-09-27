#!/usr/bin/env python3
"""Bounded semantic investigation on the 1H packet-addressed lens image.

No execution/emulation of firmware. Emits limited disassembly, selected exact
terms and structural references. Reachability is explicitly entry-relative.
"""
from __future__ import annotations
from collections import deque
import json
import struct
from sl3p_lens_callsite1i import acquire_image, bl_target
from sl3p_sparse_code1h import literal


def ascii_fold(value: int) -> int:
    if not isinstance(value, int) or not 0 <= value <= 255:
        raise ValueError('expected byte value')
    return value + 32 if 65 <= value <= 90 else value


def inspect(image):
    import capstone as cs
    from capstone.arm import ARM_OP_IMM, ARM_REG_PC
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
    md.detail = True
    def one(a):
        raw = image.read(a,4) or image.read(a,2)
        return next(md.disasm(raw,a,count=1),None) if raw else None
    def row(ins):
        result = {'address':ins.address,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
        h=literal(image,ins.address)
        if h:result['literal']=h
        return result
    def window(start,count=24):
        rows=[]
        for _ in range(count):
            ins=one(start)
            if ins is None:break
            rows.append(row(ins));start+=ins.size
        return rows
    def cfg(start,low,high,limit=4096):
        queue=deque([start]);seen={};exits=[];calls=[]
        while queue and len(seen)<limit:
            a=queue.popleft()
            if a in seen:continue
            if a<low or a>=high:
                exits.append({'address':a,'reason':'out_of_window'});continue
            ins=one(a)
            if ins is None:
                exits.append({'address':a,'reason':'unmapped_or_invalid'});continue
            seen[a]=ins
            imm=[o.imm for o in ins.operands if o.type==ARM_OP_IMM]
            call=ins.group(cs.CS_GRP_CALL);jump=ins.group(cs.CS_GRP_JUMP)
            if call:
                calls.append({'from':a,'target':imm[-1]&0xffffffff if imm else None,'operands':ins.op_str})
                queue.append(a+ins.size)
            elif jump:
                if imm:queue.append(imm[-1]&0xfffffffe)
                else:exits.append({'address':a,'reason':'indirect_transfer'})
                if ins.mnemonic not in ('b','b.w','bx','bxj'):
                    queue.append(a+ins.size)
            else:
                try:pcwrite=ARM_REG_PC in ins.regs_access()[1]
                except cs.CsError:pcwrite=False
                if pcwrite or ins.group(cs.CS_GRP_RET):
                    exits.append({'address':a,'reason':'return_or_pcwrite'})
                elif ins.mnemonic.startswith(('udf','bkpt')):
                    exits.append({'address':a,'reason':'trap'})
                else:queue.append(a+ins.size)
        return seen,calls,exits, bool(queue)
    seen,calls,exits,limited=cfg(0x25bc0,0x25bc0,0x25c14)
    result={'comparator':{'instructions':[row(seen[a]) for a in sorted(seen)],'calls':calls,'exits':exits,'limit_reached':limited}}
    prologues=[]
    for a in range(0x1c000,0x1e646,2):
        ins=one(a)
        if ins is not None and ((ins.mnemonic.startswith('push') and 'lr' in ins.op_str) or (ins.mnemonic.startswith('stmdb') and ins.op_str.startswith('sp!') and 'lr' in ins.op_str)):
            prologues.append(a)
    result['nearest_prologue_candidates']=prologues[-8:]
    targets={0x25bc0}|set(prologues[-8:]);direct=[]
    for start,b in image.regions:
        for off in range(start%2,len(b)-3,2):
            a=start+off;t=bl_target(b[off:off+4],a)
            if t in targets:
                ins=one(a)
                if ins is not None and ins.mnemonic=='bl' and ins.operands[-1].type==ARM_OP_IMM and (ins.operands[-1].imm&0xffffffff)==t:
                    direct.append({'from':a,'to':t})
    result['calls_to_candidate_entries']=[d for d in direct if d['to']!=0x25bc0]
    result['comparator_candidate_calls']=sum(d['to']==0x25bc0 for d in direct)
    result['enclosing_candidates']=[]
    allowed=(b'fwupdate',b'help',b'version',b'info',b'status',b'reset',b'boot',b'read',b'write',b'dump',b'quit',b'test',b'exit')
    allowed_addresses={a:s.decode() for s in allowed for a in image.find(s+b'\0')}
    for start in prologues[-3:]:
        insmap,calls,ends,limited=cfg(start,start,0x1e68e)
        if 0x1e646 not in insmap:
            result['enclosing_candidates'].append({'entry':start,'contains_reference':False,'instructions':len(insmap),'exits':ends[:12]});continue
        literals=[];register=[]
        for a,ins in sorted(insmap.items()):
            h=literal(image,a)
            if h and h['value'] in allowed_addresses:
                literals.append({'instruction':a,'term':allowed_addresses[h['value']],'string_address':h['value']})
            if 'sb' in ins.op_str or '[r6, #0xc]' in ins.op_str:
                register.append(row(ins))
        pointers=image.find(struct.pack('<I',start|1))
        result['enclosing_candidates'].append({'entry':start,'contains_reference':True,'instructions':len(insmap),'calls':calls,'exits':ends,'limit_reached':limited,'entry_window':window(start,22),'selected_term_loads':literals,'argument_and_member_uses':register[:40],'entry_pointer_locations':pointers,'entry_pointer_neighbour_words':[{'address':a,'words':list(struct.unpack('<8I',image.read(a-12,32)))} for a in pointers[:8] if image.read(a-12,32)]})
    result['limits']=['Candidate prologues and scan-discovered calls require independent boundary evidence.','The CFG is bounded, assumes calls return, and does not prove runtime path feasibility.','No virtual call target or camera-UPD semantics inferred.']
    return result


def main():
    image,proof=acquire_image()
    print('LENS_SEMANTICS1I_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_SEMANTICS1I','source_proof':proof,'analysis':inspect(image),'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_SEMANTICS1I_JSON_END')


if __name__=='__main__':main()
