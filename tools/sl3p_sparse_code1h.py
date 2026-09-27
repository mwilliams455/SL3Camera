#!/usr/bin/env python3
"""Static analysis of the record-addressed LDAFR image. No firmware execution.

All instruction fetches respect mapped ranges. No synthesized hole bytes are
used for code or literal reads. String-based entry candidates remain distinct
from exception-seeded traversal.
"""
from __future__ import annotations
from bisect import bisect_right
from collections import Counter,deque
import hashlib
import importlib.metadata
import json
import struct


class SparseImage:
    def __init__(self, regions: list[tuple[int,bytes]]):
        self.regions=sorted(regions)
        self.starts=[a for a,_ in self.regions]
        if any(not b or a < 0 or a+len(b)>2**32 for a,b in self.regions):
            raise ValueError('invalid sparse region')
        if any(a+len(b)>c for (a,b),(c,_) in zip(self.regions,self.regions[1:])):
            raise ValueError('overlapping sparse regions')

    def read(self,address:int,size:int) -> bytes | None:
        if size<=0:return None
        i=bisect_right(self.starts,address)-1
        if i<0:return None
        a,b=self.regions[i]
        offset=address-a
        return b[offset:offset+size] if offset+size<=len(b) else None

    def find(self,needle:bytes) -> list[int]:
        if not needle: raise ValueError('empty pattern')
        result=[]
        for a,b in self.regions:
            cursor=0
            while True:
                at=b.find(needle,cursor)
                if at<0:break
                result.append(a+at)
                cursor=at+1
        return result


def literal(image:SparseImage,address:int):
    """Independent sparse Thumb LDR(literal) coordinate calculation."""
    raw=image.read(address,2)
    if address%2 or raw is None:return None
    h=int.from_bytes(raw,'little')
    pc=(address+4)&~3
    if h&0xf800==0x4800:
        reg,pool,width=(h>>8)&7,pc+(h&255)*4,2
    elif h&0xff7f==0xf85f:
        second=image.read(address+2,2)
        if second is None:return None
        tail=int.from_bytes(second,'little')
        reg,pool,width=tail>>12,pc+(1 if h&128 else -1)*(tail&4095),4
    else:return None
    value=image.read(pool,4)
    return {'register':reg,'pool_address':pool,'value':int.from_bytes(value,'little'),
            'width':width} if value is not None else None


def vector_tables(image:SparseImage):
    result=[]
    for base,body in image.regions:
        for offset in range(0,min(512,len(body)-63),4):
            words=struct.unpack_from('<16I',body,offset)
            if not 0x20000000<=words[0]<=0x20100000 or words[0]%4:continue
            meaningful=[words[i] for i in (1,2,3,4,5,6,11,12,14,15) if words[i]]
            if len(meaningful)<5 or not all(w&1 and image.read(w&~1,2) is not None for w in meaningful):continue
            if any(words[i] for i in (7,8,9,10,13)):continue
            result.append({'address':base+offset,'initial_sp':words[0],
                           'reset_address':words[1]&~1,'exception_seeds':sorted(set(w&~1 for w in meaningful))})
    return result



def adjacent_literal_target(image:SparseImage, previous:int|None, current:int, register:int):
    """Resolve only a directly preceding literal load into the branch register."""
    if previous is None:return None
    hit=literal(image,previous)
    if not hit or previous+hit['width']!=current or hit['register']!=register:
        return None
    target=hit['value']
    return (target&~1) if target&1 and image.read(target&~1,2) is not None else None

def analyze(image:SparseImage,max_instructions:int=60000):
    import capstone as cs
    from capstone.arm import ARM_OP_IMM,ARM_OP_REG,ARM_REG_PC
    md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB|cs.CS_MODE_MCLASS)
    md.detail=True
    def one(address):
        raw=image.read(address,4) or image.read(address,2)
        return next(md.disasm(raw,address,count=1),None) if raw else None
    def display(ins):
        return {'address':ins.address,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
    tables=vector_tables(image)
    seeds=sorted({a for t in tables for a in t['exception_seeds']})
    queue=deque(seeds)
    seen={}
    edges=[]
    stops=Counter()
    resolved_indirect=[]
    while queue and len(seen)<max_instructions:
        address=queue.popleft()
        previous=None
        for _ in range(8192):
            if address in seen:break
            ins=one(address)
            if ins is None:
                stops['unmapped_or_invalid']+=1;break
            seen[address]=ins.size
            jump,call=ins.group(cs.CS_GRP_JUMP),ins.group(cs.CS_GRP_CALL)
            immediate=[op.imm for op in ins.operands if op.type==ARM_OP_IMM]
            if (jump or call) and immediate:
                target=immediate[-1]&~1
                mapped=image.read(target,2) is not None
                edges.append((address,target,call,mapped))
                if mapped:queue.append(target)
                if not call and ins.mnemonic in ('b','b.w'):break
            elif jump or call:
                target=None
                if ins.operands and ins.operands[0].type==ARM_OP_REG:
                    name=ins.reg_name(ins.operands[0].reg)
                    if name.startswith('r') and name[1:].isdigit():
                        target=adjacent_literal_target(image,previous,address,int(name[1:]))
                if target is not None:
                    queue.append(target)
                    resolved_indirect.append({'from':address,'target':target,'literal_load':previous,'call':call})
                else:stops['unresolved_indirect_control_flow']+=1
                if not call:break
            else:
                try:pcwrite=ARM_REG_PC in ins.regs_access()[1]
                except cs.CsError:pcwrite=False
                if pcwrite or ins.group(cs.CS_GRP_RET):
                    hit=literal(image,address)
                    if hit and hit['register']==15 and hit['value']&1:
                        target=hit['value']&~1
                        if image.read(target,2) is not None: queue.append(target)
                    stops['return_or_pc_write']+=1;break
            if ins.mnemonic in ('udf','udf.w','bkpt'):
                stops['trap']+=1;break
            previous=address
            address+=ins.size
            if len(seen)>=max_instructions:break
        else:stops['block_limit']+=1
    reset_samples=[]
    for t in tables:
        start=t['reset_address']
        sample=[]
        for _ in range(12):
            ins=one(start)
            if ins is None:break
            row=display(ins)
            hit=literal(image,start)
            if hit:row['literal_value']=hit['value']
            sample.append(row);start+=ins.size
            if ins.group(cs.CS_GRP_JUMP) and not ins.group(cs.CS_GRP_CALL):break
        reset_samples.append({'vector_address':t['address'],'instructions':sample})
    refs=[]
    for string_address in image.find(b'fwupdate\0'):
        pointers=image.find(struct.pack('<I',string_address))
        loads=[]
        for a,b in image.regions:
            for address in range(a+(a%2),a+len(b)-1,2):
                hit=literal(image,address)
                if not hit or hit['pool_address'] not in pointers:continue
                ins=one(address)
                if ins is None or not ins.mnemonic.startswith('ldr'):continue
                sample=[];cursor=address
                for _ in range(10):
                    step=one(cursor)
                    if step is None:break
                    sample.append(display(step));cursor+=step.size
                loads.append({'instruction_address':address,**hit,
                              'exception_seeded':address in seen,'following_instructions':sample})
        refs.append({'string_address':string_address,'pointer_addresses':pointers,'literal_loads':loads})
    return {'capstone_distribution':importlib.metadata.version('capstone'),
            'capstone_module_version':cs.__version__,'capstone_core_version':list(cs.cs_version()),
            'vector_tables':tables,'seed_count':len(seeds),'instruction_count':len(seen),
            'instruction_limit_reached':len(seen)>=max_instructions,
            'direct_edges':len(edges),'mapped_direct_edges':sum(e[3] for e in edges),
            'stop_counts':dict(stops),'resolved_adjacent_literal_branches':resolved_indirect[:20],'reset_samples':reset_samples,'fwupdate_references':refs,
            'limits':['Partial static traversal; indirect branches and tables unresolved.',
                      'Linear literal candidates outside seeded traversal are not proven reachable.',
                      'No camera-UPD consumer semantics inferred.']}


def main():
    from sl3p_loader_source_probe import acquire
    from sl3p_lens_plaintext1f import URL,SOURCE_BYTES,reconstruct
    from sl3p_lens_records1g import verify_lens
    from sl3p_lens_inner1h import TARGET_SHA
    from sl3p_ldaf1h import verify_packets
    source=acquire(URL,SOURCE_BYTES)
    plain,proof=reconstruct(source);del plain
    target=next(p for p in verify_lens(source)['payloads'] if p['sha256']==TARGET_SHA)
    content=source[target['offset']:target['offset']+target['size']]
    regions,framing=verify_packets(content)
    if framing['trailer_hex']!='53544f5000':raise ValueError('unrecognized target STOP trailer')
    report={'tool':'SPARSE_CODE1H','source_proof':proof,'target_sha256':hashlib.sha256(content).hexdigest(),
            'framing':framing,'analysis':analyze(SparseImage(regions)),
            'firmware_executed':False,'provisional_flat_mapping_superseded':True}
    print('SPARSE_CODE1H_JSON_BEGIN')
    print(json.dumps(report,separators=(',',':')))
    print('SPARSE_CODE1H_JSON_END')

if __name__=='__main__':main()
