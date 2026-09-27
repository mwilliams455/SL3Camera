#!/usr/bin/env python3
"""Static Thumb references in the pinned lens component; never executes firmware.

Capstone is needed only for the explicitly invoked real-source code analysis.
Pure address/literal helpers are independently synthetic-testable.
"""
from __future__ import annotations
from collections import Counter, deque
import hashlib
import json
import struct
from sl3p_lens_inner1h import TARGET_SHA, vector_candidates


def file_offset(address: int, base: int, start: int, length: int, width: int = 1):
    off = start + address - base
    return off if width > 0 and start <= off and off + width <= length else None


def literal_load(data: bytes, off: int, base: int, start: int):
    """Decode only Thumb LDR(literal) T1/T2. Return register, pool offset, width."""
    if off < start or off+2 > len(data) or (off-start) % 2:
        return None
    h = struct.unpack_from('<H', data, off)[0]
    pc = (base + off - start + 4) & ~3
    if h & 0xf800 == 0x4800:
        addr, reg, size = pc + (h & 255)*4, (h >> 8) & 7, 2
    elif h & 0xff7f == 0xf85f and off+4 <= len(data):
        tail = struct.unpack_from('<H', data, off+2)[0]
        addr = pc + (1 if h & 0x80 else -1)*(tail & 0xfff)
        reg, size = tail >> 12, 4
    else:
        return None
    pool = file_offset(addr,base,start,len(data),4)
    return (reg,pool,size) if pool is not None else None


def string_references(data: bytes, base: int, start: int, needle: bytes = b'fwupdate\0'):
    at = data.find(needle,start)
    if at < 0:
        return {'string_offset':None,'pointer_offsets':[],'literal_loads':[]}
    address = base+at-start
    encoded = struct.pack('<I',address)
    ptrs=[]
    pos=start
    while True:
        pos=data.find(encoded,pos)
        if pos<0: break
        ptrs.append(pos)
        pos+=1
    refs=[]
    for off in range(start,len(data)-1,2):
        hit=literal_load(data,off,base,start)
        if hit and hit[1] in ptrs:
            refs.append({'instruction_offset':off,'instruction_address':base+off-start,
                         'destination_register':hit[0],'pointer_offset':hit[1],'instruction_bytes':hit[2]})
    return {'string_offset':at,'string_address':address,'pointer_offsets':ptrs,'literal_loads':refs}


def wrapper_candidates(data: bytes):
    """At most two initial ten-byte LDAF records: fields have no assigned role."""
    result=[]
    for off in (0,10):
        if data[off:off+4] == b'LDAF' and off+10 <= len(data):
            result.append({'offset':off,'tag_byte':data[off+4],
                           'byte_5':data[off+5],
                           'u32le_at_5':int.from_bytes(data[off+5:off+9],'little'),
                           'u32le_at_6':int.from_bytes(data[off+6:off+10],'little'),
                           'byte_9':data[off+9]})
    return result


def code_walk(data: bytes, vector: dict, max_instructions: int = 60000) -> dict:
    import capstone as cs
    from capstone.arm import ARM_OP_IMM, ARM_OP_REG, ARM_REG_PC
    base,start=vector['image_base_hypothesis'],vector['vector_offset']
    md=cs.Cs(cs.CS_ARCH_ARM,cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
    md.detail=True
    vectors=struct.unpack_from('<16I',data,start)
    seeds=sorted(set(v & ~1 for v in vectors[1:] if v & 1 and file_offset(v & ~1,base,start,len(data)) is not None))
    todo=deque(seeds)
    seen={}
    edges=[]
    stops=Counter()
    reset=vector['reset_address'] & ~1
    reset_sample=[]
    while todo and len(seen)<max_instructions:
        address=todo.popleft()
        for _ in range(8192):
            if address in seen: break
            off=file_offset(address,base,start,len(data),2)
            if off is None:
                stops['outside_image']+=1; break
            ins=next(md.disasm(data[off:off+4],address,count=1),None)
            if ins is None:
                stops['invalid_instruction']+=1; break
            seen[address]=(ins.size,ins.mnemonic)
            if reset <= address < reset+40:
                reset_sample.append({'address':address,'size':ins.size,'mnemonic':ins.mnemonic})
            direct=[op.imm for op in ins.operands if op.type==ARM_OP_IMM]
            call=ins.group(cs.CS_GRP_CALL)
            jump=ins.group(cs.CS_GRP_JUMP)
            mnem=ins.mnemonic
            if (call or jump) and direct:
                target=direct[-1] & ~1
                mapped=file_offset(target,base,start,len(data),2) is not None
                edges.append({'from':address,'to':target,'call':call,'mapped':mapped})
                if mapped: todo.append(target)
                if not call and mnem in ('b','b.w'): break
            elif jump or call:
                stops['indirect_branch_or_call']+=1
                if not call: break
            # A PC destination without a direct branch is not linear fall-through.
            pcwrite=False
            try:
                pcwrite=ARM_REG_PC in ins.regs_access()[1]
            except cs.CsError:
                pass
            if not call and not jump and (ins.group(cs.CS_GRP_RET) or pcwrite):
                load=literal_load(data,off,base,start)
                if load and load[0]==15:
                    target=struct.unpack_from('<I',data,load[1])[0] & ~1
                    if file_offset(target,base,start,len(data),2) is not None: todo.append(target)
                stops['return_or_pc_write']+=1; break
            if mnem in ('udf','udf.w','bkpt'):
                stops['trap']+=1; break
            address+=ins.size
            if len(seen)>=max_instructions: break
        else:
            stops['linear_block_limit']+=1
    refs=string_references(data,base,start)
    for ref in refs['literal_loads']:
        address=ref['instruction_address']
        ref['reachable_from_exception_seed']=address in seen
        ins=next(md.disasm(data[ref['instruction_offset']:ref['instruction_offset']+4],address,count=1),None)
        ref['capstone_mnemonic']=ins.mnemonic if ins else None
        # Small following sequence summaries, no raw bytes or arbitrary strings.
        nearby=[]
        off=ref['instruction_offset']
        for ins in md.disasm(data[off:off+24],address):
            nearby.append({'address':ins.address,'mnemonic':ins.mnemonic,
                           'direct_targets':[op.imm for op in ins.operands if op.type==ARM_OP_IMM] if ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP) else []})
        ref['following_instructions']=nearby
    pointer_neighbours=[]
    for off in refs['pointer_offsets']:
        neighbours=[]
        for delta in (-8,-4,4,8,12):
            q=off+delta
            if 0<=q<=len(data)-4:
                value=struct.unpack_from('<I',data,q)[0]
                if value & 1 and file_offset(value & ~1,base,start,len(data),2) is not None:
                    neighbours.append({'delta':delta,'address':value & ~1,
                                       'reachable_from_exception_seed':(value & ~1) in seen})
        pointer_neighbours.append({'pointer_offset':off,'mapped_odd_neighbours':neighbours})
    return {'capstone_version':cs.__version__,'vector':vector,'seed_count':len(seeds),
            'instruction_count':len(seen),'instruction_limit_reached':len(seen)>=max_instructions,
            'direct_edge_count':len(edges),'mapped_direct_edges':sum(e['mapped'] for e in edges),
            'stop_counts':dict(stops),'reset_first_mnemonics':sorted(reset_sample,key=lambda r:r['address']),
            'first_direct_edges':edges[:20], 'string_references':refs,'pointer_neighbours':pointer_neighbours,
            'limits':['Static exception-seeded partial traversal, not complete reachability or execution.',
                      'Indirect calls and jump tables unresolved; immediate values are not proof of semantics.']}


def main():
    from sl3p_loader_source_probe import acquire
    from sl3p_lens_plaintext1f import URL,SOURCE_BYTES,reconstruct
    from sl3p_lens_records1g import verify_lens
    data=acquire(URL,SOURCE_BYTES)
    plain,proof=reconstruct(data)
    del plain
    package=verify_lens(data)
    wrappers=[]
    result={'tool':'LENS_CODE1H','source_proof':proof,'firmware_executed':False}
    for p in package['payloads']:
        content=data[p['offset']:p['offset']+p['size']]
        wrappers.append({'records':p['record_indexes'],'size':len(content),'wrapper_candidates':wrapper_candidates(content)})
        if p['sha256']==TARGET_SHA:
            vectors=vector_candidates(content)
            result['target_sha256']=hashlib.sha256(content).hexdigest()
            result['code_checks']=[code_walk(content,v) for v in vectors]
    result['wrappers']=wrappers
    print('LENS_CODE1H_JSON_BEGIN')
    print(json.dumps(result,separators=(',',':')))
    print('LENS_CODE1H_JSON_END')


if __name__=='__main__': main()
