#!/usr/bin/env python3
"""Static constructor-linked lens interfaces and partial RAM-copy reconstruction.

Only supplied source bytes are relocated. Missing source ranges remain missing.
No firmware execution, emulation, binary dumps or device access.
"""
from __future__ import annotations
import json
from sl3p_lens_callsite1i import acquire_image,bl_target
from sl3p_lens_interfaces1j import window
from sl3p_sparse_code1h import SparseImage,literal


def method_entries(image,table:int,slots:list[int]) -> dict[int,int]:
    if table<0 or table%4 or table>0xfffffffc or not slots or len(slots)>16:
        raise ValueError('invalid method-table request')
    result={}
    for slot in slots:
        if slot<0 or slot%4 or slot>128 or table+slot>0xfffffffc:
            raise ValueError('invalid slot')
        raw=image.read(table+slot,4)
        if raw is None:raise ValueError('unmapped table word')
        value=int.from_bytes(raw,'little')
        if not value&1 or image.read(value&~1,2) is None:
            raise ValueError('not a mapped Thumb method pointer')
        result[slot]=value&~1
    return result


def relocate_known_ranges(image,source:int,destination:int,size:int):
    if not 0<size<=0x100000 or min(source,destination)<0 or max(source,destination)+size>2**32:
        raise ValueError('invalid relocation range')
    regions=[]
    for address,data in image.regions:
        lo=max(source,address);hi=min(source+size,address+len(data))
        if hi>lo:
            regions.append((destination+lo-source,data[lo-address:hi-address]))
    known=sum(len(b) for _,b in regions)
    return SparseImage(regions),{'source':source,'destination':destination,'requested_bytes':size,
                                'known_bytes':known,'unknown_bytes':size-known,'firmware_executed':False}


def inspect(image):
    table=method_entries(image,0x904,[0,4,8,12,16])
    if table!={0:0x738,4:0x740,8:0x762,12:0x770,16:0x796}:
        raise ValueError('destination table changed')
    if literal(image,0xda0e)['value']!=0x904 or bl_target(image.read(0x798,4),0x798)!=0x730:
        raise ValueError('destination constructor or completion link changed')
    if literal(image,0x10378)['value']!=0x3bdbc or method_entries(image,0x3bdbc,[44])!={44:0x10454}:
        raise ValueError('storage constructor/table changed')
    source=literal(image,0x7a4)['value'];destination=literal(image,0x7a2)['value'];count=literal(image,0x7a6)['value']
    if (source,destination,count)!=(0x50c,0x20000554,0x214):
        raise ValueError('RAM copy literals changed')
    relocated,copy=relocate_known_ranges(image,source,destination,count*4)
    transfers=[]
    for a in (0x720,0x728,0x730):
        h=literal(image,a)
        if h is None or h['register']!=15 or not h['value']&1:
            raise ValueError('expected literal PC transfer')
        target=h['value']&~1
        if relocated.read(target,2) is None:raise ValueError('transfer source is unavailable')
        transfers.append({'veneer':a,'target':target,'source_address':source+target-destination})
    return {'destination_table':table,
            'destination_constructor':window(image,0xda04,0xda16,12),
            'destination_methods':window(image,0x738,0x7a0,64),
            'storage_constructor':window(image,0x1036c,0x103ac,36),
            'storage_read_method':window(image,0x10454,0x104c8,64),
            'reader_adapter':window(image,0x108a0,0x108b2,16),
            'copy_loop':window(image,0x7a0,0x7be,20),'partial_copy':copy,'literal_transfers':transfers,
            'relocated_windows':[
                {'role_candidate':name,'instructions':window(relocated,start,stop,100)}
                for name,start,stop in [('reset',0x20000554,0x20000584),
                                        ('prepare',0x2000058c,0x200005fa),
                                        ('program',0x200005fa,0x200006c6),
                                        ('completion',0x200006c6,0x20000742)]],
            'limits':['Role candidates require instruction and hardware-documentation checks.',
                      'Relocation is a static byte copy of known ranges, not execution or a complete RAM image.',
                      'Static constructor paths do not establish runtime command reachability or camera-UPD compatibility.']}


def main():
    image,proof=acquire_image()
    print('LENS_DESTINATION1J_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_DESTINATION1J','source_proof':proof,'analysis':inspect(image),
                      'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_DESTINATION1J_JSON_END')

if __name__=='__main__':main()
