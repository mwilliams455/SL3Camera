#!/usr/bin/env python3
"""Trace the constructor-linked comparison destination and storage adapter."""
from __future__ import annotations
import json, struct
from sl3p_lens_callsite1i import acquire_image,bl_target
from sl3p_lens_interfaces1j import window
from sl3p_sparse_code1h import literal


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


def inspect(image):
    table=method_entries(image,0x904,[0,4,8,12,16])
    if table!={0:0x738,4:0x740,8:0x762,12:0x770,16:0x796}:
        raise ValueError('destination table changed')
    if literal(image,0xda0e)['value']!=0x904 or bl_target(image.read(0x798,4),0x798)!=0x730:
        raise ValueError('destination constructor or completion link changed')
    rows=window(image,0x1036c,0x103c0,40)
    candidates=[]
    for row in rows:
        h=row.get('literal')
        if not h:continue
        try:methods=method_entries(image,h['value'],[44])
        except ValueError:continue
        a=methods[44]
        candidates.append({'load':row['address'],'table':h['value'],'slot44':a,
                           'method_window':window(image,a,a+200,90),'candidate_only':True})
    return {'destination_table':table,
            'destination_methods':window(image,0x730,0x7a0,80),
            'source_constructor':rows,'source_table_candidates':candidates,
            'reader_adapter':window(image,0x108a0,0x108b2,16),
            'low_level_region_probe':window(image,0x6d0,0x738,48),
            'limits':['The destination +12 implementation compares bytes; it does not store packet bytes.',
                      'Table +16 delegates to 0x730; further transfer semantics are still under inspection.',
                      'Static constructor paths do not establish runtime command reachability.']}


def main():
    image,proof=acquire_image()
    print('LENS_DESTINATION1J_JSON_BEGIN')
    print(json.dumps({'tool':'LENS_DESTINATION1J','source_proof':proof,'analysis':inspect(image),
                      'firmware_executed':False,'binary_published':False},separators=(',',':')))
    print('LENS_DESTINATION1J_JSON_END')

if __name__=='__main__':main()
