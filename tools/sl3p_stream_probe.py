#!/usr/bin/env python3
"""Known-fill mask tests independent of AES and of any guessed seed.
Tests complete 32-bit MT19937 output, one xorshift128 recurrence, and bounded
GF(2) linear recurrences in serialized 32-bit output lanes. No firmware cipher
or pseudorandom generator is assumed. Nonlinear/truncated/mixed generators
are outside scope. A recurrence hit is not a decoded program.
"""
from __future__ import annotations
import argparse,json,random,struct
from pathlib import Path
import numpy as np
from sl3p_inspect import Firmware,inspect,XOR_FF
MASK32=(1<<32)-1


def undo_right(x:int,shift:int)->int:
    y=x
    for _ in range((32+shift-1)//shift):y=x^(y>>shift)
    return y&MASK32


def undo_left(x:int,shift:int,mask:int)->int:
    y=x
    for _ in range((32+shift-1)//shift):y=x^((y<<shift)&mask)
    return y&MASK32


def untemper(y:int)->int:
    return undo_right(undo_left(undo_left(undo_right(y,18),15,0xefc60000),7,0x9d2c5680),11)


def temper(y:int)->int:
    y^=y>>11;y^=(y<<7)&0x9d2c5680;y^=(y<<15)&0xefc60000;y^=y>>18
    return y&MASK32


def mt_match(words:list[int], holdout:int=64)->bool:
    if holdout<1 or len(words)<624+holdout:raise ValueError('Insufficient MT sample')
    clone=random.Random(0)
    clone.setstate((3,tuple(untemper(w) for w in words[:624])+(624,),None))
    return all(clone.getrandbits(32)==w for w in words[624:624+holdout])


def xs_next(a:int,b:int)->int:
    t=(a^(a<<11))&MASK32
    return (b^(b>>19)^t^(t>>8))&MASK32


def xs_match(words:list[int],holdout:int=64)->bool:
    if holdout<1 or len(words)<4+holdout:raise ValueError('Insufficient xorshift sample')
    return all(xs_next(words[i-4],words[i-1])==words[i] for i in range(4,4+holdout))


def berlekamp_massey(bits:list[int])->tuple[int,int,int]:
    """Return recurrence polynomial, minimum fitted degree, and recent history."""
    C=B=1;L=0;m=-1;history=0
    for n,bit in enumerate(bits):
        if bit not in (0,1):raise ValueError('Not binary')
        history=(history<<1)|bit
        d=(C&history).bit_count()&1
        if d:
            previous=C;C^=B<<(n-m)
            if 2*L<=n:L=n+1-L;B=previous;m=n
    return C,L,history


def recurrence_match(bits:list[int],training:int=4096,max_degree:int=1024)->tuple[int,bool]:
    if training<1 or len(bits)<=training:raise ValueError('Need training and holdout')
    c,L,h=berlekamp_massey(bits[:training])
    if L>max_degree:return L,False
    # Keep only the necessary recent history, making the validator inexpensive.
    mask=(1<<(L+1))-1
    for bit in bits[training:]:
        h=((h<<1)|int(bit))&mask
        if (c&h).bit_count()&1:return L,False
    return L,True


def mask_candidates(data:bytes)->dict[str,bytes]:
    if len(data)%8:raise ValueError('Mask buffer must be multiple of 8')
    out={'identity':data,'XOR-FF':data.translate(XOR_FF)}
    # These cover identity/complement and C +/- 1 modulo complete byte/word
    # units, the elementary additive alternatives for constant FF/00 inputs.
    for width in (1,2,4,8):
        for endian in (['little'] if width==1 else ['little','big']):
            dtype=('<' if endian=='little' else '>')+f'u{width}'
            v=np.frombuffer(data,dtype=dtype)
            for direction in (-1,1):
                # Numpy preserves unsigned wraparound; restore explicit order.
                w=(v-np.array(1,dtype=v.dtype)) if direction<0 else (v+np.array(1,dtype=v.dtype))
                out[f'word{width}-{endian}-{direction:+d}']=w.astype(dtype).tobytes()
    return out


def run(path:Path)->dict:
    inv=inspect(path);fw=Firmware(path);report=[]
    for idx in (8,10):
        row=inv['sections'][idx]
        if not any(k['index']==idx and k['fill_byte']==255 for k in inv['known_fill_hash_targets_in_opaque_sections']):
            raise ValueError('Known fill unavailable')
        data=fw.read(row['file_offset'],row['size']);masks=mask_candidates(data)
        mt_checks=xs_checks=0;mt_hits=[];xs_hits=[];linear=[]
        for label,stream in masks.items():
            for offset in (0,1,2,3,65536,65537,65538,65539):
                segment=stream[offset:offset+4*688]
                for endian in ('little','big'):
                    words=list(struct.unpack(('<' if endian=='little' else '>')+'688I',segment))
                    mt_checks+=1;xs_checks+=1
                    if mt_match(words):mt_hits.append({'mask':label,'offset':offset,'endian':endian})
                    if xs_match(words):xs_hits.append({'mask':label,'offset':offset,'endian':endian})
            w=np.frombuffer(stream[:8192*4],dtype='<u4')
            for bit in range(32):
                bits=((w>>bit)&1).tolist();degree,ok=recurrence_match(bits)
                linear.append({'mask':label,'bit_lane':bit,'degree_fit_4096':degree,'holdout_match_degree_le_1024':ok})
        report.append({'index':idx,'mask_variants':len(masks),'MT19937_checks':mt_checks,'MT19937_hits':mt_hits,
                       'xorshift128_checks':xs_checks,'xorshift128_hits':xs_hits,
                       'linear_recurrence_checks':len(linear),'linear_recurrence_hits':[r for r in linear if r['holdout_match_degree_le_1024']],
                       'minimum_fitted_degree':min(r['degree_fit_4096'] for r in linear),
                       'maximum_fitted_degree':max(r['degree_fit_4096'] for r in linear),
                       'lane_results':linear})
    return {'tool':'SL3P_STREAM1C','firmware_sha256':inv['input_sha256'],'sections':report,
            'MT19937_scope':'688 complete output words; untemper first624, predict next64; offsets0..3 and65536..65539 in both endiannesses. Does not cover truncated or scrambled MT output.',
            'xorshift_scope':'Marsaglia 32-bit four-word xorshift128 recurrence with shifts11,19,8; 64 holdout words.',
            'linear_scope':'For each mask variant, each of32 little-endian word bit lanes:4096 training bits,4096 holdout bits, maximum degree1024. No finding about arbitrary or nonlinear generators.',
            'limitation':'A predictable-mask hypothesis is only useful if it predicts fresh bytes. Negative results do not identify a cryptographic cipher or prove its security.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:
        r=run(a.firmware);a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(r,indent=2)+'\n')
        print(json.dumps({**r,'sections':[{k:v for k,v in s.items() if k!='lane_results'} for s in r['sections']]},indent=2))
    except (OSError,ValueError) as e:p.exit(2,str(e)+'\n')
