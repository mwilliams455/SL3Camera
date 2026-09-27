#!/usr/bin/env python3
"""Bounded clear-header key-window screen using known-fill transition checks.

This is NOT an AES identification or a cryptographic keyspace brute-force.
For direct CBC/CFB/OFB, transitions after block zero can be checked without
knowing the IV. CTR checks recover hypothetical counters from a candidate key.
Only a complete expected SHA-256 match is reported as a successful decode.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sl3p_inspect import Firmware, inspect


def xor(a:bytes,b:bytes)->bytes:
    if len(a)!=len(b):raise ValueError('xor operands differ in size')
    return bytes(x^y for x,y in zip(a,b))


def key_candidates(header:bytes)->dict[bytes,str]:
    out={}
    # Every byte-aligned 128/192/256-bit window of the normalized clear
    # wrapper/directory, plus specified endian/inversion variants.
    for n in (16,24,32):
        for off in range(len(header)-n+1):
            b=header[off:off+n]
            for label,v in [('direct',b),('invert',bytes(c^255 for c in b)),
                            ('reverse',b[::-1]),('swap32',b''.join(b[o:o+4][::-1] for o in range(0,n,4)))]:
                out.setdefault(v,f'header+{off:#x}/{n}/{label}')
    return out


def transition_modes(key:bytes,ciphertext:bytes,fill:int=255)->list[str]:
    if len(ciphertext)<64 or len(ciphertext)%16:raise ValueError('Need at least four full blocks')
    mask=bytes([fill])*len(ciphertext)
    ecb=Cipher(algorithms.AES(key),modes.ECB())
    dec=ecb.decryptor();d=dec.update(ciphertext)+dec.finalize()
    hits=[]
    if xor(d[16:],ciphertext[:-16])==mask[16:]:hits.append('CBC')
    enc=ecb.encryptor();e=enc.update(ciphertext[:-16])+enc.finalize()
    if xor(e,ciphertext[16:])==mask[16:]:hits.append('CFB128')
    stream=xor(ciphertext,mask)
    enc=ecb.encryptor();e=enc.update(stream[:-16])+enc.finalize()
    if e==stream[16:]:hits.append('OFB')
    dec=ecb.decryptor();counters=dec.update(stream)+dec.finalize()
    for endian in ('big','little'):
        values=[int.from_bytes(counters[o:o+16],endian) for o in range(0,len(counters),16)]
        if all(b==(a+1)%(1<<128) for a,b in zip(values,values[1:])):hits.append('CTR-'+endian)
    return hits


def full_decode(key:bytes,b:bytes,mode:str,fill:int=255)->tuple[bytes,bytes]:
    ec=Cipher(algorithms.AES(key),modes.ECB())
    dec=ec.decryptor()
    if mode=='CBC':
        iv=xor(dec.update(b[:16])+dec.finalize(),bytes([fill])*16)
        cipher=Cipher(algorithms.AES(key),modes.CBC(iv)).decryptor()
        return cipher.update(b)+cipher.finalize(),iv
    iv=dec.update(xor(b[:16],bytes([fill])*16))+dec.finalize()
    if mode=='CFB128':m=modes.CFB(iv)
    elif mode=='OFB':m=modes.OFB(iv)
    elif mode=='CTR-big':m=modes.CTR(iv)
    elif mode=='CTR-little':
        start=int.from_bytes(iv,'little');counters=b''.join(((start+i)%(1<<128)).to_bytes(16,'little') for i in range(len(b)//16))
        enc=ec.encryptor();stream=enc.update(counters)+enc.finalize();return xor(stream,b),iv
    else:raise ValueError(mode)
    cipher=Cipher(algorithms.AES(key),m).decryptor()
    return cipher.update(b)+cipher.finalize(),iv


def run(path:Path)->dict:
    inv=inspect(path);fw=Firmware(path)
    known=inv['known_fill_hash_targets_in_opaque_sections']
    if not known:raise ValueError('No hash-identified fill target')
    target=next(k for k in known if k['index']==8)
    row=inv['sections'][8];sample=fw.read(row['file_offset'],64)
    keys=key_candidates(fw.read(0,inv['directory']['data_start']))
    hits=[]
    for key,label in keys.items():
        for mode in transition_modes(key,sample,target['fill_byte']):
            plain,iv=full_decode(key,fw.read(row['file_offset'],row['size']),mode,target['fill_byte'])
            hits.append({'key_source':label,'mode':mode,'derived_iv_hex':iv.hex(),
                         'full_sha256_matches':hashlib.sha256(plain).hexdigest()==row['stored_sha256']})
    return {'tool':'SL3P_KEYSCREEN1B','firmware_sha256':inv['input_sha256'],'target_section':8,
            'key_count':len(keys),'sample_bytes':64,'mode_predicates_per_key':5,
            'key_source':'Every byte-aligned 16/24/32-byte key window in normalized bytes [0,0x1a00), plus direct/invert/reverse/swap32 variants, deduplicated.',
            'iv_independent_transition_modes':['CBC','CFB128','OFB','CTR-big','CTR-little'],
            'hits':hits,'scope':'Direct AES-based modes with no intervening payload transform; negative results do not identify protection or eliminate derived/hidden keys.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:r=run(a.firmware);a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
    except (OSError,ValueError,struct.error) as e:p.exit(2,f'error: {e}\n')
