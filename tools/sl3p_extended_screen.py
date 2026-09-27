#!/usr/bin/env python3
"""Bounded AES screen: byte conventions, derived metadata keys and first-block tests.
Not a cryptographic keyspace search. Only a full expected SHA256 match validates
an output. A fill-only success is not a general firmware decoder.
"""
from __future__ import annotations
import argparse,hashlib,hmac,json,struct,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from sl3p_inspect import Firmware,inspect,XOR_FF
from sl3p_key_screen import key_candidates,full_decode,xor


def permute(data:bytes, width:int, invert:bool=False)->bytes:
    if width not in (1,2,4,8,16) or len(data)%width:
        raise ValueError('Unsupported width or incomplete word')
    b=data if width==1 else b''.join(data[p:p+width][::-1] for p in range(0,len(data),width))
    return b.translate(XOR_FF) if invert else b


def derivations(header:bytes,row:dict)->dict[bytes,str]:
    ent=header[row['entry_file_offset']:row['entry_file_offset']+92]
    fields={'meta16':ent[60:76], 'digest32':ent[28:60], 'digest-low16':ent[28:44],
            'digest-high16':ent[44:60], 'record-prefix28':ent[:28], 'numeric16':ent[12:28],
            'name12':ent[:12], 'model16':header[12:28], 'global64':header[0x220:0x260]}
    for n in (16,32):
        for off in range(0,64-n+1,16):fields[f'global{n}@{off}']=header[0x220+off:0x220+off+n]
    fields.update({'zero16':bytes(16),'FF16':bytes([255])*16})
    out={}
    def add(data:bytes,label:str):
        if len(data) in (16,24,32):out.setdefault(data,label)
    def hash_add(data:bytes,label:str):
        for alg in ('md5','sha256','sha512'):
            d=hashlib.new(alg,data).digest()
            for n in (16,24,32):
                if len(d)>=n:
                    add(d[:n],f'{alg}({label})[:{n}]');add(d[-n:],f'{alg}({label})[-{n}:]')
    for name,data in fields.items():
        hash_add(data,name)
        hash_add(data.hex().encode(),name+'.hex-ascii')
        for n in (16,24,32):
            if len(data)>=n:add(data[:n],name+f'[:{n}]');add(data[-n:],name+f'[-{n}:]')
    for an,a in fields.items():
        for bn,b in fields.items():
            hash_add(a+b,an+'||'+bn)
            for n in (16,24,32):
                if len(a)==len(b)==n:add(xor(a,b),an+' XOR '+bn)
            for alg in ('md5','sha256'):
                d=hmac.new(a,b,alg).digest()
                add(d[:16],f'HMAC-{alg}({an},{bn})[:16]')
                if len(d)==32:add(d,f'HMAC-{alg}({an},{bn})')
            # A finite hypothesis that a 16-byte field is transformed under
            # another visible field; not a claim of an RFC key-wrap format.
            if len(a) in (16,24,32) and len(b)==16:
                c=Cipher(algorithms.AES(a),modes.ECB())
                e=c.encryptor();add(e.update(b)+e.finalize(),f'AES-E({an},{bn})')
                d=c.decryptor();add(d.update(b)+d.finalize(),f'AES-D({an},{bn})')
    expanded={}
    for k,label in out.items():
        for kind,v in [('direct',k),('invert',k.translate(XOR_FF)),('reverse',k[::-1]),('swap32',permute(k,4))]:
            expanded.setdefault(v,label+'/'+kind)
    return expanded


def multi_transition(key:bytes, samples:list[bytes])->list[tuple[int,int,str]]:
    """Batch ECB primitives; examine both fill00 and fillFF for each sample.

    Samples contain BOTH normal and inverted variants of each permutation.
    Encryption/decryption of the complete samples is cached, making all five
    recurrence checks independent of guessed IVs and reducing setup costs.
    """
    if not samples or any(len(b)!=64 for b in samples):raise ValueError('Need 64-byte samples')
    if len(samples)%2 or any(samples[i+1]!=samples[i].translate(XOR_FF) for i in range(0,len(samples),2)):
        raise ValueError('Samples must be direct/inverted pairs')
    c=Cipher(algorithms.AES(key),modes.ECB());joined=b''.join(samples)
    d=c.decryptor();ds=d.update(joined)+d.finalize()
    e=c.encryptor();es=e.update(joined)+e.finalize()
    hits=[]
    for i,s in enumerate(samples):
        dec=ds[64*i:64*i+64];enc=es[64*i:64*i+64]
        for fill in (0,255):
            # CBC and CFB candidates can be screened in C-backed byte comparisons.
            prev=s[:-16] if fill==0 else s[:-16].translate(XOR_FF)
            if dec[16:]==prev:hits.append((i,fill,'CBC'))
            nxt=s[16:] if fill==0 else s[16:].translate(XOR_FF)
            if enc[:-16]==nxt:hits.append((i,fill,'CFB128'))
            j=i if fill==0 else i^1
            if es[j*64:j*64+48]==nxt:hits.append((i,fill,'OFB'))
            ctr=ds[j*64:j*64+64]
            for endian in ('big','little'):
                a=int.from_bytes(ctr[:16],endian);b=int.from_bytes(ctr[16:32],endian)
                if b!=(a+1)%(1<<128):continue
                vals=[int.from_bytes(ctr[k:k+16],endian) for k in (32,48)]
                if vals==[(a+2)%(1<<128),(a+3)%(1<<128)]:hits.append((i,fill,'CTR-'+endian))
    return hits


def run(path:Path)->dict:
    inv=inspect(path);fw=Firmware(path);row=inv['sections'][8]
    if not any(k['index']==8 and k['fill_byte']==255 for k in inv['known_fill_hash_targets_in_opaque_sections']):
        raise ValueError('Expected known-fill oracle not found')
    header=fw.read(0,inv['directory']['data_start']);sample=fw.read(row['file_offset'],64)
    keys=key_candidates(header);old_n=len(keys);derived=derivations(header,row);added=len(set(derived)-set(keys))
    for k,label in derived.items():keys.setdefault(k,'derived:'+label)
    schemes=[(w,iv) for w in (1,2,4,8,16) for iv in (False,True)]
    samples=[permute(sample,w,iv) for w,iv in schemes]
    hits=[];started=time.monotonic()
    for count,(key,label) in enumerate(keys.items(),1):
        for variant,fill,mode in multi_transition(key,samples):
            width,inverted=schemes[variant]
            p,iv=full_decode(key,permute(fw.read(row['file_offset'],row['size']),width,inverted),mode,fill)
            # Output00 is a hypothesis with complementary plaintext convention.
            normalized=p.translate(XOR_FF) if fill==0 else p
            hits.append({'key_source':label,'sample_variant':{'word_reversal':width,'inverted':inverted},
                         'fill':fill,'mode':mode,'derived_iv_hex':iv.hex(),
                         'sha256_after_plaintext_convention':hashlib.sha256(normalized).hexdigest(),
                         'full_expected_hash_matches':hashlib.sha256(normalized).hexdigest()==row['stored_sha256']})
        if count%20000==0:print(f'Checked {count}/{len(keys)} keys',flush=True)
    return {'tool':'SL3P_EXTENDED_SCREEN1C','firmware_sha256':inv['input_sha256'],
            'target_section':8,'sample_offset_in_section':0,'sample_bytes':64,
            'base_visible_header_key_count':old_n,'derived_distinct_keys':len(derived),'new_derived_keys_not_in_base':added,
            'total_distinct_keys':len(keys),'payload_permutations':schemes,'fill_conventions':[0,255],
            'modes':['CBC','CFB128','OFB','CTR-big','CTR-little'],
            'predicate_combinations':len(keys)*len(schemes)*2*5,
            'prefix_hits':hits,'elapsed_seconds':time.monotonic()-started,
            'limitations':['Tests only the explicitly generated visible-field key and byte-convention families.',
                           'No identification or rejection of AES in general; no exhaustive KDF/keyspace search.',
                           'Two byte-order conventions indistinguishable on constant plaintext would need nonconstant validation.',
                           'No protected program output is created on a negative result.']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:
        r=run(a.firmware);a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
    except (OSError,ValueError) as e:p.exit(2,str(e)+'\n')
