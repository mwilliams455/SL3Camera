#!/usr/bin/env python3
"""Read-only bounded signature scan. Byte hits are not decoded files.
Checks common magic sequences and selected ASCII/UTF16 strings after XOR-FF.
Gzip tests cap both input and output. This is not a universal firmware scanner.
"""
import argparse
import json
from pathlib import Path
import struct
import zlib
from sl3p_inspect import Firmware

SIGNATURES={
    'gzip':b'\x1f\x8b\x08','ELF':b'\x7fELF','squashfs':b'hsqs',
    'XZ':b'\xfd7zXZ\0','LZ4_frame':b'\x04\x22\x4d\x18',
    'ZIP':b'PK\x03\x04','UBI':b'UBI#','uImage':bytes.fromhex('27051956'),
    'cpio':b'070701',
}
for term in ('LUT_3D_SIZE','L-Log','Leica Pure','Leica Cine','BT.2020','leica','lut_data'):
    for encoding in ('ascii','utf-16le','utf-16be'):
        SIGNATURES[f'{term} / {encoding}']=term.encode(encoding)


def scan(path):
    fw=Firmware(path);hits={name:[] for name in SIGNATURES}
    tail=b'';position=0;overlap=max(map(len,SIGNATURES.values()))-1
    for block in fw.chunks(0,fw.size):
        data=tail+block;base=position-len(tail)
        for name,sig in SIGNATURES.items():
            at=data.find(sig)
            while at>=0:
                absolute=base+at
                if not hits[name] or hits[name][-1]!=absolute:hits[name].append(absolute)
                at=data.find(sig,at+1)
        position+=len(block);tail=data[-overlap:]
    checks=[]
    for name in ('gzip','ELF','squashfs'):
        for off in hits[name]:
            data=fw.read(off,min(65536,fw.size-off))
            row={'type':name,'offset':off,'offset_hex':f'0x{off:08x}','first16_hex':data[:16].hex()}
            if name=='gzip':
                if len(data)<10 or data[3]&0xe0:
                    row['result']='invalid reserved gzip flag bits / header'
                else:
                    try:
                        dec=zlib.decompressobj(31);out=dec.decompress(data,1024*1024)
                        row.update(result='valid_complete_stream' if dec.eof else 'inconclusive_bounded_test',output_bytes=len(out))
                    except zlib.error as exc:row['result']=f'rejected: {exc}'
            elif name=='ELF':
                valid=len(data)>=16 and data[4] in (1,2) and data[5] in (1,2) and data[6]==1
                row['result']='candidate_needs_full_validation' if valid else 'invalid ELF identification bytes'
            else:
                major,minor=struct.unpack_from('<HH',data,28)
                row.update(major=major,minor=minor,result='candidate_needs_full_validation' if (major,minor)==(4,0) else 'not a valid SquashFS v4 superblock')
            checks.append(row)
    return {'stage':'outer-normalized bytes, NOT decrypted payloads',
            'signature_hits':hits,'validation':checks,
            'limitations':'Negative selected-signature tests do not exclude other embedded formats or transformed assets.'}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();r=scan(a.firmware);a.out.write_text(json.dumps(r,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'counts':{k:len(v) for k,v in r['signature_hits'].items()},'validation':r['validation']},indent=2))
