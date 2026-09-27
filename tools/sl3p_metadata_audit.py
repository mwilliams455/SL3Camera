#!/usr/bin/env python3
"""Read-only tests of unexplained metadata. No cipher identification is inferred."""
from __future__ import annotations
import argparse, hashlib, json, struct
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ec
from sl3p_inspect import Firmware, inspect


def digest_variants(data: bytes) -> dict[str, bytes]:
    out = {'MD5': hashlib.md5(data).digest()}
    for alg in ('sha1', 'sha256', 'sha512'):
        d = hashlib.new(alg, data).digest()
        out[alg + '-first16'] = d[:16]
        out[alg + '-last16'] = d[-16:]
    return out


def point_tests(data: bytes) -> list[dict]:
    if len(data) != 64:
        raise ValueError('Exactly 64 bytes required')
    out = []
    for order in ('xy', 'yx'):
        a,b = (data[:32],data[32:]) if order == 'xy' else (data[32:],data[:32])
        for endian in ('big','little'):
            x,y = int.from_bytes(a,endian),int.from_bytes(b,endian)
            for curve in (ec.SECP256R1(),ec.SECP256K1(),ec.BrainpoolP256R1()):
                ok = False
                try:
                    ec.EllipticCurvePublicNumbers(x,y,curve).public_key()
                    ok = True
                except ValueError:
                    pass
                out.append({'curve':curve.name,'order':order,'integer_order':endian,'valid_point':ok})
    return out


def run(path: Path) -> dict:
    inv=inspect(path); fw=Firmware(path); rows=inv['sections']; hdr=fw.read(0,0x1a00)
    prot=[r for r in rows if r['flags']==3]
    metas=[bytes.fromhex(r['unknown_16_bytes']) for r in prot]
    pairs=[]
    for i,a in enumerate(prot):
        for b in prot[i+1:]:
            if (a['size'],a['stored_sha256']) != (b['size'],b['stored_sha256']):continue
            am,bm=bytes.fromhex(a['unknown_16_bytes']),bytes.fromhex(b['unknown_16_bytes'])
            pairs.append({'indexes':[a['index'],b['index']], 'names':[a['name'],b['name']],
                          'expected_sha256':a['stored_sha256'],'size':a['size'],
                          'metadata_equal':am==bm,
                          'metadata_hamming_distance_bits':sum((x^y).bit_count() for x,y in zip(am,bm)),
                          'stored_payload_equal':a['payload_sha256_after_outer_transform']==b['payload_sha256_after_outer_transform']})
    # These are directly specified checksum hypotheses, not an exhaustive KDF search.
    checks=0; hits=[]; known=inv['known_fill_hash_targets_in_opaque_sections']
    for item in known:
        row=rows[item['index']]; expected=bytes.fromhex(row['unknown_16_bytes'])
        if row['flags']!=3:continue
        plain=bytes([item['fill_byte']])*row['size']
        ent=hdr[row['entry_file_offset']:row['entry_file_offset']+92]
        contexts={'empty':b'', 'name':row['name'].encode(), 'name-NUL':row['name'].encode()+b'\0',
                  'name-field12':ent[:12], 'numeric16':ent[12:28], 'record-prefix28':ent[:28],
                  'expected-SHA256':ent[28:60], 'model':hdr[12:28], 'global64':hdr[0x220:0x260]}
        for contextname,context in contexts.items():
            for order,data in [('context||plaintext',context+plain),('plaintext||context',plain+context)]:
                for alg,digest in digest_variants(data).items():
                    checks+=1
                    if digest==expected:hits.append({'index':row['index'],'context':contextname,'order':order,'algorithm':alg})
    # Check whether the entire 64-byte field is a simple digest of chosen regions.
    glob=hdr[0x220:0x260]; global_checks=[]
    regions=[('outer-prefix',0,0x44),('inner-header',0x2a0,0x4c),
             ('directory',0x2ec,len(rows)*92),('payload',0x1a00,fw.size-0x1a00),
             ('inner-to-EOF',0x2a0,fw.size-0x2a0),('after-field-to-EOF',0x260,fw.size-0x260),
             ('leica-body-field-zeroed',0x200,fw.size-0x200)]
    for name,off,length in regions:
        hashes={alg:hashlib.new(alg) for alg in ('sha512','blake2b')}
        pos=off
        for chunk in fw.chunks(off,length):
            if name=='leica-body-field-zeroed' and pos<0x260 and pos+len(chunk)>0x220:
                ba=bytearray(chunk); lo=max(0,0x220-pos);hi=min(len(ba),0x260-pos);ba[lo:hi]=b'\0'*(hi-lo);chunk=bytes(ba)
            for h in hashes.values():h.update(chunk)
            pos+=len(chunk)
        for alg,h in hashes.items():global_checks.append({'region':name,'algorithm':alg,'matches':h.digest()==glob})
    return {'tool':'SL3P_METADATA1C','firmware_sha256':inv['input_sha256'],
            'protected_section_count':len(prot),'unique_nonzero_metadata16':len(set(metas)),
            'metadata16_nonzero_iff_flag3':all((set(bytes.fromhex(r['unknown_16_bytes']))!={0})==(r['flags']==3) for r in rows),
            'all_reserved16_zero':all(r['reserved_16_bytes']=='00'*16 for r in rows),
            'same_expected_content_pairs':pairs,
            'known_plaintext_context_checksum_checks':checks,'known_plaintext_context_checksum_hits':hits,
            'global64_digest_checks':global_checks,'global64_public_point_tests':point_tests(glob),
            'inference':'Under the expected-content SHA256 interpretation, differing metadata on identical-content pairs rules out a deterministic function of plaintext alone. It does not identify an IV, a key, a salt or a tag.',
            'limitations':['Raw ECDSA-signature interpretation cannot be verified without an independently established public key and signed-message definition.',
                           'Negative digest/point tests only exclude the exact enumerated interpretations.',
                           'No protected bytes are decoded by this audit.']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:
        r=run(a.firmware);a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
    except (OSError,ValueError) as e:p.exit(2,str(e)+'\n')
