#!/usr/bin/env python3
"""Read-only, reproducible SL3P protected-payload audit. NOT a decryptor.

Coverage: all section bytes in non-overlapping 4 KiB tiles, all metadata,
all same-size/same-expected-hash pairs. Entropy is not cipher identification.
Requires numpy; layout validation is delegated to the frozen CONTAINER1A parser.
"""
from __future__ import annotations
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import struct
import sys
import numpy as np
from sl3p_inspect import Firmware, inspect

TILE = 4096


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(data)
    return float(-(p * np.log2(p)).sum())


def tile_stats(data: bytes, tile_size: int = TILE) -> dict:
    if tile_size < 1:
        raise ValueError('tile_size must be positive')
    records = []
    for offset in range(0, len(data), tile_size):
        part = data[offset:offset + tile_size]
        counts = np.bincount(np.frombuffer(part, dtype=np.uint8), minlength=256)
        records.append((offset, len(part), entropy(part), int(counts.max())))
    if not records:
        return {'tiles': 0, 'bytes_covered': 0}
    full = [r for r in records if r[1] == tile_size]
    min_row = min(records, key=lambda r: r[2])
    low = [dict(offset=o, size=n, entropy=h) for o,n,h,m in records if n==tile_size and h < 7.8]
    return {
        'tiles': len(records), 'bytes_covered': sum(r[1] for r in records),
        'full_tiles':len(full), 'partial_tiles':len(records)-len(full),
        'entropy_min_all':min_row[2], 'entropy_min_offset':min_row[0],
        'entropy_max_all':max(r[2] for r in records),
        'entropy_mean_full':float(np.mean([r[2] for r in full])) if full else None,
        'entropy_min_full':min((r[2] for r in full),default=None),
        'full_tiles_entropy_below_7_8':low,
        'max_single_byte_fraction_full':max((r[3]/r[1] for r in full),default=None),
        'scope':'Non-overlapping tiles, not a byte-sliding detector. High entropy cannot exclude small plaintext islands or identify a cipher.'
    }


def compare_same_plain_candidate(a: bytes, b: bytes, field_a: bytes, field_b: bytes) -> dict:
    if len(a) != len(b) or len(a) == 0:
        raise ValueError('Require equal nonzero lengths')
    x=np.frombuffer(a,dtype=np.uint8);y=np.frombuffer(b,dtype=np.uint8)
    diff = bytes(np.bitwise_xor(x,y))
    return {
        'bytes_compared':len(a), 'equal_bytes':int(np.count_nonzero(x==y)),
        'equal_fraction':float(np.mean(x==y)),
        'equal_aligned_16B_blocks':sum(a[o:o+16]==b[o:o+16] for o in range(0,len(a)-15,16)),
        'payloads_identical':a==b, 'fields_identical':field_a==field_b,
        'payload_xor_entropy':entropy(diff),
        'repeating_field_xor_explains_difference':all(d==(field_a[i%16]^field_b[i%16]) for i,d in enumerate(diff)),
    }


def target_layout(rows: list[dict]) -> dict:
    cursor=0;gaps=[];overlaps=[];total=0
    for row in sorted((r for r in rows if r['size']),key=lambda r:(r['target_offset_unconfirmed'],r['index'])):
        start=row['target_offset_unconfirmed'];end=start+row['size'];total+=row['size']
        if start>cursor:gaps.append({'offset':cursor,'size':start-cursor,'before_index':row['index']})
        if start<cursor:overlaps.append({'index':row['index'],'start':start,'previous_end':cursor})
        cursor=max(cursor,end)
    return {'span_end':cursor,'nonempty_payload_bytes':total,'gaps':gaps,
            'gap_bytes':sum(g['size'] for g in gaps),'overlaps':overlaps,
            'all_targets_64KiB_aligned':all(r['target_offset_unconfirmed']%65536==0 for r in rows),
            'meaning':'Stored target-offset field only; NOT established CPU runtime addresses or partition capacities.'}


def run(path: Path) -> dict:
    inv=inspect(path);fw=Firmware(path);rows=inv['sections'];head=fw.read(0,inv['directory']['data_start'])
    details=[];hash_groups=defaultdict(list);total_opaque=0;full_tiles=0;all_low=[]
    known={r['index']:r for r in inv['known_fill_hash_targets_in_opaque_sections']}
    for row in rows:
        hash_groups[(row['size'],row['stored_sha256'])].append(row)
        b=fw.read(row['file_offset'],row['size'])
        field=bytes.fromhex(row['unknown_16_bytes']);sha=hashlib.sha256(b).digest()
        candidates={'md5_payload':hashlib.md5(b).digest(),
                    'md5_original':hashlib.md5(b.translate(bytes(255-i for i in range(256)))).digest(),
                    'sha256_payload_first16':sha[:16], 'sha256_payload_last16':sha[16:],
                    'sha256_expected_first16':bytes.fromhex(row['stored_sha256'])[:16],
                    'sha256_expected_last16':bytes.fromhex(row['stored_sha256'])[16:]}
        d={'index':row['index'],'name':row['name'],'size':row['size'],
           'metadata16_digest_matches':[k for k,v in candidates.items() if v==field]}
        if row['flags']==3:
            stats=tile_stats(b);d['tile_stats']=stats;total_opaque+=len(b);full_tiles+=stats['full_tiles']
            all_low += [{'index':row['index'],**v} for v in stats['full_tiles_entropy_below_7_8']]
            d['aligned_16B_blocks']=len(b)//16
            d['unique_aligned_16B_blocks']=len(set(b[o:o+16] for o in range(0,len(b)-15,16)))
            if row['index'] in known:
                # Any exact periodic XOR/additive mask with period <= n-64 must repeat this prefix.
                other=b.find(b[:64],1)
                d['known_fill_tests']={
                    'candidate_fill':known[row['index']]['fill_byte'],
                    'first64_reappears_at':other,
                    'no_exact_mask_period_up_to':len(b)-64 if other==-1 else None,
                    'direct_fixed_key_ECB16_rejected':len(set(b[o:o+16] for o in range(0,len(b)-15,16)))>1,
                    'qualification':'Conditional on direct encryption/obfuscation of the hash-identified constant-fill candidate. No cipher identified.'}
        details.append(d)
    pairs=[]
    for (size,digest),group in hash_groups.items():
        opaque=[r for r in group if r['flags']==3]
        if not size or len(opaque)<2:continue
        for i,a in enumerate(opaque):
            for b in opaque[i+1:]:
                pairs.append({'indexes':[a['index'],b['index']],'names':[a['name'],b['name']],
                              'size':size,'expected_sha256':digest,
                              'comparison':compare_same_plain_candidate(fw.read(a['file_offset'],size),fw.read(b['file_offset'],size),bytes.fromhex(a['unknown_16_bytes']),bytes.fromhex(b['unknown_16_bytes']))})
    gaps=[('outer_unused',0x44,0x200),('leica_reserved1',0x206,0x220),('leica_reserved2',0x260,0x2a0),
          ('directory_padding',inv['directory']['offset']+len(rows)*inv['directory']['entry_size'],inv['directory']['data_start'])]
    gap_info=[]
    for name,start,end in gaps:
        b=head[start:end];gap_info.append({'name':name,'start':start,'end':end,'size':len(b),'all_zero':b==bytes(len(b)),'nonzero_bytes':sum(c!=0 for c in b)})
    header_hashes=[]
    for name,o,n in [('inner',0x2a0,fw.size-0x2a0),('directory',0x2ec,len(rows)*92),('payload',inv['directory']['data_start'],inv['directory']['data_size']),('post_signature',0x260,fw.size-0x260)]:
        h=hashlib.sha256()
        for b in fw.chunks(o,n):h.update(b)
        header_hashes.append({'name':name,'offset':o,'length':n,'sha256':h.hexdigest(),'matches_header220':h.digest()==head[0x220:0x240],'matches_header240':h.digest()==head[0x240:0x260]})
    return {'tool':'SL3P_DEEPAUDIT1B','firmware_sha256':inv['input_sha256'],
            'summary':{'sections':len(rows),'opaque_sections':sum(r['flags']==3 for r in rows),'opaque_bytes_audited':total_opaque,
                       'full_4KiB_tiles_audited':full_tiles,'low_entropy_full_tiles':all_low,
                       'metadata16_digest_matches_opaque':sum(bool(d['metadata16_digest_matches']) for d in details if rows[d['index']]['flags']==3),
                       'paired_opaque_same_expected_hash':len(pairs)},
            'target_layout':target_layout(rows),'unallocated_header_regions':gap_info,
            'header64_sha256_hypotheses':header_hashes,'section_details':details,'same_expected_hash_pairs':pairs,
            'limitations':['Target-offset semantics are not reverse engineered.','Entropy and names do not identify executable architecture, NN models, or image algorithms.','Opaque expected-hash equality is a content-identity candidate, not recovered plaintext.','Hash checks are not vendor signature authentication.']}


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('firmware',type=Path);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args()
    try:
        result=run(args.firmware);args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
        print(json.dumps(result['summary'],indent=2))
    except (OSError,ValueError,struct.error) as e:ap.exit(2,f'error: {e}\n')
if __name__=='__main__':main()
