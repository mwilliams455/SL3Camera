#!/usr/bin/env python3
"""Compare two supported UPD inventories without pretending to decrypt either.

Pairs sections by (name, occurrence number), retaining duplicate names.
If duplicate-name ordering changes between versions, review pairing manually.
"""
from __future__ import annotations
import argparse
from collections import Counter
import json
from pathlib import Path
import struct
from sl3p_inspect import inspect


def keyed(rows:list[dict])->dict:
    seen=Counter();result={}
    for row in rows:
        key=(row['name'],seen[row['name']]);seen[row['name']]+=1;result[key]=row
    return result


def compare_inventories(a:dict,b:dict)->dict:
    left=keyed(a['sections']);right=keyed(b['sections']);rows=[]
    fields=['size','stored_sha256','payload_sha256_after_outer_transform','unknown_16_bytes',
            'target_offset_unconfirmed','file_offset','flags']
    for key in dict.fromkeys([*left,*right]):
        x=left.get(key);y=right.get(key)
        r={'name':key[0],'occurrence':key[1],'left_index':None if x is None else x['index'],
           'right_index':None if y is None else y['index']}
        if x is None:r['status']='added'
        elif y is None:r['status']='removed'
        else:
            changed={f:{'left':x[f],'right':y[f]} for f in fields if x[f]!=y[f]}
            same_expected=x['stored_sha256']==y['stored_sha256'] and x['size']==y['size']
            same_stored=x['payload_sha256_after_outer_transform']==y['payload_sha256_after_outer_transform']
            r.update(changed_fields=changed,same_expected_content_digest=same_expected,same_stored_payload=same_stored)
            if not changed:r['status']='unchanged_record_fields'
            elif same_expected and not same_stored:r['status']='same_expected_content_different_representation'
            elif same_expected:r['status']='same_expected_content_metadata_changed'
            else:r['status']='expected_content_changed'
        rows.append(r)
    return {'tool':'SL3P_COMPARE1B','left_sha256':a['input_sha256'],'right_sha256':b['input_sha256'],
            'left_model':a['internal_identifier'],'right_model':b['internal_identifier'],
            'same_model_identifier':a['internal_identifier']==b['internal_identifier'],
            'summary':dict(Counter(r['status'] for r in rows)),'sections':rows,
            'limitations':['Pairing uses name and ordinal, not proven semantic identity.','Same expected content is not proof of unchanged runtime behavior, especially when target offsets or flags differ.','No payload has been decrypted by this comparison.']}

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('left',type=Path);p.add_argument('right',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:r=compare_inventories(inspect(a.left),inspect(a.right));a.out.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r['summary'],indent=2))
    except (OSError,ValueError,struct.error) as e:p.exit(2,f'error: {e}\n')
