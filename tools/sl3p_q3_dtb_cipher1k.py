#!/usr/bin/env python3
"""Analyze a mapped Q3 DTB as candidate known plaintext inside protected program bytes.

The mapping is supported by published Q3 boot addresses + UPD target offsets, but
the tool labels it candidate plaintext until a decoded program independently
confirms it. It emits hashes/statistics only, not firmware/ciphertext bytes.
"""
from __future__ import annotations
import argparse,collections,hashlib,json,math
from pathlib import Path
from sl3p_inspect import Firmware
from sl3p_upd_family1k import inspect_family

Q3_UBOOT_BASE=0x400180000
Q3_DTB_ADDRESS=0x401290000
EXPECTED_DTB_SHA256="9feb71705abf76de032143dcb39a1129dc5a880dcf683aab26ca67ff686994a1"
HIST_MASK=bytes.fromhex(
 "0f71299c43b5b2ddaa584c2220904ea7"
 "f09b9ff28c980de93027362ea8ef3050"
 "b7f510bd"
)

def entropy(data: bytes) -> float:
    if not data:return 0.0
    c=collections.Counter(data);n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def lag_equal_fraction(data: bytes, lag: int) -> float:
    if lag<=0 or lag>=len(data):return 0.0
    return sum(a==b for a,b in zip(data[:-lag],data[lag:]))/(len(data)-lag)

def repeated_plain_block_test(plain: bytes,cipher: bytes,block=16):
    groups={}
    n=min(len(plain),len(cipher))//block
    for i in range(n):
        p=plain[i*block:(i+1)*block]
        groups.setdefault(p,[]).append(i)
    repeated={p:ix for p,ix in groups.items() if len(ix)>1}
    pairs=0;same_cipher=0
    samples=[]
    for p,ix in repeated.items():
        base=cipher[ix[0]*block:(ix[0]+1)*block]
        for j in ix[1:]:
            pairs+=1
            cb=cipher[j*block:(j+1)*block]
            eq=cb==base;same_cipher+=int(eq)
            if len(samples)<20:samples.append({"plain_block_sha256":hashlib.sha256(p).hexdigest(),
                "first_index":ix[0],"other_index":j,"cipher_blocks_equal":eq})
    return {"repeated_plaintext_block_groups":len(repeated),"comparison_pairs":pairs,
            "equal_ciphertext_pairs":same_cipher,"samples":samples}

def metadata_relation(stream:bytes,meta:bytes):
    variants={
      "direct":meta,
      "reversed":meta[::-1],
      "complemented":bytes(x^0xff for x in meta),
      "reversed_complemented":bytes(x^0xff for x in meta[::-1]),
    }
    out={}
    for name,v in variants.items():
        matches=sum(b==v[i%len(v)] for i,b in enumerate(stream))
        out[name]={"equal_bytes":matches,"fraction":matches/len(stream) if stream else 0.0}
    return out

def analyze(firmware:Path,dtb_path:Path):
    inv=inspect_family(firmware)
    if inv["internal_identifier"]!="DC1231":
        raise ValueError(f"Expected Q3 DC1231, got {inv['internal_identifier']}")
    program=next(s for s in inv["sections"] if s["name"]=="program")
    runtime_base=Q3_UBOOT_BASE+program["target_offset_unconfirmed"]
    rel=Q3_DTB_ADDRESS-runtime_base
    if rel<0 or rel>=program["size"]:
        raise ValueError("Mapped DTB offset falls outside program")
    dtb=dtb_path.read_bytes();dsha=hashlib.sha256(dtb).hexdigest()
    if dsha!=EXPECTED_DTB_SHA256:
        raise ValueError(f"Unexpected rebuilt DTB hash {dsha}")
    if rel+len(dtb)>program["size"]:
        raise ValueError("DTB candidate exceeds program")
    fw=Firmware(firmware)
    cipher=fw.read(program["file_offset"]+rel,len(dtb))
    stream=bytes(a^b for a,b in zip(cipher,dtb))
    periods=[1,2,4,8,16,32,36,64,128,256,512,1024,2048,4096,8192]
    hist_positions=[]
    for start in range(max(0,len(stream)-len(HIST_MASK)+1)):
        if stream[start:start+len(HIST_MASK)]==HIST_MASK:
            hist_positions.append(start)
            if len(hist_positions)>=20:break
    meta=bytes.fromhex(program["unknown_16_bytes"])
    return {"tool":"Q3_DTB_CIPHER1K",
      "firmware":{"identifier":inv["internal_identifier"],"sha256":inv["input_sha256"],
        "program_index":program["index"],"program_size":program["size"],
        "program_expected_sha256":program["expected_sha256"],
        "program_target_offset":program["target_offset_unconfirmed"],
        "program_protected_payload_sha256":program["payload_sha256_after_outer_transform"],
        "program_metadata16_sha256":hashlib.sha256(meta).hexdigest()},
      "mapping":{"uboot_base":Q3_UBOOT_BASE,"program_runtime_base":runtime_base,
        "published_dtb_address":Q3_DTB_ADDRESS,"candidate_plaintext_relative_offset":rel,
        "candidate_plaintext_length":len(dtb),
        "basis":"Q3 published U-Boot addresses plus UPD program target offset; not decoded-program proof"},
      "dtb":{"sha256":dsha,"bytes":len(dtb)},
      "protected_segment":{"sha256":hashlib.sha256(cipher).hexdigest(),"entropy":entropy(cipher),
        "unique_16byte_blocks":len({cipher[i:i+16] for i in range(0,len(cipher)//16*16,16)})},
      "xor_stream":{"sha256":hashlib.sha256(stream).hexdigest(),"entropy":entropy(stream),
        "lag_equal_fraction":{str(p):lag_equal_fraction(stream,p) for p in periods},
        "historical_tz_mask_exact_positions":hist_positions,
        "metadata16_repetition_relation":metadata_relation(stream,meta)},
      "repeated_plaintext_test":repeated_plain_block_test(dtb,cipher),
      "limits":[
        "The rebuilt DTB is candidate plaintext at this location until independent plaintext recovery confirms the runtime mapping.",
        "A negative simple-XOR/periodicity/ECB screen does not identify the actual protection algorithm.",
        "No protected payload bytes or derived keystream bytes are emitted."
      ],
      "firmware_executed":False,"binary_published":False}

def main():
 p=argparse.ArgumentParser();p.add_argument("firmware",type=Path);p.add_argument("dtb",type=Path);a=p.parse_args()
 print("Q3_DTB_CIPHER1K_JSON_BEGIN");print(json.dumps(analyze(a.firmware,a.dtb),separators=(",",":")));print("Q3_DTB_CIPHER1K_JSON_END")
if __name__=="__main__":main()
