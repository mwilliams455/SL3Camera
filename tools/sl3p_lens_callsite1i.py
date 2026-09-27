#!/usr/bin/env python3
"""RESEARCH1I: bounded static callsite inspection, never firmware execution.

Reads only pinned public source bytes and mapped packet regions. Linear scan
candidates are not asserted reachable. Numeric disassembly is bounded; neither
binary payloads nor arbitrary firmware strings are emitted.
"""
from __future__ import annotations
import hashlib
import json
import struct
from sl3p_sparse_code1h import SparseImage, literal


def bl_target(raw: bytes, address: int) -> int | None:
    """Decode Thumb-2 BL immediate only (not BLX or B.W)."""
    if address < 0 or address > 0xfffffffb or address % 2 or len(raw) < 4:
        return None
    first, second = struct.unpack_from('<HH', raw)
    if first & 0xf800 != 0xf000 or second & 0xd000 != 0xd000:
        return None
    s = (first >> 10) & 1
    i1 = 1 ^ ((second >> 13) & 1) ^ s
    i2 = 1 ^ ((second >> 11) & 1) ^ s
    value = (s << 24) | (i1 << 23) | (i2 << 22) | ((first & 1023) << 12) | ((second & 2047) << 1)
    if s:
        value -= 1 << 25
    return (address + 4 + value) & 0xffffffff


def acquire_image():
    from sl3p_loader_source_probe import acquire
    from sl3p_lens_plaintext1f import URL, SOURCE_BYTES, reconstruct
    from sl3p_lens_records1g import verify_lens
    from sl3p_lens_inner1h import TARGET_SHA
    from sl3p_ldaf1h import verify_packets
    source = acquire(URL, SOURCE_BYTES)
    plain, proof = reconstruct(source)
    del plain
    target = next(p for p in verify_lens(source)['payloads'] if p['sha256'] == TARGET_SHA)
    payload = source[target['offset']:target['offset'] + target['size']]
    if hashlib.sha256(payload).hexdigest() != TARGET_SHA:
        raise ValueError('target payload identity failed')
    regions, framing = verify_packets(payload)
    if framing['trailer_hex'] != '53544f5000':
        raise ValueError('target trailer changed')
    return SparseImage(regions), proof


def inspect(image: SparseImage) -> dict:
    import capstone as cs
    from capstone.arm import ARM_OP_IMM
    md = cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_THUMB | cs.CS_MODE_MCLASS)
    md.detail = True
    def one(address):
        raw = image.read(address, 4) or image.read(address, 2)
        return next(md.disasm(raw, address, count=1), None) if raw else None
    def window(start, count=64, stop_return=False):
        rows = []
        cursor = start
        for _ in range(count):
            ins = one(cursor)
            if ins is None:
                break
            row = {'address':cursor,'size':ins.size,'mnemonic':ins.mnemonic,'operands':ins.op_str}
            hit = literal(image, cursor)
            if hit:
                row['literal'] = hit
            rows.append(row)
            cursor += ins.size
            if stop_return and (ins.mnemonic == 'bx' and ins.op_str == 'lr' or ins.mnemonic.startswith('pop') and 'pc' in ins.op_str):
                break
        return rows
    targets = {0x25bc0, 0x1e646, 0x1e680}
    calls = []
    prologues = []
    for start, body in image.regions:
        for address in range(start + start % 2, start + len(body) - 3, 2):
            raw = image.read(address, 4)
            target = bl_target(raw, address)
            if target in targets:
                ins = one(address)
                if ins is not None and ins.mnemonic == 'bl' and ins.operands[-1].type == ARM_OP_IMM and (ins.operands[-1].imm & 0xffffffff) == target:
                    calls.append({'from':address,'target':target,'candidate_only':True})
            if 0x1e400 <= address < 0x1e646:
                ins = one(address)
                if ins is not None and ins.mnemonic.startswith('push') and 'lr' in ins.op_str:
                    prologues.append(address)
    return {'callee':window(0x25bc0,80,True),
            'callsite_neighbourhood':window(0x1e600,100),
            'candidate_prologues':prologues,
            'direct_call_candidates':calls[:100],
            'direct_call_candidate_count':len(calls),
            'limits':['Halfword scanning does not establish instruction boundaries or reachability.',
                      'Function roles remain hypotheses pending argument and control-flow analysis.']}


def main():
    image, proof = acquire_image()
    report = {'tool':'LENS_CALLSITE1I','source_proof':proof,'analysis':inspect(image),
              'firmware_executed':False,'binary_published':False}
    print('LENS_CALLSITE1I_JSON_BEGIN')
    print(json.dumps(report,separators=(',',':')))
    print('LENS_CALLSITE1I_JSON_END')


if __name__ == '__main__':
    main()
