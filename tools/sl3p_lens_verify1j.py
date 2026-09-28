#!/usr/bin/env python3
"""Assert selected 1J static observations and emit a source-only summary.

This checks decoded instructions and constructor links. It does not execute
firmware or establish runtime path feasibility or a physical chip identity.
"""
from __future__ import annotations
import json
from sl3p_lens_callsite1i import acquire_image, bl_target
from sl3p_lens_interfaces1j import window
from sl3p_lens_destination1j import inspect, method_entries, relocate_known_ranges
from sl3p_sparse_code1h import literal


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify(image):
    evidence = inspect(image)
    calls = {0xadaa: 0xda04, 0xb194: 0x1036c, 0xb1ac: 0x10870,
             0x76a: 0x728, 0x798: 0x730}
    for address, target in calls.items():
        require(bl_target(image.read(address, 4) or b'', address) == target,
                f'call identity changed at {address:#x}')
    for address, value in {0xada6: 0x2000ada0, 0xb1a8: 0x2000ac9c,
                           0xda0e: 0x904, 0x1087e: 0x3e4d8,
                           0x10378: 0x3bdbc}.items():
        hit = literal(image, address)
        require(hit is not None and hit['value'] == value,
                f'literal identity changed at {address:#x}')
    require(method_entries(image, 0x3e4d8, [8]) == {8: 0x108a0}, 'adapter table changed')
    comparator = window(image, 0x770, 0x796, 32)
    index = {row['address']: row for row in comparator}
    require(len(comparator) == 18, 'comparison boundary changed')
    require(index[0x772]['operands'] == 'r1, r1, #0x80000', 'comparison base changed')
    require(index[0x78c]['operands'] == 'r0, #4', 'mismatch status changed')
    require(index[0x790]['operands'] == 'r0, #0', 'equal status changed')
    require(not any(r['mnemonic'].startswith(('str', 'stm', 'bl')) for r in comparator),
            'comparison now contains a store or call')
    require(comparator[-1]['mnemonic'] == 'bx' and comparator[-1]['operands'] == 'lr',
            'comparison return changed')
    copy = evidence['partial_copy']
    require((copy['requested_bytes'], copy['known_bytes'], copy['unknown_bytes']) == (2128, 1044, 1084),
            'available relocation coverage changed')
    relocated, _ = relocate_known_ranges(image, 0x50c, 0x20000554, 2128)
    require(relocated.read(0x20000968, 1) is None, 'missing copy tail was invented')
    reset = window(relocated, 0x20000554, 0x20000568, 16)
    require([r['mnemonic'] for r in reset] == ['ldr', 'ldr', 'ands', 'ldr', 'orrs', 'str', 'dsb', 'b'],
            'reset sequence changed')
    require(reset[0]['literal']['value'] == 0xe000ed0c, 'AIRCR address changed')
    require(reset[2]['operands'] == 'r2, r2, #0x700', 'priority mask changed')
    require(reset[3]['literal']['value'] == 0x05fa0004, 'reset request word changed')
    require(reset[5]['operands'] == 'r2, [r1]' and reset[-1]['operands'] == '#0x20000566',
            'reset store or wait loop changed')
    require(bl_target(relocated.read(0x2000073c, 4), 0x2000073c) == 0x20000554,
            'completion no longer reaches reset helper')
    reader = {r['address']: r for r in evidence['storage_read_method']}
    for address, operands in {0x10494: 'r0, #3', 0x1049e: 'r1, r1, #0x10',
                               0x104a4: 'r1, r1, #8', 0x104aa: 'r5, [r0, #3]',
                               0x104b0: 'r3, r7', 0x104b2: 'r2, #4'}.items():
        require(reader[address]['operands'] == operands, f'read framing changed at {address:#x}')
    return {
        'selected_static_checks_pass': True,
        'destination': {'object_operand': 0x2000ada0, 'constructor': 0xda04, 'table': 0x904,
                        'methods': evidence['destination_table'], 'verification_entry': 0x770,
                        'verification_address_bias': 0x80000, 'comparison_mismatch_status': 4,
                        'comparison_equal_status': 0, 'comparison_contains_store_or_call': False},
        'reader': {'adapter_constructor': 0x10870, 'adapter_object_operand': 0x2000ac9c,
                   'adapter_entry': 0x108a0, 'forwarded_member_offset': 8, 'forwarded_table_slot': 44,
                   'storage_constructor': 0x1036c, 'storage_table': 0x3bdbc,
                   'read_entry': 0x10454, 'command': 3, 'address_bytes': 3,
                   'address_order': 'most-significant-byte-first', 'bus_or_chip_identified': False},
        'partial_copy': copy, 'literal_transfers': evidence['literal_transfers'],
        'completion': {'wrapper': 0x796, 'ram_entry': 0x200006c6,
                       'call_to_reset': 0x2000073c, 'reset_entry': 0x20000554,
                       'reset_register': 0xe000ed0c, 'request_word': 0x05fa0004,
                       'priority_mask_preserved': 0x700, 'software_reset_request_identified': True,
                       'preceding_vendor_register_semantics_verified': False},
        'camera_upd_decryption_recovered': False, 'firmware_executed': False,
        'limits': ['Static instruction checks, not a hardware trace or full path-feasibility proof.',
                   'The observed update branch calls verification, not the separate programming method.',
                   'Unknown copied bytes remain unavailable; this is not a complete RAM reconstruction.',
                   'No camera UPD consumer or base photographic transform was identified.']}


def main():
    image, proof = acquire_image()
    report = {'tool': 'LENS_INTERFACES1J_VERIFIED', 'source_proof': proof, 'analysis': verify(image)}
    print('LENS_INTERFACES1J_VERIFIED_JSON_BEGIN')
    print(json.dumps(report, separators=(',', ':')))
    print('LENS_INTERFACES1J_VERIFIED_JSON_END')


if __name__ == '__main__':
    main()
