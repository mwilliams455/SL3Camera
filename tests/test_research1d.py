#!/usr/bin/env python3
"""Controlled tests for relationship auditing and conservative loader triage."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import sl3p_cross_section as cross
import sl3p_loader_triage as loader
import sl3p_inspect as upd

A = bytes(range(16))
B = bytes(range(16, 32))
C = bytes(range(32, 48))
D = bytes(range(48, 64))
FIELD = bytes(range(128, 144))


def fixture(parts, invert=False):
    """Parts: (name, bytes, flag, optional alternative expected plaintext)."""
    data_start = (upd.DIRECTORY + len(parts)*upd.STRIDE + 511) // 512 * 512
    total = sum(len(p[1]) for p in parts)
    b = bytearray(data_start + total)
    b[:4] = b'UPD\0'
    b[12:18] = b'TEST1D'
    b[0x200:0x206] = b'leica\0'
    b[0x2a0:0x2a4] = b'UPD\0'
    b[0x2ac:0x2b2] = b'TEST1D'
    struct.pack_into('<III', b, 0x38, 0x200, len(b)-0x200, 0)
    struct.pack_into('<III', b, 0x2e0, data_start-0x200, total, len(parts))
    offset = data_start
    for i, (name, content, flags, expected) in enumerate(parts):
        at = upd.DIRECTORY + i*upd.STRIDE
        name = name.encode('ascii')
        b[at:at+len(name)] = name
        struct.pack_into('<4I', b, at+12, offset-0x200, len(content), i*65536, flags)
        b[at+28:at+60] = hashlib.sha256(content if expected is None else expected).digest()
        if flags == 3:
            b[at+60:at+76] = FIELD
        b[offset:offset+len(content)] = content
        offset += len(content)
    struct.pack_into('<I', b, 0x40, zlib.crc32(b[0x200:]) & 0xffffffff)
    return bytes(b).translate(upd.XOR_FF) if invert else bytes(b)


class CrossSectionTests(unittest.TestCase):
    def test_all_distinct(self):
        r = cross.audit_blocks([(0, 'a', A+B, FIELD), (1, 'b', C+D, FIELD)])
        self.assertEqual((r['aligned_blocks'], r['distinct_block_values']), (4, 4))
        self.assertEqual(r['cross_section_shared_block_values'], 0)
        self.assertEqual(r['metadata_matches'], [])

    def test_different_positions_and_duplicate_names(self):
        r = cross.audit_blocks([(2, 'same', A+B, FIELD), (7, 'same', C+A, FIELD)])
        self.assertEqual(r['cross_section_equal_block_pairs'], 1)
        self.assertEqual(r['cross_section_examples'][0]['locations'],
                         [{'index': 2, 'name': 'same', 'relative_offset': 0},
                          {'index': 7, 'name': 'same', 'relative_offset': 16}])

    def test_within_and_across_multiplicity(self):
        r = cross.audit_blocks([(0, 'a', A+A+B, FIELD), (1, 'b', A+A+A, FIELD)])
        self.assertEqual(r['within_section_equal_block_pairs'], 4)
        self.assertEqual(r['cross_section_equal_block_pairs'], 6)
        self.assertEqual(r['cross_section_shared_block_values'], 1)
        self.assertEqual(r['distinct_block_values'], 2)

    def test_within_section_only_is_not_cross(self):
        r = cross.audit_blocks([(0, 'a', A+A+B, FIELD)])
        self.assertEqual(r['cross_section_equal_block_pairs'], 0)
        self.assertEqual(r['within_section_equal_block_pairs'], 1)

    def test_multiple_shared_values(self):
        r = cross.audit_blocks([(0, 'a', A+B+C, FIELD), (1, 'b', B+A+D, FIELD)])
        self.assertEqual(r['cross_section_shared_block_values'], 2)
        self.assertEqual(r['section_pair_matches'][0]['shared_block_values'], 2)

    def test_one_byte_difference_is_not_match(self):
        x = bytearray(A); x[-1] ^= 1
        r = cross.audit_blocks([(0, 'a', A, FIELD), (1, 'b', bytes(x), FIELD)])
        self.assertEqual(r['cross_section_equal_block_pairs'], 0)

    def test_metadata_inside_different_section(self):
        r = cross.audit_blocks([(0, 'a', A, FIELD), (1, 'b', B+FIELD, D)])
        hits = [m for m in r['metadata_matches'] if m['convention'] == 'reverse_words_1B']
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]['metadata_owner_index'], 0)
        self.assertEqual(hits[0]['locations'][0]['index'], 1)
        self.assertEqual(hits[0]['locations'][0]['relative_offset'], 16)

    def test_transformed_metadata_detected(self):
        value = cross.field_conventions(FIELD)['reverse_words_4B_xor_ff']
        r = cross.audit_blocks([(0, 'a', B+value, FIELD)])
        self.assertTrue(any(m['convention'] == 'reverse_words_4B_xor_ff'
                            for m in r['metadata_matches']))

    def test_unaligned_metadata_is_not_claimed(self):
        data = b'Z'+FIELD+b'Y'*15
        r = cross.audit_blocks([(0, 'a', data, FIELD)])
        self.assertEqual(r['metadata_matches'], [])

    def test_section_relative_alignment(self):
        r = cross.audit_blocks([(2, 'a', A, FIELD), (7, 'b', A, FIELD)])
        self.assertEqual([p['relative_offset'] for p in r['cross_section_examples'][0]['locations']], [0, 0])

    def test_empty(self):
        r = cross.audit_blocks([])
        self.assertEqual(r['aligned_blocks'], 0)
        self.assertEqual(r['distinct_block_values'], 0)

    def test_empty_section_does_not_shift_owner(self):
        r = cross.audit_blocks([(0, 'empty', b'', FIELD), (1, 'b', A, FIELD), (2, 'c', A, FIELD)])
        self.assertEqual([p['index'] for p in r['cross_section_examples'][0]['locations']], [1, 2])

    def test_duplicate_indexes_rejected(self):
        with self.assertRaises(ValueError):
            cross.audit_blocks([(1, 'a', A, FIELD), (1, 'b', B, FIELD)])

    def test_partial_blocks_rejected(self):
        with self.assertRaises(ValueError):
            cross.audit_blocks([(1, 'a', A+b'x', FIELD)])

    def test_bad_metadata_rejected(self):
        with self.assertRaises(ValueError): cross.field_conventions(b'bad')
        with self.assertRaises(ValueError): cross.audit_blocks([(0, 'a', A, b'bad')])

    def test_limits_rejected(self):
        with self.assertRaises(ValueError): cross.audit_blocks([(0, 'a', A, FIELD)], max_bytes=15)
        with self.assertRaises(ValueError): cross.audit_blocks([], max_examples=-1)

    def test_examples_can_be_bounded(self):
        r = cross.audit_blocks([(0, 'a', A+B, FIELD), (1, 'b', A+B, FIELD)], max_examples=1)
        self.assertEqual(len(r['cross_section_examples']), 1)
        self.assertTrue(r['cross_section_examples_truncated'])
        self.assertTrue(r['cross_section_examples'][0]['locations_truncated'])

    def test_json_serializable(self):
        r = cross.audit_blocks([(0, 'a', A+B, FIELD), (1, 'b', A+FIELD, FIELD)])
        self.assertEqual(json.loads(json.dumps(r)), r)


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'fixture.lfu'
    def tearDown(self): self.temp.cleanup()

    def test_readable_nonconstant_loader_is_candidate_only(self):
        self.path.write_bytes(fixture([('loader1', A+B, 2, None)]))
        r = loader.run(self.path)
        self.assertEqual(r['name_suggested_readable_candidate_indexes'], [0])
        self.assertIn('disassembly', ' '.join(r['limitations']))

    def test_empty_and_fill_are_not_code_candidates(self):
        self.path.write_bytes(fixture([('boot', b'', 2, None), ('loader1', b'\xff'*32, 2, None)]))
        self.assertEqual(loader.run(self.path)['name_suggested_readable_candidate_indexes'], [])

    def test_opaque_good_name_is_not_promoted(self):
        self.path.write_bytes(fixture([('loader1', A+B, 3, b'\xff'*32)]))
        self.assertEqual(loader.run(self.path)['name_suggested_readable_candidate_indexes'], [])

    def test_duplicate_loader_names_remain_distinct(self):
        self.path.write_bytes(fixture([('postboot1_r', A, 2, None), ('postboot1_r', B, 2, None)]))
        self.assertEqual(loader.run(self.path)['name_suggested_readable_candidate_indexes'], [0, 1])

    def test_unfamiliar_readable_section_is_retained(self):
        self.path.write_bytes(fixture([('unknown', A+B, 2, None)]))
        r = loader.run(self.path)
        self.assertEqual(r['hash_verified_nonconstant_section_indexes'], [0])
        self.assertEqual(r['name_suggested_readable_candidate_indexes'], [])

    def test_flag3_hash_match_not_automatically_opaque(self):
        self.path.write_bytes(fixture([('loader1', A+B, 3, None)]))
        r = loader.run(self.path)
        self.assertEqual(r['name_suggested_readable_candidate_indexes'], [0])
        self.assertEqual(r['name_suggested_sections'][0]['flags'], 3)

    def test_bad_crc_is_rejected(self):
        b = bytearray(fixture([('loader1', A, 2, None)])); b[-1] ^= 1
        self.path.write_bytes(b)
        with self.assertRaises(upd.FormatError): loader.run(self.path)
        with self.assertRaises(upd.FormatError): cross.run(self.path)

    def test_alternative_format_is_not_silently_accepted(self):
        self.path.write_bytes(b'COMP'+b'\0'*1024)
        with self.assertRaises(upd.FormatError): loader.run(self.path)

    def test_outer_inversion_equivalent(self):
        parts = [('loader1', A+B, 3, b'\xff'*32), ('postboot1_r', C+A, 3, b'\xff'*32)]
        self.path.write_bytes(fixture(parts))
        one = cross.run(self.path)['result']
        self.path.write_bytes(fixture(parts, invert=True))
        two = cross.run(self.path)['result']
        self.assertEqual(one, two)
        self.assertEqual(two['cross_section_equal_block_pairs'], 1)

    def test_read_only_and_cli_refuses_overwrite(self):
        data = fixture([('loader1', A, 2, None)])
        self.path.write_bytes(data)
        for tool in ('sl3p_loader_triage.py', 'sl3p_cross_section.py'):
            completed = subprocess.run([sys.executable, str(ROOT/'tools'/tool),
                str(self.path), '--out', str(self.path)], capture_output=True)
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(self.path.read_bytes(), data)

    def test_cross_run_excludes_clear_padding(self):
        self.path.write_bytes(fixture([('loader1', A+B, 3, b'\xff'*32),
            ('lut_data', b'\0'*64, 2, None), ('clear', A+B, 2, None)]))
        r = cross.run(self.path)['result']
        self.assertEqual(r['sections_audited'], 1)
        self.assertEqual(r['bytes_audited'], 32)


if __name__ == '__main__': unittest.main()
