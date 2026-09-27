import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_lens_inner1h import entropy, vector_candidates, zlib_candidates, srecord_screen, inspect_payload


class InnerTests(unittest.TestCase):
    def vector(self):
        words = [0x20004000] + [0x08000081]*15
        for i in (7,8,9,10,13): words[i] = 0
        return struct.pack('<16I', *words) + b'\0'*192

    def test_entropy_empty(self):
        self.assertEqual(entropy(b''),0)

    def test_entropy_uniform(self):
        self.assertEqual(entropy(bytes(range(256))),8)

    def test_vector_positive(self):
        rows=vector_candidates(self.vector())
        self.assertTrue(any(r['vector_offset']==0 and r['reset_file_offset']==128 and r['reserved_zero_count']==5 for r in rows))

    def test_vector_short(self):
        self.assertEqual(vector_candidates(b'\0'*63),[])

    def test_vector_bad_stack(self):
        data=b'\0'*4+self.vector()[4:]
        self.assertEqual(vector_candidates(data),[])

    def test_vector_bad_reset(self):
        data=self.vector()[:4]+struct.pack('<I',0x08000080)+self.vector()[8:]
        self.assertEqual(vector_candidates(data),[])

    def test_zlib_complete(self):
        raw=b'nonconstant synthetic fixture '*100
        rows=zlib_candidates(b'HEAD'+zlib.compress(raw))
        self.assertEqual(rows[0]['offset'],4)
        self.assertEqual(rows[0]['decoded_sha256'],hashlib.sha256(raw).hexdigest())
        self.assertEqual(rows[0]['trailing_bytes'],0)

    def test_zlib_truncated(self):
        self.assertEqual(zlib_candidates(zlib.compress(b'A'*100)[:-1]),[])

    def test_srecord_valid(self):
        self.assertEqual(srecord_screen(b'S0030000FC\n')['checksum_valid_text_records'],1)

    def test_srecord_invalid(self):
        self.assertEqual(srecord_screen(b'S0030000FD\n')['checksum_valid_text_records'],0)

    def test_only_target_has_opening_fields(self):
        self.assertNotIn('opening_u32le_candidates',inspect_payload(b'\0'*64))

    def test_no_arbitrary_strings(self):
        report=str(inspect_payload(b'PRIVATE_SYNTHETIC_STRING\0'*30))
        self.assertNotIn('PRIVATE_SYNTHETIC_STRING',report)
