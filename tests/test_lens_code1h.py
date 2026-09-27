from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_lens_code1h import file_offset, literal_load, string_references, wrapper_candidates


class CodeHelpersTests(unittest.TestCase):
    def test_mapping(self):
        self.assertEqual(file_offset(0x8008,0x8000,20,100,4),28)
        self.assertIsNone(file_offset(0x7fff,0x8000,20,100))
        self.assertIsNone(file_offset(0x8050,0x8000,20,100))
        self.assertIsNone(file_offset(0x804f,0x8000,20,100,4))

    def test_t1_literal(self):
        d=bytearray(100)
        struct.pack_into('<H',d,20,0x4901)
        self.assertEqual(literal_load(bytes(d),20,0x8000,20),(1,28,2))

    def test_t2_positive(self):
        d=bytearray(100)
        struct.pack_into('<HH',d,20,0xf8df,0x2004)
        self.assertEqual(literal_load(bytes(d),20,0x8000,20),(2,28,4))

    def test_t2_negative(self):
        d=bytearray(100)
        struct.pack_into('<HH',d,20,0xf85f,0x2004)
        self.assertEqual(literal_load(bytes(d),20,0x8000,20),(2,20,4))

    def test_bounds_and_alignment(self):
        self.assertIsNone(literal_load(b'\0'*100,21,0x8000,20))
        self.assertIsNone(literal_load(b'\0'*100,99,0x8000,20))
        self.assertIsNone(literal_load(b'\0'*100,18,0x8000,20))

    def test_string_reference(self):
        d=bytearray(100)
        struct.pack_into('<H',d,20,0x4801)
        struct.pack_into('<I',d,28,0x8000+64-20)
        d[64:73]=b'fwupdate\0'
        result=string_references(bytes(d),0x8000,20)
        self.assertEqual(result['pointer_offsets'],[28])
        self.assertEqual(result['literal_loads'][0]['instruction_offset'],20)

    def test_missing_string(self):
        self.assertEqual(string_references(b'\0'*100,0x8000,20)['literal_loads'],[])

    def test_wrapper_is_candidate_not_validator(self):
        d=b'LDAFR'+bytes([17])+b'\xff'*4
        self.assertEqual(wrapper_candidates(d)[0]['tag_byte'],82)
        self.assertEqual(wrapper_candidates(d)[0]['u32le_at_6'],0xffffffff)
        self.assertEqual(wrapper_candidates(d[:9]),[])
        self.assertEqual(wrapper_candidates(b'OTHER'+b'\0'*20),[])
