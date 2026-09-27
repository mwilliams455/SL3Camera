import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_lens_callsite1i import bl_target
from sl3p_lens_semantics1i import ascii_fold
from sl3p_lens_dispatch1i import cstring
from sl3p_sparse_code1h import SparseImage


class CallsiteTests(unittest.TestCase):
    def test_bl_zero_displacement(self):
        self.assertEqual(bl_target(bytes.fromhex('00f000f8'),0x1000),0x1004)

    def test_bl_backward(self):
        self.assertEqual(bl_target(bytes.fromhex('fff7feff'),0x1000),0x1000)

    def test_bl_positive_limit(self):
        self.assertEqual(bl_target(struct.pack('<HH',0xf3ff,0xd7ff),0),0x1000002)

    def test_bl_negative_limit_wrap(self):
        self.assertEqual(bl_target(struct.pack('<HH',0xf400,0xd000),0),0xff000004)

    def test_bl_reject_other_branches(self):
        for s in ('00f000e8','00f000b8','70470000','00000000'):
            self.assertIsNone(bl_target(bytes.fromhex(s),0x1000))

    def test_bl_requires_four_bytes(self):
        for n in range(4):self.assertIsNone(bl_target(b'\0'*n,0))

    def test_bl_reject_bad_address(self):
        for a in (-2,1,0xfffffffc,0x100000000):
            self.assertIsNone(bl_target(bytes.fromhex('00f000f8'),a))

    def test_ascii_fold_all_byte_values(self):
        for x in range(256):
            self.assertEqual(ascii_fold(x),bytes([x]).lower()[0])

    def test_ascii_fold_invalid(self):
        for x in (-1,256,1.5,'A'):
            with self.assertRaises(ValueError):ascii_fold(x)

    def test_ascii_fold_boundaries(self):
        self.assertEqual([ascii_fold(x) for x in (64,65,90,91,96,97,122,123)],
                         [64,97,122,91,96,97,122,123])

    def test_ascii_fold_idempotent(self):
        for x in range(256):self.assertEqual(ascii_fold(ascii_fold(x)),ascii_fold(x))

    def test_cstring_exact(self):
        self.assertEqual(cstring(SparseImage([(32,b'Memory\0')]),32),'Memory')

    def test_cstring_empty(self):
        self.assertEqual(cstring(SparseImage([(32,b'\0')]),32),'')

    def test_cstring_unmapped_terminator(self):
        self.assertIsNone(cstring(SparseImage([(32,b'Memory')]),32))

    def test_cstring_no_hole_fill(self):
        self.assertIsNone(cstring(SparseImage([(32,b'Mem'),(36,b'ory\0')]),32))

    def test_cstring_limit(self):
        image=SparseImage([(32,b'Memory\0')])
        self.assertIsNone(cstring(image,32,6))
        self.assertEqual(cstring(image,32,7),'Memory')

    def test_cstring_nonprintable(self):
        for b in (b'\xff\0',b'A\x01\0'):
            self.assertIsNone(cstring(SparseImage([(32,b)]),32))

    def test_cstring_invalid_limit(self):
        for n in (0,-1,129):
            with self.assertRaises(ValueError):cstring(SparseImage([]),0,n)


if __name__=='__main__':unittest.main()
