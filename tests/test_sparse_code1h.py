from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_sparse_code1h import SparseImage,literal,vector_tables

class SparseTests(unittest.TestCase):
    def test_holes_not_synthesized(self):
        image=SparseImage([(0,b'AB'),(100,b'CD')])
        self.assertIsNone(image.read(2,1))
        self.assertIsNone(image.read(1,2))
        self.assertEqual(image.read(100,2),b'CD')

    def test_high_address_does_not_allocate_span(self):
        image=SparseImage([(0,b'A'),(0xffffffff,b'B')])
        self.assertEqual(image.read(0xffffffff,1),b'B')
        self.assertEqual(sum(len(b) for _,b in image.regions),2)

    def test_overlap_rejected(self):
        with self.assertRaises(ValueError):SparseImage([(0,b'AB'),(1,b'C')])

    def test_find_and_bounds(self):
        image=SparseImage([(0,b'ABA'),(100,b'ABA')])
        self.assertEqual(image.find(b'A'),[0,2,100,102])
        self.assertIsNone(image.read(-1,1))
        self.assertIsNone(image.read(0,0))
        with self.assertRaises(ValueError):image.find(b'')

    def test_t1_literal_sparse(self):
        image=SparseImage([(0x8000,bytes.fromhex('01480000')),(0x8008,struct.pack('<I',0x41458))])
        self.assertEqual(literal(image,0x8000)['value'],0x41458)
        self.assertEqual(literal(image,0x8000)['pool_address'],0x8008)

    def test_missing_pool_not_zero(self):
        image=SparseImage([(0x8000,bytes.fromhex('0148'))])
        self.assertIsNone(literal(image,0x8000))

    def test_t2_positive_and_negative(self):
        image=SparseImage([(0x8000,bytes.fromhex('dff8042000000000')+struct.pack('<I',123))])
        self.assertEqual(literal(image,0x8000)['value'],123)
        image=SparseImage([(0x8000,bytes.fromhex('5ff80420'))])
        self.assertEqual(literal(image,0x8000)['pool_address'],0x8000)

    def test_vector_map_crosses_disjoint_regions(self):
        words=[0x20001000]+[0x8001]*15
        for i in (7,8,9,10,13):words[i]=0
        image=SparseImage([(0,struct.pack('<16I',*words)),(0x8000,b'\x70\x47')])
        self.assertEqual(vector_tables(image)[0]['reset_address'],0x8000)
        image=SparseImage([(0,struct.pack('<16I',*words))])
        self.assertEqual(vector_tables(image),[])
