"""Synthetic tests; no firmware, network or Capstone dependency."""
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_sparse_code1h import SparseImage
from sl3p_lens_interfaces1j import scan_literals, window
from sl3p_lens_destination1j import method_entries, relocate_known_ranges

class TableTests(unittest.TestCase):
    def setUp(self):
        self.image=SparseImage([(0x100,struct.pack('<4I',0x801,0x803,0,0x901)),
                                (0x800,b'\x70\x47'*2),(0x900,b'\x70\x47')])
    def test_selected_slots(self):
        self.assertEqual(method_entries(self.image,0x100,[0,4,12]),{0:0x800,4:0x802,12:0x900})
    def test_invalid_table(self):
        for address in (-4,0x101,2**32):
            with self.subTest(address=address), self.assertRaises(ValueError):method_entries(self.image,address,[0])
    def test_invalid_slots(self):
        for slots in ([],[0]*17,[-4],[2],[132]):
            with self.subTest(slots=slots), self.assertRaises(ValueError):method_entries(self.image,0x100,slots)
    def test_slot_address_overflow(self):
        with self.assertRaises(ValueError):method_entries(self.image,0xfffffffc,[4])
    def test_missing_table_word(self):
        with self.assertRaises(ValueError):method_entries(self.image,0x100,[16])
    def test_null_and_even_pointer(self):
        for value in (0,0x800):
            image=SparseImage([(0x100,struct.pack('<I',value)),(0x800,b'\x70\x47')])
            with self.subTest(value=value),self.assertRaises(ValueError):method_entries(image,0x100,[0])
    def test_odd_but_unmapped_pointer(self):
        image=SparseImage([(0x100,struct.pack('<I',0x701))])
        with self.assertRaises(ValueError):method_entries(image,0x100,[0])

class RelocationTests(unittest.TestCase):
    def test_complete(self):
        image=SparseImage([(0x100,b'ABCDEFGH')])
        out,report=relocate_known_ranges(image,0x100,0x2000,8)
        self.assertEqual(out.read(0x2000,8),b'ABCDEFGH');self.assertEqual(report['unknown_bytes'],0)
    def test_partial_and_no_invented_bytes(self):
        out,report=relocate_known_ranges(SparseImage([(0x100,b'ABCD')]),0x100,0x2000,12)
        self.assertEqual((report['known_bytes'],report['unknown_bytes']),(4,8))
        self.assertIsNone(out.read(0x2004,1));self.assertIsNone(out.read(0x2000,5))
    def test_holes_preserved(self):
        out,report=relocate_known_ranges(SparseImage([(0x100,b'AB'),(0x105,b'CD')]),0x100,0x2000,8)
        self.assertEqual(out.read(0x2005,2),b'CD');self.assertIsNone(out.read(0x2002,3));self.assertEqual(report['known_bytes'],4)
    def test_intersection_clipped_both_ends(self):
        out,report=relocate_known_ranges(SparseImage([(0x100,b'ABCDEFGH')]),0x102,0x2000,3)
        self.assertEqual(out.read(0x2000,3),b'CDE');self.assertEqual(report['known_bytes'],3)
    def test_missing_all(self):
        out,report=relocate_known_ranges(SparseImage([]),0x100,0x2000,8)
        self.assertEqual(out.regions,[]);self.assertEqual(report['unknown_bytes'],8)
    def test_preserves_zero_data(self):
        out,report=relocate_known_ranges(SparseImage([(0,b'\0'*4)]),0,0x100,4)
        self.assertEqual(out.read(0x100,4),b'\0'*4);self.assertEqual(report['known_bytes'],4)
    def test_invalid_ranges(self):
        for s,d,n in [(-1,0,1),(0,-1,1),(0,0,0),(0,0,-1),(0,0,0x100001),(0xffffffff,0,2),(0,0xffffffff,2)]:
            with self.subTest(args=(s,d,n)),self.assertRaises(ValueError):relocate_known_ranges(SparseImage([]),s,d,n)
    def test_original_unchanged(self):
        original=SparseImage([(0x100,b'ABCD')]);before=list(original.regions)
        relocate_known_ranges(original,0x100,0x2000,4)
        self.assertEqual(original.regions,before)

class LiteralScanTests(unittest.TestCase):
    def setUp(self):
        self.image=SparseImage([(0x8000,bytes.fromhex('0148000000000000')+struct.pack('<I',0x2000ada0))])
    def test_literal_found(self):
        hits=scan_literals(self.image,{0x2000ada0},0x8000,0x8002)
        self.assertEqual(len(hits),1);self.assertEqual(hits[0]['instruction'],0x8000);self.assertTrue(hits[0]['candidate_only'])
    def test_outside_range_not_found(self):
        self.assertEqual(scan_literals(self.image,{0x2000ada0},0x8002,0x8004),[])
    def test_empty_targets(self):self.assertEqual(scan_literals(self.image,set(),0x8000,0x8002),[])
    def test_bad_scan_ranges(self):
        for lo,hi in [(-1,1),(1,1),(2,1),(0,0x100001),(0xffffffff,0x100000001)]:
            with self.subTest(bounds=(lo,hi)),self.assertRaises(ValueError):scan_literals(self.image,set(),lo,hi)
    def test_unmapped_literal_pool(self):
        image=SparseImage([(0x8000,bytes.fromhex('0148'))])
        self.assertEqual(scan_literals(image,{0},0x8000,0x8002),[])
    def test_window_rejects_invalid_before_import(self):
        for lo,hi,n in [(0,0,1),(-1,1,1),(0,1,0),(0,1,513)]:
            with self.subTest(bounds=(lo,hi,n)),self.assertRaises(ValueError):window(self.image,lo,hi,n)

if __name__=='__main__':unittest.main()
