import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
from sl3p_q3_boot_map1k import parse_boot_addresses,map_sections,mapping_relationships

CFG="""
CONFIG_SYS_TEXT_BASE=0x400180000
# KERNEL_ADDRESS :  0x403700000
# ZKERNEL_ADDRESS: 0x400200000
# DTB_ADDRESS    : 0x401290000
"""
SECTIONS=[
 {"index":0,"name":"boot","target_offset_unconfirmed":0,"size":0},
 {"index":1,"name":"loader1","target_offset_unconfirmed":0,"size":0x20000},
 {"index":5,"name":"program","target_offset_unconfirmed":0x80000,"size":0x2cc0000},
 {"index":6,"name":"compress_pr","target_offset_unconfirmed":0x2d40000,"size":0x1000000},
]

class BootMap1KTests(unittest.TestCase):
    def test_parse_exact_addresses(self):
        a=parse_boot_addresses(CFG)
        self.assertEqual(a["uboot"],0x400180000)
        self.assertEqual(a["zkernel"],0x400200000)
        self.assertEqual(a["kernel"],0x403700000)
        self.assertEqual(a["dtb"],0x401290000)

    def test_missing_address_fails_closed(self):
        with self.assertRaises(ValueError):
            parse_boot_addresses("CONFIG_SYS_TEXT_BASE=0x1")

    def test_section_mapping(self):
        a=parse_boot_addresses(CFG)
        rows=map_sections(SECTIONS,a["uboot"])
        self.assertEqual(rows[1]["mapped_from_uboot_base"],0x400180000)
        self.assertEqual(rows[2]["mapped_from_uboot_base"],0x400200000)
        self.assertEqual(rows[3]["mapped_from_uboot_base"],0x402ec0000)

    def test_relationships(self):
        a=parse_boot_addresses(CFG)
        rel=mapping_relationships(map_sections(SECTIONS,a["uboot"]),a)
        self.assertEqual(rel["zkernel_minus_uboot"],0x80000)
        self.assertTrue(rel["loader1_maps_to_uboot"])
        self.assertTrue(rel["program_maps_to_zkernel"])
        self.assertEqual(rel["dtb_relative_to_program_start"],0x1090000)
        self.assertTrue(rel["dtb_inside_program"])
        self.assertEqual(rel["program_end"],0x402ec0000)
        self.assertEqual(rel["kernel_minus_uboot"],0x3580000)

    def test_dtb_outside_program_detected(self):
        a=parse_boot_addresses(CFG)
        a=dict(a,dtb=0x500000000)
        rel=mapping_relationships(map_sections(SECTIONS,a["uboot"]),a)
        self.assertFalse(rel["dtb_inside_program"])

    def test_negative_mapping_rejected(self):
        with self.assertRaises(ValueError):
            map_sections(SECTIONS,-1)
        bad=[dict(SECTIONS[0],target_offset_unconfirmed=-1)]
        with self.assertRaises(ValueError):
            map_sections(bad,0)

    def test_missing_required_section_rejected(self):
        a=parse_boot_addresses(CFG)
        with self.assertRaises(ValueError):
            mapping_relationships(map_sections(SECTIONS[:2],a["uboot"]),a)

if __name__=="__main__":
    unittest.main()
