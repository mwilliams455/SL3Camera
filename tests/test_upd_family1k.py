#!/usr/bin/env python3
import hashlib,struct,sys,tempfile,unittest,zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_inspect import XOR_FF,FormatError
from sl3p_upd_family1k import inspect_family

def fixture(marker=b'leica\\0',invert=False,bad_nested=False,legacy=False):
    start=0x400;b=bytearray(start+16)
    b[:4]=b'UPD\\0';b[12:18]=b'TEST01';b[0x200:0x200+len(marker)]=marker
    b[0x2a0:0x2a4]=b'BAD!' if bad_nested else b'UPD\\0';b[0x2ac:0x2b2]=b'TEST01'
    struct.pack_into('<III',b,0x38,0x200,len(b)-0x200,0)
    struct.pack_into('<III',b,0x2e0,0 if legacy else start-0x200,0 if legacy else 16,1)
    at=0x2ec;b[at:at+4]=b'data';struct.pack_into('<4I',b,at+12,start-0x200,16,0,2)
    payload=b'Z'*16;b[at+28:at+60]=hashlib.sha256(payload).digest();b[start:start+16]=payload
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
    out=bytes(b)
    return out.translate(XOR_FF) if invert else out

def legacy_gap_fixture():
    start=0x400;b=bytearray(start+48)
    b[:4]=b'UPD\\0';b[12:18]=b'TEST01';b[0x200:0x209]=b'panasonic'
    b[0x2a0:0x2a4]=b'UPD\\0';b[0x2ac:0x2b2]=b'TEST01'
    struct.pack_into('<III',b,0x38,0x200,len(b)-0x200,0)
    struct.pack_into('<III',b,0x2e0,0,0,2)
    p1=b'A'*16;p2=b'B'*16
    a=0x2ec;b[a:a+5]=b'first';struct.pack_into('<4I',b,a+12,start-0x200,16,0,2);b[a+28:a+60]=hashlib.sha256(p1).digest()
    a+=92;b[a:a+6]=b'second';struct.pack_into('<4I',b,a+12,start-0x200+32,16,16,2);b[a+28:a+60]=hashlib.sha256(p2).digest()
    b[start:start+16]=p1;b[start+32:start+48]=p2
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
    return bytes(b)

class Tests(unittest.TestCase):
    def runf(self,data):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'f.bin';p.write_bytes(data);return inspect_family(p)
    def test_accepts_leica_marker_and_inversion(self):
        r=self.runf(fixture(invert=True))
        self.assertEqual(r['outer_transform'],'XOR_FF')
        self.assertEqual(r['internal_identifier'],'TEST01')
        self.assertEqual(r['directory']['layout'],'modern_explicit')
    def test_accepts_non_leica_marker(self):
        r=self.runf(fixture(marker=b'panasonic\0'))
        self.assertEqual(bytes.fromhex(r['brand_marker_0x200_hex'])[:9],b'panasonic')
    def test_accepts_legacy_nested_layout_by_exact_coverage(self):
        r=self.runf(fixture(marker=b'panasonic\0',legacy=True))
        self.assertEqual(r['directory']['layout'],'legacy_inferred')
        self.assertEqual(r['directory']['declared_data_relative_offset'],0)
        self.assertEqual(r['directory']['declared_data_size'],0)
        self.assertEqual(r['directory']['data_start'],0x400)
        self.assertEqual(r['directory']['data_size'],16)
        self.assertTrue(r['sections'][0]['sha256_matches'])
    def test_rejects_legacy_gap_or_shifted_first_section(self):
        with self.assertRaises(FormatError):
            self.runf(legacy_gap_fixture())
    def test_rejects_bad_nested_header(self):
        with self.assertRaises(FormatError):self.runf(fixture(bad_nested=True))
if __name__=='__main__':unittest.main()
