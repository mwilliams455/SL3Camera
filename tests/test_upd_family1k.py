#!/usr/bin/env python3
import hashlib,struct,sys,tempfile,unittest,zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_inspect import XOR_FF,FormatError
from sl3p_upd_family1k import inspect_family

def fixture(marker=b'leica\0',invert=False,bad_nested=False):
    start=0x400;b=bytearray(start+16)
    b[:4]=b'UPD\0';b[12:18]=b'TEST01';b[0x200:0x200+len(marker)]=marker
    b[0x2a0:0x2a4]=b'BAD!' if bad_nested else b'UPD\0';b[0x2ac:0x2b2]=b'TEST01'
    struct.pack_into('<III',b,0x38,0x200,len(b)-0x200,0)
    struct.pack_into('<III',b,0x2e0,start-0x200,16,1)
    at=0x2ec;b[at:at+4]=b'data';struct.pack_into('<4I',b,at+12,start-0x200,16,0,2)
    payload=b'Z'*16;b[at+28:at+60]=hashlib.sha256(payload).digest();b[start:start+16]=payload
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
    out=bytes(b)
    return out.translate(XOR_FF) if invert else out

class Tests(unittest.TestCase):
    def runf(self,data):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'f.bin';p.write_bytes(data);return inspect_family(p)
    def test_accepts_leica_marker_and_inversion(self):
        r=self.runf(fixture(invert=True));self.assertEqual(r['outer_transform'],'XOR_FF');self.assertEqual(r['internal_identifier'],'TEST01')
    def test_accepts_non_leica_marker(self):
        r=self.runf(fixture(marker=b'\0'*6));self.assertEqual(r['brand_marker_0x200_hex'][:12],'000000000000')
    def test_rejects_bad_nested_header(self):
        with self.assertRaises(FormatError):self.runf(fixture(bad_nested=True))
if __name__=='__main__':unittest.main()
