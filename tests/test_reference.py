#!/usr/bin/env python3
"""Synthetic unit tests. No claim of real-camera / GPU appearance validation."""
import hashlib
import json
import math
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import llog_reference as log
import sl3p_inspect as upd


def make_fixture(invert=True):
    """Original synthetic wrapper, including a duplicate section name."""
    start=0x400
    parts=[('sample',b'\0'*32,2,b'\0'*32),
           ('sample',bytes(range(32)),3,b'\xff'*32)]
    b=bytearray(start+64)
    b[0:4]=b'UPD\0';b[0x0c:0x12]=b'TEST01'
    b[0x200:0x206]=b'leica\0'
    b[0x2a0:0x2a4]=b'UPD\0';b[0x2ac:0x2b2]=b'TEST01'
    struct.pack_into('<III',b,0x38,0x200,len(b)-0x200,0)
    struct.pack_into('<III',b,0x2e0,start-0x200,64,2)
    offset=start
    for i,(name,payload,flags,plain) in enumerate(parts):
        at=0x2ec+i*0x5c
        b[at:at+len(name)]=name.encode()
        struct.pack_into('<4I',b,at+12,offset-0x200,len(payload),0,flags)
        b[at+28:at+60]=hashlib.sha256(plain).digest()
        b[offset:offset+len(payload)]=payload
        offset+=len(payload)
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
    return bytes(b).translate(upd.XOR_FF) if invert else bytes(b)


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'fixture.lfu'
    def tearDown(self): self.temp.cleanup()
    def load(self, data):
        self.path.write_bytes(data)
        return upd.inspect(self.path)
    def test_inverted_wrapper_and_duplicate_names(self):
        r=self.load(make_fixture())
        self.assertEqual(r['outer_transform'],'XOR_FF')
        self.assertEqual(r['counts']['hash_matches'],1)
        self.assertEqual([s['name'] for s in r['sections']],['sample','sample'])
        self.assertEqual(r['sections'][0]['constant_fill_byte'],0)
        self.assertEqual(r['sections'][1]['classification'],'opaque_not_decrypted')
    def test_already_normalized(self):
        self.assertEqual(self.load(make_fixture(False))['outer_transform'],'already_outer_normalized')
    def test_crc_rejects_corruption(self):
        b=bytearray(make_fixture());b[-1]^=1
        with self.assertRaisesRegex(upd.FormatError,'CRC mismatch'): self.load(b)
    def test_size_rejects_truncation(self):
        with self.assertRaises(upd.FormatError): self.load(make_fixture()[:-1])
    def test_magic_rejected(self):
        with self.assertRaises(upd.FormatError): self.load(b'wrong magic')
    def test_section_bounds_rejected_even_with_good_crc(self):
        b=bytearray(make_fixture(False))
        struct.pack_into('<I',b,0x2ec+12,0xffffff00)
        struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
        with self.assertRaises(upd.FormatError): self.load(b)
    def test_safe_distinct_extraction_and_no_overwrite(self):
        r=self.load(make_fixture())
        out=Path(self.temp.name)/'sections'
        upd.extract(self.path,r,out,[0,1])
        self.assertEqual((out/'00_sample.verified.bin').read_bytes(),b'\0'*32)
        self.assertEqual((out/'01_sample.opaque.bin').read_bytes(),bytes(range(32)))
        with self.assertRaises(FileExistsError): upd.extract(self.path,r,out,[0])


class LLogTests(unittest.TestCase):
    def test_black_gray_white(self):
        self.assertEqual(log.encode_lsr(0.0),0.09)
        self.assertAlmostEqual(log.encode_lsr(0.18),0.43531390404392656,places=14)
        self.assertAlmostEqual(log.encode_lsr(0.9),0.6195571060114647,places=14)
    def test_10bit_reference_points(self):
        for x,code in [(0,92),(.02,220),(.18,445),(.9,634),(4.07,814),(8.15,897)]:
            self.assertLess(abs(log.encode_lsr(x)*1023-code),0.5)
    def test_roundtrip_away_from_published_branch_overlap(self):
        samples=[-0.01,0.0,.001,.003,.006]
        samples += [10**(-2+4*i/9999) for i in range(10000)]
        for x in samples:
            self.assertLess(abs(log.decode_llog(log.encode_lsr(x))-x),max(1,abs(x))*2e-14)
    def test_retains_published_branch_discontinuity(self):
        a=log.encode_lsr(.006)
        b=log.encode_lsr(math.nextafter(.006,math.inf))
        self.assertAlmostEqual(a-b,0.0008995265679011,places=14)
        # Not an exact inverse in the small overlapping interval.
        self.assertGreater(abs(log.decode_llog(log.encode_lsr(.00601))-.00601),1e-5)
    def test_matrix_inverse(self):
        for v in [(1,0,0),(0,1,0),(0,0,1),(.2,.3,.4)]:
            got=log.matvec(log.XYZ_D65_TO_RGB2020,log.matvec(log.RGB2020_TO_XYZ_D65,v))
            for a,b in zip(v,got):self.assertAlmostEqual(a,b,places=13)
    def test_d65_neutral_and_explicit_ev(self):
        white=(.3127/.3290,1.0,(1-.3127-.3290)/.3290)
        gray=tuple(x*.18 for x in white)
        for got in log.xyz_d65_to_llog(gray):self.assertAlmostEqual(got,log.encode_lsr(.18),places=13)
        for got in log.xyz_d65_to_llog(gray,1.0):self.assertAlmostEqual(got,log.encode_lsr(.36),places=13)
    def test_bad_input_rejected(self):
        for v in [math.inf,-math.inf,math.nan]:
            with self.assertRaises(ValueError):log.encode_lsr(v)
            with self.assertRaises(ValueError):log.decode_llog(v)
        with self.assertRaises(ValueError):log.xyz_d65_to_llog([1,2])
    def test_no_hidden_clipping(self):
        self.assertLess(log.encode_lsr(-1),0)
        self.assertGreater(log.encode_lsr(100),1)

if __name__=='__main__':
    unittest.main(verbosity=2)
