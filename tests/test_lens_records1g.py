import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_lens_records1g import SOF, EOH, RECORD, parse_layout, audit, crc32_msb


def fixture() -> bytes:
    a,b = b'first synthetic payload', b'Other payload'
    start = 31+4*19+len(EOH)
    header = SOF+struct.pack('>HHBBHH',1,2026,9,27,11,4)
    rows = [(0,0,0x20010200,start,len(a),zlib.crc32(a)),
            (1,0,0x20020200,start,len(a),zlib.crc32(a)),
            (2,1,0x20030100,start+len(a),len(b),zlib.crc32(b)),
            (3,2,0x20040000,0,0,0)]
    return header+b''.join(RECORD.pack(*r) for r in rows)+EOH+a+b


class LensRecordsTests(unittest.TestCase):
    def test_complete_coverage_and_aliases(self):
        r = audit(fixture())
        self.assertEqual((r['record_count'],r['empty_records'],r['unique_payload_count']),(4,1,2))
        self.assertEqual(r['payloads'][0]['record_indexes'],[0,1])
        self.assertEqual(r['checksum_consensus'],['crc32_iso_hdlc'])
    def test_crc_reference_vector(self):
        self.assertEqual(crc32_msb(b'123456789'),0x0376e6e7)
        self.assertEqual(crc32_msb(b''),0xffffffff)
    def test_magic(self):
        with self.assertRaises(ValueError): parse_layout(b'BAD'+fixture()[3:])
    def test_count(self):
        d=bytearray(fixture());d[29:31]=b'\0\0'
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_eoh(self):
        d=bytearray(fixture());d[31+76]=0
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_ordinal(self):
        d=bytearray(fixture());d[32]=10
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_bounds(self):
        d=bytearray(fixture());struct.pack_into('>I',d,31+11,0xffffffff)
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_alias_checksum_disagreement(self):
        d=bytearray(fixture());d[31+19+18]^=1
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_partial_overlap(self):
        d=bytearray(fixture());off=struct.unpack_from('>I',d,31+38+7)[0]
        struct.pack_into('>I',d,31+38+7,off-1)
        with self.assertRaises(ValueError):parse_layout(bytes(d))
    def test_unexplained_tail(self):
        with self.assertRaises(ValueError):parse_layout(fixture()+b'\0')
    def test_corruption_has_no_checksum_consensus(self):
        d=bytearray(fixture());d[-1]^=1
        self.assertEqual(audit(bytes(d))['checksum_consensus'],[])
    def test_no_payload_in_report(self):
        self.assertNotIn('first synthetic payload',str(audit(fixture())))
    def test_no_input_mutation(self):
        data=fixture();h=hashlib.sha256(data).digest();audit(data)
        self.assertEqual(hashlib.sha256(data).digest(),h)


if __name__ == '__main__': unittest.main()
