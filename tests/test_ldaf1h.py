from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_ldaf1h import MAGIC,Packet,parse_packets,segments,summarize


def record(address,body):
    count=len(body)+5
    rest=bytes([count])+address.to_bytes(4,'big')+body
    return MAGIC+rest+bytes([(~sum(rest))&255])


def package(*records,tail=b''):
    return MAGIC+b'\x11'+b'\xff'*4+b''.join(records)+tail


class LdafTests(unittest.TestCase):
    def test_two_packets_and_exact_bytes(self):
        p,r=parse_packets(package(record(0,b'AB'),record(2,b'CD')))
        self.assertEqual(segments(p),[(0,b'ABCD')])
        self.assertEqual(r['packet_count'],2)
        self.assertTrue(r['all_packet_checksums_verified'])

    def test_big_endian_sparse_addresses(self):
        p,r=parse_packets(package(record(0x10000,b'A'),record(0xfffe0000,b'B')))
        self.assertEqual(segments(p),[(0x10000,b'A'),(0xfffe0000,b'B')])

    def test_marker_inside_data_not_split(self):
        p,_=parse_packets(package(record(0,b'X'+MAGIC+b'Y')))
        self.assertEqual(len(p),1)
        self.assertEqual(p[0].data,b'X'+MAGIC+b'Y')

    def test_checksum_failure(self):
        b=bytearray(package(record(0,b'hello')))
        b[-1]^=1
        with self.assertRaises(ValueError): parse_packets(bytes(b))

    def test_truncated_record(self):
        with self.assertRaises(ValueError): parse_packets(package(record(0,b'A'))[:-1])

    def test_prologue_rejected(self):
        with self.assertRaises(ValueError): parse_packets(b'NOPE')
        with self.assertRaises(ValueError): parse_packets(MAGIC+b'\x11'+b'\0'*4+record(0,b'A'))

    def test_prologue_only_rejected(self):
        with self.assertRaises(ValueError): parse_packets(package())

    def test_zero_data_record_preserved(self):
        p,r=parse_packets(package(record(0x1000,b'')))
        self.assertEqual(r['no_data_packet_addresses'],[0x1000])
        self.assertEqual(segments(p),[])

    def test_overlap_rejected(self):
        p,_=parse_packets(package(record(0,b'AB'),record(1,b'C')))
        with self.assertRaises(ValueError): segments(p)

    def test_long_trailer_rejected(self):
        with self.assertRaises(ValueError): parse_packets(package(record(0,b'AB'),tail=b'Z'*17))

    def test_short_trailer_reported_not_verified(self):
        p,r=parse_packets(package(record(0,b'AB'),tail=b'END!'))
        self.assertEqual(r['trailer_hex'],b'END!'.hex())
        self.assertFalse(r['trailer_semantics_verified'])

    def test_overflow_rejected(self):
        with self.assertRaises(ValueError): parse_packets(package(record(0xffffffff,b'AB')))

    def test_count_too_short(self):
        with self.assertRaises(ValueError): parse_packets(package(MAGIC+b'\x04'+b'\0'*4))

    def test_summary_does_not_dump_data(self):
        image,r=summarize(package(record(0,b'private_fixture\0fwupdate\0')))
        self.assertNotIn('private_fixture',str(r))
        self.assertEqual(r['segments'][0]['fwupdate_address'],16)
