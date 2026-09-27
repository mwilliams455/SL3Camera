import hashlib
import struct
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_loader_source_probe import decode_m11, varint, probe, approved


def fixture(body, size):
    header = bytearray(40)
    struct.pack_into('<I', header, 4, 40)
    struct.pack_into('<I', header, 12, size)
    struct.pack_into('<I', header, 20, len(body))
    header[24:40] = hashlib.md5(body).digest()
    return bytes(header) + body


class LoaderSourceTests(unittest.TestCase):
    def test_literals(self):
        out, info = decode_m11(fixture(b'\xffabc', 3))
        self.assertEqual(out, b'abc')
        self.assertTrue(info['packed_md5_matches'])

    def test_overlap(self):
        self.assertEqual(decode_m11(fixture(b'\xffab\xff\x06\x02', 8))[0], b'abababab')

    def test_escape(self):
        self.assertEqual(decode_m11(fixture(b'\xff\xff\x00', 1))[0], b'\xff')

    def test_base128(self):
        self.assertEqual(varint(b'\x81\x80\x00', 0), (16384, 3))

    def test_md5_reject(self):
        d = bytearray(fixture(b'\xffabc', 3)); d[-1] ^= 1
        with self.assertRaises(ValueError): decode_m11(bytes(d))

    def test_truncated_marker(self):
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffab\xff', 3))

    def test_bad_distance(self):
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffab\xff\x06\x03', 8))

    def test_overlong_varint(self):
        with self.assertRaises(ValueError): varint(b'\x80' * 6, 0)

    def test_short_varint(self):
        with self.assertRaises(ValueError): varint(b'\x80', 0)

    def test_limit(self):
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffabc', 3), limit=2)

    def test_size_mismatch(self):
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffabc', 2))
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffabc', 4))

    def test_unexplained_tail(self):
        with self.assertRaises(ValueError): decode_m11(fixture(b'\xffabc', 3) + b'x')

    def test_probe_no_snippet_leak(self):
        d = b'private-secret-decrypt-never-output UPD\0'
        r = probe(d)
        self.assertNotIn('private-secret', str(r))
        self.assertEqual(r['exact_markers']['UPD\\0']['count'], 1)
        self.assertEqual(r['casefolded_terms']['decrypt']['count'], 1)

    def test_approved_hosts(self):
        self.assertTrue(approved('https://leica-camera.com/file.FW'))
        for u in ['http://leica-camera.com/a','https://leica-camera.com.evil/a',
                  'https://user:pass@leica-camera.com/a','https://example.com/a']:
            self.assertFalse(approved(u))


if __name__ == '__main__': unittest.main()
