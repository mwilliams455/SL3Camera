import hashlib
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_lineage_probe1f import (views, entropy, outline, padded_matches,
                                 match_summary, inspect_bytes, SOURCES)
from sl3p_inspect import XOR_FF
from sl3p_loader_source_probe import approved


def row(index, payload, stored=None, flag=3):
    h = hashlib.sha256(payload).hexdigest()
    return [index, 'test', len(payload), flag, h, stored or h, '0'*64]


class LineageTests(unittest.TestCase):
    def test_views_raw(self):
        self.assertEqual(views(b'abcd')[0], 'raw_unknown')
    def test_views_normal(self):
        self.assertEqual(views(b'UPD\0xxx'), ('already_normalized', b'UPD\0xxx'))
    def test_views_inverted(self):
        self.assertEqual(views(b'UPD\0xxx'.translate(XOR_FF)), ('outer_XOR_FF', b'UPD\0xxx'))
    def test_entropy_fill(self):
        self.assertEqual(entropy(b'x'*100), 0)
    def test_entropy_empty(self):
        self.assertEqual(entropy(b''), 0)
    def test_entropy_uniform(self):
        self.assertEqual(entropy(bytes(range(256))), 8)
    def test_outline_no_payload_strings(self):
        b = b'xxxx confidential-DO-NOT-PUBLISH encrypt here'
        r = outline(b)
        self.assertNotIn('confidential', json.dumps(r))
        self.assertEqual(r['terms']['encrypt']['count'], 1)
    def test_outline_bounds(self):
        with self.assertRaises(ValueError): outline(b'')
    def test_unknown_not_validated(self):
        r = inspect_bytes(b'UPD\0'+b'A'*1024, {'sections': []})
        self.assertEqual(r['status'], 'strict_UPD_not_validated')
    def test_exact_match(self):
        m = padded_matches(b'abc', {'sections': [row(1,b'abc')]})
        self.assertEqual(len(m), 1)
        self.assertIsNone(m[0]['trailing_fill'])
    def test_trailing_ff(self):
        m = padded_matches(b'abc', {'sections': [row(3,b'abc'+b'\xff'*20)]})
        self.assertEqual(m[0]['trailing_fill'], 255)
    def test_trailing_zero(self):
        m = padded_matches(b'abc', {'sections': [row(3,b'abc'+b'\0'*20)]})
        self.assertEqual(m[0]['trailing_fill'], 0)
    def test_complement_match(self):
        m = padded_matches(b'abc'.translate(XOR_FF), {'sections': [row(3,b'abc')]})
        self.assertEqual(m[0]['view'], 'XOR_FF')
    def test_no_prefix_only(self):
        self.assertEqual(padded_matches(b'abcd', {'sections': [row(1,b'abcdx')]}), [])
    def test_no_truncation(self):
        self.assertEqual(padded_matches(b'abcd', {'sections': [row(1,b'abc')]}), [])
    def test_clear_target_excluded(self):
        self.assertEqual(padded_matches(b'abc', {'sections': [row(1,b'abc',flag=2)]}), [])
    def test_pairs_count(self):
        a = {'sections':[row(1,b'abc','1'*64),row(2,b'abc','1'*64)]}
        b = {'sections':[row(3,b'abc','2'*64),row(4,b'abc','2'*64)]}
        r = match_summary(a,b)
        self.assertEqual(len(r['protected_pairs']), 4)
        self.assertEqual(r['distinct_baseline_protected_count'], 2)
        self.assertEqual(r['clear_counterpart_pairs'], [])
    def test_readable_counterpart(self):
        a = {'sections':[row(1,b'abc','1'*64)]}
        b = {'sections':[row(3,b'abc',flag=2)]}
        r = match_summary(a,b)
        self.assertEqual(len(r['clear_counterpart_pairs']), 1)
    def test_all_sources_approved(self):
        self.assertTrue(all(approved(u) for u in SOURCES.values()))

if __name__ == '__main__': unittest.main()
