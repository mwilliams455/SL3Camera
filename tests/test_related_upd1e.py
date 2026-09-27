import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_related_upd_probe import Links, compare

class RelatedTests(unittest.TestCase):
    def test_vendor_links_only(self):
        p = Links(); p.feed('<a href="/sites/default/files/SL3.lfu">a</a><a href="https://evil.com/x.lfu">x</a>')
        self.assertEqual(p.urls, ['https://leica-camera.com/sites/default/files/SL3.lfu'])
    def test_duplicates(self):
        p = Links(); p.feed('<a href="/x.lfu">x</a>' * 2)
        self.assertEqual(len(p.urls), 1)
    def test_keep_duplicate_names(self):
        a = {'sections': [[1,'postboot',16,3,'H','a','b'],[2,'postboot',16,3,'H','c','d']]}
        b = {'sections': [[9,'postboot',16,3,'H','a','b']]}
        r = compare(a,b)['same_size_expected_hash_pairs']
        self.assertEqual(len(r),2); self.assertTrue(r[0]['stored_bytes_hash_equal'])
        self.assertFalse(r[1]['stored_bytes_hash_equal'])
    def test_no_empty_match(self):
        a = {'sections': [[1,'boot',0,2,'H','a','b']]}
        self.assertEqual(compare(a,a)['same_size_expected_hash_pairs'], [])
    def test_size_required(self):
        a = {'sections': [[1,'boot',16,3,'H','a','b']]}
        b = {'sections': [[1,'boot',32,3,'H','a','b']]}
        self.assertEqual(compare(a,b)['same_size_expected_hash_pairs'], [])

if __name__ == '__main__': unittest.main()
