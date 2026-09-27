import hashlib
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_pair_probe1e import canonical_sha, check_digest, content_summary

class PairProbeTests(unittest.TestCase):
    def test_pin_accepts_and_rejects(self):
        check_digest(b'abc', hashlib.sha256(b'abc').hexdigest())
        with self.assertRaises(ValueError): check_digest(b'abd', hashlib.sha256(b'abc').hexdigest())
    def test_canonical_data_change(self):
        self.assertEqual(canonical_sha({'a':1}), canonical_sha({'a':1}))
        self.assertNotEqual(canonical_sha({'a':1}), canonical_sha({'a':2}))
    def test_pairs_not_overcounted_as_sections(self):
        a = {'sections': [[19,'a',512,3,'H','a','b'],[20,'b',512,3,'H','c','d']]}
        b = {'sections': [[19,'a',512,3,'H','e','f'],[20,'b',512,3,'H','g','h']]}
        r = content_summary(a,b)
        self.assertEqual(len(r['same_expected_content_protected_pairs']),4)
        self.assertEqual(r['matched_protected_sections'],2)
        self.assertEqual(r['matched_protected_excluding_known_ff_stored_bytes'],1024)
    def test_no_matches_not_vacuous_success(self):
        a = {'sections': [[1,'a',16,3,'H','a','b']]}
        b = {'sections': [[1,'a',32,3,'X','c','d']]}
        r = content_summary(a,b)
        self.assertFalse(r['all_protected_matches_have_different_stored_hashes'])
        self.assertEqual(r['unmatched_protected_section_names'], ['a'])
        self.assertEqual(r['same_name_size_changes'][0]['sl3_bytes'],32)

if __name__ == '__main__': unittest.main()
