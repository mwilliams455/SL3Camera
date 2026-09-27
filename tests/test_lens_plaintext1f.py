from pathlib import Path
import sys
import hashlib
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_lens_plaintext1f import reconstruct, structure

class LensPlaintextTests(unittest.TestCase):
    def args(self,d=b'LENS\x01\x02',size=64):
        return dict(source_hash=hashlib.sha256(d).hexdigest(), source_size=len(d),
                    target_size=size, target_hash=hashlib.sha256(d+b'\0'*(size-len(d))).hexdigest())
    def test_full_hash(self):
        d=b'LENS\x01\x02'; plain,r=reconstruct(d,**self.args(d))
        self.assertEqual(len(plain),64)
        self.assertTrue(r['complete_expected_hash_matches'])
        self.assertFalse(r['payload_decryption_performed'])
    def test_wrong_source(self):
        d=b'LENS\x01\x02'
        with self.assertRaises(ValueError): reconstruct(d+b'x',**self.args(d))
    def test_wrong_target(self):
        d=b'LENS\x01\x02'; a=self.args(d); a['target_hash']='0'*64
        with self.assertRaises(ValueError): reconstruct(d,**a)
    def test_wrong_magic(self):
        d=b'XXXX\x01\x02'
        with self.assertRaises(ValueError): reconstruct(d,**self.args(d))
    def test_invalid_bounds(self):
        d=b'LENS\x01\x02'; a=self.args(d); a['target_size']=3
        with self.assertRaises(ValueError): reconstruct(d,**a)
    def test_no_string_dump(self):
        r=structure(b'LENS'+bytes(32)+b'fwupdate private-sensitive')
        self.assertNotIn('private-sensitive',str(r))
        self.assertEqual(r['term_hits']['fwupdate']['count'],1)
    def test_short_magic_candidate(self):
        r=structure(b'LENS')
        self.assertEqual(r['lens_magic']['count'],1)
        self.assertEqual(r['header_candidates'],[])
    def test_header_numeric_candidates(self):
        r=structure(b'LENS'+(32).to_bytes(4,'little')+bytes(24))
        self.assertEqual(r['header_candidates'][0]['word_values_equal_remaining_file_bytes'],[4])

if __name__=='__main__': unittest.main()
