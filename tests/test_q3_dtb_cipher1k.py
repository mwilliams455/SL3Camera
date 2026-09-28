#!/usr/bin/env python3
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_q3_dtb_cipher1k import lag_equal_fraction,repeated_plain_block_test,metadata_relation

class Tests(unittest.TestCase):
 def test_lag_detector_finds_period(self):
  d=b'ABCD'*100
  self.assertEqual(lag_equal_fraction(d,4),1.0)
  self.assertLess(lag_equal_fraction(d,3),0.1)
 def test_repeated_plain_blocks_detect_ecb_like_relation(self):
  p=b'A'*16+b'B'*16+b'A'*16
  c=b'X'*16+b'Y'*16+b'X'*16
  r=repeated_plain_block_test(p,c)
  self.assertEqual(r['comparison_pairs'],1);self.assertEqual(r['equal_ciphertext_pairs'],1)
 def test_repeated_plain_blocks_detect_non_ecb(self):
  p=b'A'*16+b'A'*16
  c=b'X'*16+b'Z'*16
  r=repeated_plain_block_test(p,c)
  self.assertEqual(r['equal_ciphertext_pairs'],0)
 def test_metadata_relation(self):
  meta=bytes(range(16));stream=meta*4
  r=metadata_relation(stream,meta)
  self.assertEqual(r['direct']['fraction'],1.0)
if __name__=='__main__':unittest.main()
