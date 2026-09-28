import unittest,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_sl3s_compare1k as m

class SL3PSL3SCompare1KTests(unittest.TestCase):
    def test_duplicate_matching_is_consumed_once(self):
        b=[{"index":1,"name":"x","size":4,"flags":3,"expected_sha256":"aa"},
           {"index":2,"name":"x","size":4,"flags":3,"expected_sha256":"aa"}]
        o=[{"index":9,"name":"x","size":4,"flags":3,"expected_sha256":"aa","target":0}]
        r=m.compare(b,o)
        self.assertEqual(sum(x["same_name_content_sl3s"] for x in r),1)
    def test_different_size_does_not_match(self):
        b=[{"index":1,"name":"x","size":4,"flags":3,"expected_sha256":"aa"}]
        o=[{"index":9,"name":"x","size":8,"flags":3,"expected_sha256":"aa","target":0}]
        self.assertFalse(m.compare(b,o)[0]["same_name_content_sl3s"])
    def test_different_hash_does_not_match(self):
        b=[{"index":1,"name":"x","size":4,"flags":3,"expected_sha256":"aa"}]
        o=[{"index":9,"name":"x","size":4,"flags":3,"expected_sha256":"bb","target":0}]
        self.assertFalse(m.compare(b,o)[0]["same_name_content_sl3s"])

if __name__=="__main__":unittest.main()
