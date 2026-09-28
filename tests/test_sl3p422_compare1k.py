import hashlib,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_sl3p422_compare1k as m

class Compare422Tests(unittest.TestCase):
    def fake(self,stored="aa",payload="bb",name="program",size=4,flags=3,index=5):
        return {"index":index,"name":name,"size":size,"target_offset_unconfirmed":0x80000,"flags":flags,
                "stored_sha256":stored,"payload_sha256_after_outer_transform":payload,
                "unknown_16_bytes":"00"*16}
    def base(self,expected="aa",stored="bb",name="program",size=4,flags=3,index=5):
        return {index:{"index":index,"name":name,"size":size,"flags":flags,
                       "expected_sha256":expected,"stored_payload_sha256":stored,"metadata16_sha256":"x"}}
    def test_same_expected_same_stored(self):
        r=m.compare({"sections":[self.fake()]},self.base())
        self.assertEqual(r["counts"]["same_expected_same_stored"],1)
    def test_same_expected_different_stored(self):
        r=m.compare({"sections":[self.fake(payload="cc")]},self.base())
        self.assertEqual(r["counts"]["same_expected_different_stored"],1)
    def test_changed_expected(self):
        r=m.compare({"sections":[self.fake(stored="cc")]},self.base())
        self.assertEqual(r["counts"]["changed_expected"],1)
    def test_reindexed(self):
        r=m.compare({"sections":[self.fake(name="other")]},self.base())
        self.assertEqual(r["counts"]["missing_or_reindexed"],1)
    def test_metadata_hash_is_full_16_bytes(self):
        r=m.compare({"sections":[self.fake()]},self.base())
        self.assertEqual(r["rows"][0]["metadata16_sha256_422"],hashlib.sha256(bytes(16)).hexdigest())
if __name__=="__main__":unittest.main()
