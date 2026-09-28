import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_q3_s1rm2_oss_compare1k as m

class OSSCompare1KTests(unittest.TestCase):
    def test_compare(self):
        a={"a":"1","b":"2","c":"3"};b={"b":"2","c":"4","d":"5"}
        r=m.compare(a,b)
        self.assertEqual(r["shared_paths"],2)
        self.assertEqual(r["identical_shared"],1)
        self.assertEqual(r["modified_shared"],1)
        self.assertEqual(r["a_only"],1);self.assertEqual(r["b_only"],1)
        self.assertEqual(r["modified_paths"],["c"])
    def test_compare_empty(self):
        r=m.compare({},{});self.assertEqual(r["shared_paths"],0)
if __name__=="__main__":unittest.main()
