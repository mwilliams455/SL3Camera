import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_lineage_matrix1k as m

class LineageMatrix1KTests(unittest.TestCase):
    def row(self,i=1,name="x",size=4,flags=3,expected="aa",target=0):
        return {"index":i,"name":name,"size":size,"flags":flags,"expected":expected,"target":target}
    def test_three_way_shared(self):
        b=[self.row()]; q=[self.row()]; s=[self.row()]; p=[self.row()]
        r=m.classify(b,q,s,p)[0]
        self.assertEqual(r["lineage_class"],"shared_q3_sl3_sl3p")
        self.assertFalse(r["changed_421_to_422"])
    def test_sl3_only_lineage(self):
        b=[self.row()]; q=[]; s=[self.row()]; p=[self.row()]
        self.assertEqual(m.classify(b,q,s,p)[0]["lineage_class"],"shared_sl3_sl3p")
    def test_changed_in_422(self):
        b=[self.row(expected="aa")]; p=[self.row(expected="bb")]
        r=m.classify(b,[],[],p)[0]
        self.assertTrue(r["changed_421_to_422"])
    def test_same_content_different_name_is_not_same_name(self):
        b=[self.row(name="a")]; q=[self.row(name="b")]
        r=m.classify(b,q,[],[self.row(name="a")])[0]
        self.assertFalse(r["q3_same_name_content"])
        self.assertTrue(r["q3_any_same_size_content"])
    def test_duplicate_content_consumed_once(self):
        b=[self.row(i=1),self.row(i=2)]
        q=[self.row(i=9)]
        p=[self.row(i=1),self.row(i=2)]
        r=m.classify(b,q,[],p)
        self.assertEqual(sum(x["q3_same_name_content"] for x in r),1)

if __name__=="__main__": unittest.main()
