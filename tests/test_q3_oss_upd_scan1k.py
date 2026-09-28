import io,tarfile,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_q3_oss_upd_scan1k as m

def make_tar(files):
    bio=io.BytesIO()
    with tarfile.open(fileobj=bio,mode="w:gz") as tf:
        for name,data in files.items():
            info=tarfile.TarInfo(name);info.size=len(data);tf.addfile(info,io.BytesIO(data))
    return bio.getvalue()

class Q3OSSScan1KTests(unittest.TestCase):
    def test_token_hit(self):
        r=m.scan_tar(make_tar({"a.c":b"const char*x=\"lut_data\";"}),"x")
        self.assertEqual(r["hit_counts"]["lut_data"],1)
    def test_case_insensitive(self):
        r=m.scan_tar(make_tar({"a":b"RAW_KIZU_C"}),"x")
        self.assertEqual(r["hit_counts"]["raw_kizu_c"],1)
    def test_no_hit(self):
        self.assertEqual(m.scan_tar(make_tar({"a":b"hello"}),"x")["hits"],[])
    def test_select_members(self):
        names=["x/u-boot.tar.gz","x/linux.tar.gz","x/z"]
        self.assertEqual(m.select_members(names),names[:2])
    def test_ambiguous_member_rejected(self):
        with self.assertRaises(ValueError):m.select_members(["a/u-boot.tar.gz","b/u-boot.tar.gz","a/linux.tar.gz"])
if __name__=="__main__":unittest.main()
