import io,tarfile,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_q3_uboot_vendor_scan1k as m

def tar(files):
    b=io.BytesIO()
    with tarfile.open(fileobj=b,mode="w:gz") as tf:
        for n,d in files.items():
            i=tarfile.TarInfo(n);i.size=len(d);tf.addfile(i,io.BytesIO(d))
    return b.getvalue()

class VendorScanTests(unittest.TestCase):
    def test_path_filter(self):
        self.assertTrue(m.interesting_path("arch/arm/mach-socionext/foo.c"))
        self.assertFalse(m.interesting_path("README"))
    def test_vendor_content_hit(self):
        r=m.scan(tar({"board/x/foo.c":b"firmware verify sha256"}))
        self.assertEqual(r["content_hits"][0]["path"],"board/x/foo.c")
        self.assertEqual({x["term"] for x in r["content_hits"][0]["hits"]},{"firmware","sha256","verify"})
    def test_nonvendor_content_ignored(self):
        r=m.scan(tar({"lib/foo.c":b"firmware verify sha256"}))
        self.assertEqual(r["content_hits"],[])
if __name__=="__main__":unittest.main()
