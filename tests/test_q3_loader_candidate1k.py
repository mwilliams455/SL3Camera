import hashlib,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_q3_loader_candidate1k as m

class LoaderCandidate1KTests(unittest.TestCase):
    def test_windows_are_aligned_and_complete(self):
        d=bytes(range(256))*1536
        rows=m.aligned_windows(d)
        self.assertEqual([r["offset"] for r in rows],[0,131072,262144])
        self.assertTrue(all(len(d[r["offset"]:r["offset"]+m.TARGET_SIZE])==m.TARGET_SIZE for r in rows))
    def test_short_input_has_no_window(self):
        self.assertEqual(m.aligned_windows(b"x"*100),[])
    def test_bad_size_rejected(self):
        with self.assertRaises(ValueError): m.aligned_windows(b"x",0)
    def test_forms_are_deterministic(self):
        d=(b"Leica-Q3-known-candidate\0"*12000)
        a=m.candidate_forms(d); b=m.candidate_forms(d)
        self.assertEqual(a,b)
        self.assertEqual(a["gzip_mtime0"]["sha256"],b["gzip_mtime0"]["sha256"])
    def test_prefix_hash(self):
        d=b"A"*m.TARGET_SIZE+b"B"*17
        got=m.candidate_forms(d)["prefix_128k"]["sha256"]
        self.assertEqual(got,hashlib.sha256(b"A"*m.TARGET_SIZE).hexdigest())
    def test_inspect_synthetic_exact_match_flag_false(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/"candidate.bin";p.write_bytes(b"A"*200000)
            r=m.inspect([p])
        self.assertFalse(r["any_exact_candidate_match"])
        self.assertEqual(r["loader1_expected_bytes"],131072)

if __name__=="__main__": unittest.main()
