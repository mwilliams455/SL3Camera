import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_q3_program_build1k as m

class ProgramBuild1KTests(unittest.TestCase):
    def test_place_zero(self):
        b=m.place([(0,b"abc"),(10,b"z")],0)
        self.assertEqual(b[:3],b"abc");self.assertEqual(b[10:11],b"z");self.assertEqual(len(b),m.PROGRAM_SIZE)
    def test_place_ff(self):
        b=m.place([(1,b"x")],0xff)
        self.assertEqual(b[0],255);self.assertEqual(b[1:2],b"x")
    def test_out_of_range(self):
        with self.assertRaises(ValueError):m.place([(m.PROGRAM_SIZE,b"x")],0)
    def test_inspect_no_synthetic_match(self):
        r=m.inspect(b"A"*16,b"B"*16,b"C"*16)
        self.assertFalse(r["any_full_match"])
        self.assertEqual(r["dtb_offset"],0x1090000)
if __name__=="__main__":unittest.main()
