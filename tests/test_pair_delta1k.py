import math,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"tools"))
import sl3p_pair_delta1k as m

class PairDelta1KTests(unittest.TestCase):
    def test_entropy_constant(self):
        self.assertEqual(m.entropy_bytes(bytes(1024)),0.0)
    def test_entropy_uniform(self):
        e=m.entropy_bytes(bytes(range(256))*4)
        self.assertAlmostEqual(e,8.0,places=12)
    def test_empty_entropy(self):
        self.assertEqual(m.entropy_bytes(b""),0.0)
if __name__=="__main__":unittest.main()
