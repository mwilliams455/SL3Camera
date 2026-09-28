import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_public_source_probe import allowed_url, compare_sections, zip_inventory

class PublicSourceTests(unittest.TestCase):
    def test_allowed_url(self):
        self.assertTrue(allowed_url('https://leica-camera.com/sites/default/files/example.zip'))
    def test_reject_other_origin(self):
        for u in ['http://leica-camera.com/sites/default/files/x', 'https://evil.com/x', 'https://leica-camera.com.evil.com/sites/default/files/x', 'https://user:pass@leica-camera.com/sites/default/files/x', 'https://leica-camera.com:444/sites/default/files/x', 'https://leica-camera.com/other/x']:
            self.assertFalse(allowed_url(u))
    def row(self, index, size=16, sha='expected'):
        return dict(index=index, name='duplicate', size=size, flags=3, stored_sha256=sha, payload_sha256_after_outer_transform=str(index), constant_fill_byte=None, sha256_matches=False)
    def test_duplicate_relationships_preserved(self):
        x=compare_sections({'sections':[self.row(1),self.row(2)]},{'sections':[self.row(3),self.row(4)]})
        self.assertEqual(len(x['matches']),4)
        self.assertEqual(len(x['not_direct_fill_matches']),4)
    def test_empty_not_promoted(self):
        x=compare_sections({'sections':[self.row(1,0)]},{'sections':[self.row(2,0)]})
        self.assertEqual(x['matches'],[])
    def test_hash_mismatch_not_matched(self):
        x=compare_sections({'sections':[self.row(1)]},{'sections':[self.row(2,sha='different')]})
        self.assertEqual(x['matches'],[])
    def test_archive_no_extraction(self):
        with tempfile.TemporaryDirectory() as td:
            p=Path(td)/'fixture.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('../escape.txt','test')
                z.writestr('OSS/u-boot.tar.gz','not actually compressed')
                z.writestr('OSS/README','notes')
            x=zip_inventory(p)
            self.assertEqual(x['files'],3)
            self.assertEqual(x['candidate_count'],2)
            self.assertEqual(len(x['nested_archives']),1)
            self.assertEqual(list(Path(td).iterdir()),[p])

if __name__ == '__main__': unittest.main()
