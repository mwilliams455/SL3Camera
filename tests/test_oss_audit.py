import io
from pathlib import Path
import sys
import tarfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from sl3p_oss_audit import scan_tar

def fixture(rows):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode='w:gz') as archive:
        for name, data, kind in rows:
            item = tarfile.TarInfo(name)
            if kind == 'link':
                item.type = tarfile.SYMTYPE
                item.linkname = '/etc/passwd'
                archive.addfile(item)
            else:
                item.size = len(data)
                archive.addfile(item, io.BytesIO(data))
    out.seek(0)
    return out

class OSSAuditTests(unittest.TestCase):
    def test_exact_marker_and_vendor(self):
        x = scan_tar(fixture([('src/board.c', b'milbeaut\nloader1\n', 'file')]))
        self.assertEqual(x['term_results']['loader1']['files'], 1)
        self.assertEqual(x['term_results']['milbeaut']['examples'][0]['lines'], [1])
    def test_no_symlink_following(self):
        x = scan_tar(fixture([('../../danger', b'', 'link')]))
        self.assertEqual(x['counts']['scanned_files'], 0)
    def test_crypto_line_not_emitted(self):
        x = scan_tar(fixture([('leica.c', b'leica aes_key = 123\n', 'file')]))
        self.assertEqual(x['vendor_crypto_count'], 1)
        self.assertEqual(x['specific_files'][0]['excerpts'], [])
    def test_large_file_skip(self):
        x = scan_tar(fixture([('x.c', b'12345', 'file')]), member_limit=4)
        self.assertEqual(x['counts']['skipped_large'], 1)
    def test_total_budget(self):
        with self.assertRaises(ValueError):
            scan_tar(fixture([('x', b'12345', 'file')]), total_limit=4)
    def test_entry_budget(self):
        with self.assertRaises(ValueError):
            scan_tar(fixture([('x', b'', 'file'), ('y', b'', 'file')]), file_limit=1)
    def test_binary_skip(self):
        x = scan_tar(fixture([('x.c', b'loader1\0', 'file')]))
        self.assertEqual(x['counts']['skipped_binary'], 1)
    def test_upd_word_not_substring(self):
        x = scan_tar(fixture([('x.c', b'UPDATE\nUPD\n', 'file')]))
        self.assertEqual(x['term_results']['UPD']['examples'][0]['lines'], [2])

if __name__ == '__main__': unittest.main()
