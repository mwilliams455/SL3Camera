import io
from pathlib import Path
import sys
import tarfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from sl3p_board_trace import summarize, selected_members
from test_oss_audit import fixture

class BoardTraceTests(unittest.TestCase):
    def test_numbered_context(self):
        x=summarize('x.c',b'one\nboot_cpu();\nthree\nfour\n')
        self.assertEqual(x['selected_lines'],[[1,'one'],[2,'boot_cpu();'],[3,'three']])
    def test_budget_visible(self):
        x=summarize('x.c',b'boot\n'*10,line_budget=3)
        self.assertTrue(x['truncated'])
        self.assertEqual(len(x['selected_lines']),3)
    def test_suspect_literals_not_emitted(self):
        x=summarize('x.c',b'aes_key = 123;\nboot();\n')
        self.assertEqual(x['redacted_lines'],1)
        self.assertNotIn('123',str(x['selected_lines']))
    def test_fixed_file_order(self):
        x=selected_members(fixture([('b',b'boot_b','file'),('a',b'boot_a','file')]),('a','b'))
        self.assertEqual([r['path'] for r in x],['a','b'])
    def test_missing_path_rejected(self):
        with self.assertRaises(ValueError):
            selected_members(fixture([('b',b'boot','file')]),('a',))
    def test_selected_link_rejected(self):
        with self.assertRaises(ValueError):
            selected_members(fixture([('a',b'','link')]),('a',))
    def test_duplicate_path_rejected(self):
        with self.assertRaises(ValueError):
            selected_members(fixture([('a',b'boot','file'),('a',b'boot','file')]),('a',))

if __name__=='__main__':unittest.main()
