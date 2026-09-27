#!/usr/bin/env python3
"""Synthetic checks of research tools. No device or image-fidelity validation."""
from __future__ import annotations
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import sl3p_deep_audit as audit
import sl3p_key_screen as keys
import sl3p_compare as cmp
import sl3p_verify_candidate as verify


class AuditTests(unittest.TestCase):
    def test_entropy_constant(self):self.assertEqual(audit.entropy(bytes(4096)),0)
    def test_entropy_balanced(self):self.assertEqual(audit.entropy(bytes(range(256))*16),8)
    def test_tile_coverage_and_partial(self):
        r=audit.tile_stats(bytes(range(256))*17)
        self.assertEqual(r['bytes_covered'],4352);self.assertEqual(r['full_tiles'],1);self.assertEqual(r['partial_tiles'],1)
    def test_empty_tiles(self):self.assertEqual(audit.tile_stats(b'')['bytes_covered'],0)
    def test_gap_detection(self):
        r=audit.target_layout([{'index':0,'target_offset_unconfirmed':0,'size':32},{'index':1,'target_offset_unconfirmed':64,'size':16}])
        self.assertEqual(r['gap_bytes'],32);self.assertFalse(r['overlaps']);self.assertEqual(r['span_end'],80)
    def test_overlap_detection(self):
        r=audit.target_layout([{'index':0,'target_offset_unconfirmed':0,'size':32},{'index':1,'target_offset_unconfirmed':16,'size':32}])
        self.assertEqual(len(r['overlaps']),1)
    def test_pair_mask_detection(self):
        a=bytes(range(256));fa=bytes(16);fb=bytes([9])*16;b=bytes(c^9 for c in a)
        r=audit.compare_same_plain_candidate(a,b,fa,fb)
        self.assertTrue(r['repeating_field_xor_explains_difference']);self.assertEqual(r['equal_bytes'],0)
    def test_pair_bad_input(self):
        with self.assertRaises(ValueError):audit.compare_same_plain_candidate(b'a',b'bb',bytes(16),bytes(16))


def inventory():
    base={'size':32,'stored_sha256':'a'*64,'payload_sha256_after_outer_transform':'b'*64,
          'unknown_16_bytes':'c'*32,'target_offset_unconfirmed':0,'file_offset':1024,'flags':3}
    return {'input_sha256':'input','internal_identifier':'TEST',
            'sections':[dict(base,index=0,name='dup'),dict(base,index=1,name='dup')]}

class CompareTests(unittest.TestCase):
    def test_duplicates_preserved(self):self.assertEqual(len(cmp.keyed(inventory()['sections'])),2)
    def test_identical(self):self.assertEqual(cmp.compare_inventories(inventory(),inventory())['summary'],{'unchanged_record_fields':2})
    def test_representational_change(self):
        a=inventory();b=copy.deepcopy(a);b['sections'][0]['payload_sha256_after_outer_transform']='d'*64
        r=cmp.compare_inventories(a,b);self.assertEqual(r['sections'][0]['status'],'same_expected_content_different_representation')
    def test_expected_digest_change(self):
        a=inventory();b=copy.deepcopy(a);b['sections'][1]['stored_sha256']='d'*64
        self.assertEqual(cmp.compare_inventories(a,b)['sections'][1]['status'],'expected_content_changed')
    def test_target_change_not_silently_unchanged(self):
        a=inventory();b=copy.deepcopy(a);b['sections'][0]['target_offset_unconfirmed']=1024
        self.assertEqual(cmp.compare_inventories(a,b)['sections'][0]['status'],'same_expected_content_metadata_changed')
    def test_add_remove(self):
        a=inventory();b=inventory();b['sections'][1]['name']='new'
        r=cmp.compare_inventories(a,b);self.assertEqual(r['summary'].get('added'),1);self.assertEqual(r['summary'].get('removed'),1)

class AESPredicateTests(unittest.TestCase):
    def setUp(self):self.key=bytes(range(32));self.iv=bytes(range(16,32));self.plain=bytes([255])*256
    def enc(self,name):
        if name=='CTR-little':
            value=int.from_bytes(self.iv,'little');counters=b''.join((value+i).to_bytes(16,'little') for i in range(len(self.plain)//16))
            e=Cipher(algorithms.AES(self.key),modes.ECB()).encryptor();return keys.xor(e.update(counters)+e.finalize(),self.plain)
        m={'CBC':modes.CBC(self.iv),'CFB128':modes.CFB(self.iv),'OFB':modes.OFB(self.iv),'CTR-big':modes.CTR(self.iv)}[name]
        e=Cipher(algorithms.AES(self.key),m).encryptor();return e.update(self.plain)+e.finalize()
    def check_mode(self,name):
        c=self.enc(name);self.assertIn(name,keys.transition_modes(self.key,c[:64]))
        p,iv=keys.full_decode(self.key,c,name);self.assertEqual(p,self.plain);self.assertEqual(iv,self.iv)
    def test_cbc(self):self.check_mode('CBC')
    def test_cfb(self):self.check_mode('CFB128')
    def test_ofb(self):self.check_mode('OFB')
    def test_ctr_big(self):self.check_mode('CTR-big')
    def test_ctr_little(self):self.check_mode('CTR-little')
    def test_wrong_key_rejected(self):self.assertEqual(keys.transition_modes(bytes(32),self.enc('CBC')[:64]),[])
    def test_window_candidate(self):
        key=bytes(range(16));self.assertIn(key,keys.key_candidates(b'prefix'+key+b'tail'))

class OracleTests(unittest.TestCase):
    def test_accept_and_reject(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'candidate';path.write_bytes(b'valid')
            row={'index':1,'name':'test','size':5,'stored_sha256':hashlib.sha256(b'valid').hexdigest()}
            self.assertTrue(verify.verify(row,path)['passes'])
            path.write_bytes(b'wrong');self.assertFalse(verify.verify(row,path)['passes'])
            path.write_bytes(b'vali');self.assertFalse(verify.verify(row,path)['passes'])

if __name__=='__main__':unittest.main(verbosity=2)
