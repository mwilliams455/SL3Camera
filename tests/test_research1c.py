#!/usr/bin/env python3
"""Synthetic validation of RESEARCH1C; not camera/rendering validation."""
from __future__ import annotations
import hashlib,random,struct,sys,unittest
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.asymmetric import ec
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import sl3p_extended_screen as ext
import sl3p_stream_probe as st
import sl3p_metadata_audit as meta
import sl3p_key_screen as old
from sl3p_inspect import XOR_FF


def encrypted(key,iv,plain,mode):
    if mode=='CTR-little':
        value=int.from_bytes(iv,'little')
        blocks=b''.join(((value+i)%(1<<128)).to_bytes(16,'little') for i in range(len(plain)//16))
        e=Cipher(algorithms.AES(key),modes.ECB()).encryptor()
        return old.xor(e.update(blocks)+e.finalize(),plain)
    m={'CBC':modes.CBC(iv),'CFB128':modes.CFB(iv),'OFB':modes.OFB(iv),'CTR-big':modes.CTR(iv)}[mode]
    e=Cipher(algorithms.AES(key),m).encryptor();return e.update(plain)+e.finalize()

class ExtendedTests(unittest.TestCase):
    def check_mode(self,mode,fill):
        for n in (16,24,32):
            with self.subTest(key_bytes=n):
                k=bytes(range(n));iv=bytes(range(16,32));p=bytes([fill])*256
                ct=encrypted(k,iv,p,mode)
                for w in (1,2,4,8,16):
                    for inv in (False,True):
                        with self.subTest(word=w,inverted=inv):
                            stored=ext.permute(ct,w,inv)
                            schemes=[(v,i) for v in (1,2,4,8,16) for i in (False,True)]
                            samples=[ext.permute(stored[:64],v,i) for v,i in schemes]
                            self.assertIn((schemes.index((w,inv)),fill,mode),ext.multi_transition(k,samples))
                            plain,recovered_iv=old.full_decode(k,ext.permute(stored,w,inv),mode,fill)
                            self.assertEqual(plain,p);self.assertEqual(recovered_iv,iv)
    def test_cbc_ff(self):self.check_mode('CBC',255)
    def test_cbc_zero(self):self.check_mode('CBC',0)
    def test_cfb_ff(self):self.check_mode('CFB128',255)
    def test_cfb_zero(self):self.check_mode('CFB128',0)
    def test_ofb_ff(self):self.check_mode('OFB',255)
    def test_ofb_zero(self):self.check_mode('OFB',0)
    def test_ctr_big_ff(self):self.check_mode('CTR-big',255)
    def test_ctr_big_zero(self):self.check_mode('CTR-big',0)
    def test_ctr_little_ff(self):self.check_mode('CTR-little',255)
    def test_ctr_little_zero(self):self.check_mode('CTR-little',0)
    def test_wrong_key(self):
        ct=encrypted(bytes(range(32)),bytes(16),b'\xff'*64,'CBC')
        self.assertEqual(ext.multi_transition(bytes(32),[ct,ct.translate(XOR_FF)]),[])
    def test_nonconstant_plaintext(self):
        k=bytes(range(32));ct=encrypted(k,bytes(16),bytes(range(64)),'CBC')
        self.assertEqual(ext.multi_transition(k,[ct,ct.translate(XOR_FF)]),[])
    def test_ctr_counter_wrap(self):
        k=bytes(16);iv=bytes([255])*16;p=bytes([255])*256
        for mode in ('CTR-big','CTR-little'):
            ct=encrypted(k,iv,p,mode)
            self.assertIn((0,255,mode),ext.multi_transition(k,[ct[:64],ct[:64].translate(XOR_FF)]))
    def test_bad_batches(self):
        for b in ([],[bytes(64)],[bytes(63),bytes(63)],[bytes(64),bytes(64)]):
            with self.assertRaises(ValueError):ext.multi_transition(bytes(16),b)
    def test_permutation_inverse(self):
        b=bytes(range(256))
        for w in (1,2,4,8,16):
            for inv in (False,True):self.assertEqual(ext.permute(ext.permute(b,w,inv),w,inv),b)
    def test_bad_permutations(self):
        with self.assertRaises(ValueError):ext.permute(b'abc',2)
        with self.assertRaises(ValueError):ext.permute(b'abcd',3)
    def test_derived_keys_are_labeled_and_deterministic(self):
        h=bytearray(0x400);h[0x220:0x260]=bytes(range(64));off=0x2ec
        h[off:off+12]=b'known_name\0\0';h[off+28:off+60]=bytes(range(32));h[off+60:off+76]=bytes(range(16))
        r={'entry_file_offset':off};d=ext.derivations(bytes(h),r)
        self.assertTrue(all(len(k) in (16,24,32) for k in d))
        self.assertIn(hashlib.sha256(bytes(range(16))).digest(),d)
        self.assertEqual(d,ext.derivations(bytes(h),r))
    def test_matches_preserved_predicate(self):
        rng=random.Random(42)
        for _ in range(100):
            k=rng.randbytes(16);s=rng.randbytes(64)
            got=[mode for variant,fill,mode in ext.multi_transition(k,[s,s.translate(XOR_FF)]) if variant==0 and fill==255]
            self.assertEqual(got,old.transition_modes(k,s))

class StreamTests(unittest.TestCase):
    def test_untemper_inverse(self):
        rng=random.Random(19)
        for x in [0,1,0xffffffff]+[rng.getrandbits(32) for _ in range(1000)]:self.assertEqual(st.untemper(st.temper(x)),x)
    def test_mt_unknown_phase(self):
        for phase in (0,1,17,227,396,623,624,625,1234):
            rng=random.Random(123)
            for _ in range(phase):rng.getrandbits(32)
            self.assertTrue(st.mt_match([rng.getrandbits(32) for _ in range(688)]))
    def test_mt_holdout_corruption(self):
        rng=random.Random(123);w=[rng.getrandbits(32) for _ in range(688)];w[635]^=1
        self.assertFalse(st.mt_match(w))
    def test_mt_insufficient(self):
        with self.assertRaises(ValueError):st.mt_match([0]*624)
    def test_xorshift_positive(self):
        w=[123456789,362436069,521288629,88675123]
        for i in range(128):w.append(st.xs_next(w[-4],w[-1]))
        self.assertTrue(st.xs_match(w))
    def test_xorshift_negative(self):
        rng=random.Random(123);self.assertFalse(st.xs_match([rng.getrandbits(32) for _ in range(128)]))
    def test_xorshift_insufficient(self):
        with self.assertRaises(ValueError):st.xs_match([1,2,3,4])
    def test_linear_degree7(self):
        b=[1,0,1,1,0,1,0]
        for _ in range(1024):b.append(b[-7]^b[-3])
        self.assertEqual(st.recurrence_match(b,512,64),(7,True))
    def test_linear_holdout_mutation(self):
        b=[1,0,1,1,0,1,0]
        for _ in range(1024):b.append(b[-7]^b[-3])
        b[700]^=1;self.assertEqual(st.recurrence_match(b,512,64),(7,False))
    def test_linear_degree_limit(self):
        b=[1,0,1,1,0,1,0]
        for _ in range(1024):b.append(b[-7]^b[-3])
        self.assertEqual(st.recurrence_match(b,512,6),(7,False))
    def test_linear_zero(self):self.assertEqual(st.recurrence_match([0]*100,50,4),(0,True))
    def test_linear_invalid(self):
        with self.assertRaises(ValueError):st.berlekamp_massey([0,1,2])
        with self.assertRaises(ValueError):st.recurrence_match([0,1],2)
    def test_mask_byte_wrap(self):
        d=st.mask_candidates(b'\xff'*8);self.assertEqual(d['word1-little-+1'],bytes(8))
        d=st.mask_candidates(bytes(8));self.assertEqual(d['word1-little--1'],b'\xff'*8)
    def test_mask_word_endianness(self):
        d=st.mask_candidates(bytes(8))
        self.assertEqual(d['word4-little-+1'],b'\x01\0\0\0'*2)
        self.assertEqual(d['word4-big-+1'],b'\0\0\0\x01'*2)
    def test_mask_invalid(self):
        with self.assertRaises(ValueError):st.mask_candidates(b'abc')

class MetadataTests(unittest.TestCase):
    def test_digest_variants(self):
        r=meta.digest_variants(b'abc');self.assertEqual(len(r),7)
        self.assertEqual(r['MD5'].hex(),'900150983cd24fb0d6963f7d28e17f72')
    def test_real_public_point_is_recognized(self):
        p=ec.derive_private_key(1,ec.SECP256R1()).public_key().public_numbers()
        data=p.x.to_bytes(32,'big')+p.y.to_bytes(32,'big');r=meta.point_tests(data)
        self.assertTrue(any(x['valid_point'] and x['curve']=='secp256r1' and x['order']=='xy' and x['integer_order']=='big' for x in r))
    def test_invalid_public_point(self):self.assertFalse(any(r['valid_point'] for r in meta.point_tests(bytes(64))))
    def test_point_wrong_length(self):
        with self.assertRaises(ValueError):meta.point_tests(bytes(32))

if __name__=='__main__':unittest.main(verbosity=2)
