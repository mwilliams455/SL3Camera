#!/usr/bin/env python3
"""Positive and negative controlled end-to-end decoder-screen experiments."""
import contextlib,hashlib,io,struct,sys,tempfile,unittest,zlib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import sl3p_extended_screen as ext
from sl3p_inspect import XOR_FF
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes


def fixture(fill=255,corrupt_tail=False):
    key=bytes(range(32));start=0x1a00;b=bytearray(start+512)
    b[:4]=b'UPD\0';b[12:18]=b'TEST01';b[0x200:0x206]=b'leica\0';b[0x220:0x240]=key
    b[0x2a0:0x2a4]=b'UPD\0';b[0x2ac:0x2b2]=b'TEST01'
    struct.pack_into('<III',b,0x38,0x200,len(b)-0x200,0)
    struct.pack_into('<III',b,0x2e0,start-0x200,512,11)
    cursor=start
    for i in range(11):
        at=0x2ec+i*92;name=f'section{i}'.encode();b[at:at+len(name)]=name
        size=256 if i in (8,10) else 0
        struct.pack_into('<4I',b,at+12,cursor-0x200,size,i*65536,3 if size else 2)
        b[at+28:at+60]=hashlib.sha256(b'\xff'*size).digest()
        if size:
            iv=bytes([i])*16;b[at+60:at+76]=iv
            en=Cipher(algorithms.AES(key),modes.CBC(iv)).encryptor();ct=en.update(bytes([fill])*size)+en.finalize()
            payload=bytearray(ext.permute(ct,4,True))
            if corrupt_tail and i==8:payload[200]^=1
            b[cursor:cursor+size]=payload
        cursor+=size
    struct.pack_into('<I',b,0x40,zlib.crc32(b[0x200:])&0xffffffff)
    return bytes(b).translate(XOR_FF)

class EndToEndTests(unittest.TestCase):
    def run_fixture(self,**kw):
        with tempfile.TemporaryDirectory() as t:
            f=Path(t)/'synthetic.lfu';f.write_bytes(fixture(**kw))
            with contextlib.redirect_stdout(io.StringIO()):return ext.run(f)
    def test_recovers_header_key_and_nontrivial_ciphertext_convention(self):
        r=self.run_fixture()
        self.assertTrue(any(h['full_expected_hash_matches'] and h['mode']=='CBC' and h['fill']==255 and
                            h['sample_variant']=={'word_reversal':4,'inverted':True} for h in r['prefix_hits']))
    def test_complementary_plaintext_convention(self):
        r=self.run_fixture(fill=0)
        self.assertTrue(any(h['full_expected_hash_matches'] and h['mode']=='CBC' and h['fill']==0 for h in r['prefix_hits']))
    def test_prefix_match_cannot_bypass_full_hash(self):
        r=self.run_fixture(corrupt_tail=True)
        self.assertTrue(r['prefix_hits'])
        self.assertFalse(any(h['full_expected_hash_matches'] for h in r['prefix_hits']))

if __name__=='__main__':unittest.main(verbosity=2)
