#!/usr/bin/env python3
"""Extend the prior signature screen; match markers are never a recovered asset.

No-magic formats and encrypted/compressed resources remain outside this screen.
Only marker presence/absence is reported for new signatures. Original gzip,
ELF, and SquashFS hits still undergo the prior structural checks.
"""
import argparse,json,bz2
from pathlib import Path
import scan_signatures as base
from sl3p_inspect import inspect,Firmware

EXTRA={
 'PNG':b'\x89PNG\r\n\x1a\n','JPEG_JFIF':b'JFIF\0','TIFF_LE':b'II\x2a\0',
 'TIFF_BE':b'MM\0\x2a','PDF':b'%PDF-','PE_DOS_stub':b'This program cannot be run in DOS mode',
 'ICC_marker':b'acsp','TFLite_marker':b'TFL3','NCNN_text_magic':b'7767517',
 'BZip2':b'BZh','Zstandard':bytes.fromhex('28b52ffd'),'7zip':bytes.fromhex('377abcaf271c'),
 'DTB':bytes.fromhex('d00dfeed'),'SQLite':b'SQLite format 3\0','OpenSSL_private_key_marker':b'-----BEGIN PRIVATE KEY-----',
}
TERMS=['LUT_1D_SIZE','DOMAIN_MIN','DOMAIN_MAX','LUT_3D_INPUT_RANGE','ColorMatrix1','ForwardMatrix1',
 'AsShotNeutral','BaselineExposure','LUT_3D_SIZE','L-Log','Leica Pure','Leica Cine',
 'WhiteBalance','ToneCurve','GammaTable','MediaCodec','ProRes','H.265','HEVC','BT.709',
 'REC.709','REC.2020','TensorFlow','ONNX','Arm Compute','CMSIS-NN','Maestro','Socionext','Milbeaut',
 'AUTOFOCUS','AF_TRACKING','C2PA','ContentCredentials','AES-CBC','mbedtls_aes','uECC_verify']

def run(path:Path)->dict:
    inv=inspect(path)
    base.SIGNATURES.update(EXTRA)
    for word in TERMS:
        for encoding in ('ascii','utf-16le','utf-16be'):
            base.SIGNATURES[f'{word} / {encoding}']=word.encode(encoding)
    result=base.scan(path)
    fw=Firmware(path)
    for off in result['signature_hits'].get('BZip2',[]):
        data=fw.read(off,min(65536,fw.size-off))
        check={'type':'BZip2','offset':off,'first16_hex':data[:16].hex()}
        if len(data)<10 or data[3:4] not in [bytes([v]) for v in range(49,58)]:
            check['result']='invalid BZip2 block-size character'
        else:
            try:
                dec=bz2.BZ2Decompressor();out=dec.decompress(data,max_length=1024*1024)
                check.update(result='valid_complete_stream' if dec.eof else 'inconclusive_bounded_test',output_bytes=len(out))
            except (ValueError,OSError,EOFError) as exc:check['result']=f'rejected: {exc}'
        result['validation'].append(check)
    marker_rows=[]
    for name,positions in result['signature_hits'].items():
        for pos in positions:
            section=next((r for r in inv['sections'] if r['file_offset']<=pos<r['file_offset']+r['size']),None)
            marker_rows.append({'marker':name,'offset':pos,'section_index':None if section is None else section['index'],
                               'section_name':None if section is None else section['name'],
                               'status':'marker_only_not_validated_asset'})
    result.update(tool='SL3P_ASSETSCAN1B',firmware_sha256=inv['input_sha256'],marker_locations=marker_rows,
                  total_signatures=len(base.SIGNATURES),limitations='Extended asset markers do not validate assets; short markers often occur by chance. Gzip/ELF/SquashFS structural checks are inherited. No assertion of absent encrypted or no-magic assets.')
    return result
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('firmware',type=Path);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    r=run(a.firmware);a.out.write_text(json.dumps(r,indent=2)+'\n')
    print(json.dumps({'total_signatures':r['total_signatures'],'nonzero_counts':{k:len(v) for k,v in r['signature_hits'].items() if v},'validation':r['validation']},indent=2))
