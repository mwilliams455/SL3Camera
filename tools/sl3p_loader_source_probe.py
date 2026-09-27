#!/usr/bin/env python3
"""Read-only candidate-source probe. Never executes or publishes firmware bytes.

The M11 LZ convention is independently bounded here from the existing project
implementation at mwilliams455/M11Camera commit 44232e4f5074f5816eb224682c980545cfcd6c65.
Success in this format does NOT establish SL3-P loader compatibility.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import struct
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener

LIMIT = 256 * 1024 * 1024
SOURCES = {
    'm11p261': ('https://leica-camera.com/sites/default/files/LEICA_M11-P_2.6.1.FW', 63621633),
    'm11p264': ('https://leica-camera.com/sites/default/files/LEICA_M11-P_2.6.4.FW', None),
}
# Exact section names are much stronger leads than generic crypto vocabulary.
EXACT = (b'UPD\0', b'leica\0', b'loader1', b'postboot1_r', b'compress_pr',
         b'eep_ow_a', b'lut_data', b'MC7251')
TERMS = (b'decrypt', b'encrypt', b'firmware', b'updater', b'sha256',
         b'aes_', b'cipher', b'bootloader', b'updatefirm', b'fwupdate')


def varint(data: bytes, pos: int) -> tuple[int, int]:
    value = 0
    for _ in range(5):
        if pos >= len(data):
            raise ValueError('truncated varint')
        byte = data[pos]
        pos += 1
        value = (value << 7) | (byte & 127)
        if byte < 128:
            return value, pos
    raise ValueError('overlong varint')


def decode_m11(data: bytes, limit: int = LIMIT) -> tuple[bytes, dict]:
    if len(data) < 40:
        raise ValueError('short M11 header')
    start, output_size, packed_size = (struct.unpack_from('<I', data, x)[0]
                                      for x in (4, 12, 20))
    if not 40 <= start < len(data) or start + packed_size != len(data):
        raise ValueError('M11 body bounds or unexplained trailing data')
    if not 0 < output_size <= limit or not 0 < packed_size <= limit:
        raise ValueError('M11 declared size outside limits')
    body = data[start:]
    if hashlib.md5(body).digest() != data[24:40]:
        raise ValueError('M11 packed-body MD5 mismatch')
    marker, pos, out = body[0], 1, bytearray()
    refs = literals = escapes = 0
    while pos < len(body):
        byte = body[pos]
        pos += 1
        if byte != marker:
            out.append(byte)
            literals += 1
        else:
            if pos >= len(body):
                raise ValueError('truncated marker')
            if body[pos] == 0:
                out.append(marker)
                escapes += 1
                pos += 1
            else:
                length, pos = varint(body, pos)
                distance, pos = varint(body, pos)
                if not 0 < distance <= len(out) or length == 0:
                    raise ValueError('invalid back-reference')
                if len(out) + length > output_size:
                    raise ValueError('back-reference exceeds declared output')
                # Correct overlapping copy; bounded before allocation.
                seed = bytes(out[-distance:])
                out.extend((seed * ((length + distance - 1) // distance))[:length])
                refs += 1
        if len(out) > output_size:
            raise ValueError('output exceeds declaration')
    if len(out) != output_size:
        raise ValueError('output shorter than declaration')
    return bytes(out), {'format': 'observed_M11_marker_LZ', 'packed_md5_matches': True,
                        'packed_bytes': packed_size, 'decoded_bytes': len(out),
                        'decoded_sha256': hashlib.sha256(out).hexdigest(),
                        'references': refs, 'literals': literals, 'escapes': escapes}


def locations(data: bytes, needle: bytes, cap: int = 16) -> dict:
    count, pos, offsets = 0, 0, []
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        count += 1
        if len(offsets) < cap:
            offsets.append(pos)
        pos += 1
    return {'count': count, 'first_offsets': offsets}


def probe(data: bytes) -> dict:
    if len(data) > LIMIT:
        raise ValueError('input exceeds limit')
    lower = data.lower()
    # No arbitrary strings, key material, byte dumps or binary slices in report.
    return {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'exact_markers': {x.decode('ascii').replace('\0', '\\0'): locations(data, x) for x in EXACT},
            'casefolded_terms': {x.decode('ascii'): locations(lower, x) for x in TERMS}}


def approved(url: str) -> bool:
    u = urlparse(url)
    return (u.scheme == 'https' and u.hostname in ('leica-camera.com', 'www.leica-camera.com')
            and u.username is None and u.password is None and u.port in (None, 443))


class VendorRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not approved(newurl):
            raise ValueError('redirect left approved Leica HTTPS hosts')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def acquire(url: str, expected_size: int | None) -> bytes:
    if not approved(url):
        raise ValueError('unapproved source URL')
    opener = build_opener(VendorRedirect())
    req = Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/octet-stream,*/*'})
    with opener.open(req, timeout=45) as stream:
        if not approved(stream.geturl()):
            raise ValueError('unapproved final URL')
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT or len(data) < 1024:
        raise ValueError('invalid downloaded size')
    if expected_size is not None and len(data) != expected_size:
        raise ValueError('download differs from recorded size')
    return data


def inspect_candidate(source: str) -> dict:
    url, expected = SOURCES[source]
    result = {'source_id': source, 'url': url, 'sl3p_compatibility_established': False}
    try:
        data = acquire(url, expected)
        result['download'] = {'ok': True, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
        decoded, validation = decode_m11(data)
        result['decode'] = validation
        result['decoded_probe'] = probe(decoded)
        result['status'] = 'decoded_candidate_not_validated_SL3P_consumer'
    except Exception as exc:
        result['status'] = 'failed'
        result['error_type'] = type(exc).__name__
        # Messages here originate from our bounds checks or public HTTP endpoint.
        result['error'] = str(exc)[:250]
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source', choices=SOURCES, action='append', required=True)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    if args.out.exists():
        ap.error('refusing to overwrite output')
    result = {'tool': 'LOADER_SOURCE1E', 'candidates': [inspect_candidate(s) for s in args.source],
              'binary_written_or_executed': False,
              'limits': ['Marker hits do not establish caller semantics or shared keys.',
                         'M11 decoder is not an SL3-P decryptor.']}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open('x', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print('LOADER_SOURCE1E_JSON_BEGIN')
    print(json.dumps(result, indent=2))
    print('LOADER_SOURCE1E_JSON_END')
    if not any(x['status'] != 'failed' for x in result['candidates']):
        raise SystemExit(1)


if __name__ == '__main__':
    main()
