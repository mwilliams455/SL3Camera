#!/usr/bin/env python3
"""Bounded exploratory LENS directory measurements, not a validated parser.

Only the public container header/table fields are reported. Firmware payloads
are not printed, written to Git, or executed. The 1F source and target hashes
must both pass before any observations are emitted.
"""
from __future__ import annotations
import hashlib
import json
import re
import struct
from sl3p_lens_plaintext1f import URL, SOURCE_BYTES, reconstruct
from sl3p_loader_source_probe import acquire


def measure(data: bytes) -> dict:
    sof = b'LENS-UPDATE-FILE-SOF:'
    eoh = b'LENS-UPDATE-FILE-EOH:'
    if not data.startswith(sof) or len(data) < 31:
        raise ValueError('not the observed LENS format')
    count = int.from_bytes(data[29:31], 'big')
    stop = 31 + 19 * count
    if not 0 < count <= 256 or data[stop:stop+len(eoh)] != eoh:
        raise ValueError('candidate directory arithmetic failed')
    records = []
    for i in range(count):
        off = 31 + 19*i
        row = data[off:off+19]
        records.append({'index':i, 'table_offset':off,
                        'prefix3_values':list(row[:3]),
                        'four_u32_be_from_3':list(struct.unpack_from('>4I',row,3))})
    marks = [{'offset':m.start(), 'marker':m.group().decode('ascii')} for m in
             re.finditer(rb'LENS-UPDATE-FILE-[A-Z]{3}:', data)]
    return {'file_bytes':len(data), 'file_sha256':hashlib.sha256(data).hexdigest(),
            'fixed_header_u16_be_from_19':list(struct.unpack_from('>6H',data,19)),
            'candidate_count':count, 'candidate_record_bytes':19,
            'eoh_offset':stop, 'eoh_end':stop+len(eoh),
            'markers':marks, 'directory_records':records,
            'limitations':['Header arithmetic is not record-semantics validation.',
                          'No instruction architecture or update-consumer function established.']}


def main() -> None:
    data = acquire(URL, SOURCE_BYTES)
    plain, verification = reconstruct(data)
    del plain
    result = {'tool':'LENS_LAYOUT1G_DISCOVERY','source_url':URL,
              'verification':verification,'layout':measure(data),
              'payload_published':False,'firmware_executed':False}
    print('LENS_LAYOUT1G_JSON_BEGIN')
    print(json.dumps(result,separators=(',',':')))
    print('LENS_LAYOUT1G_JSON_END')


if __name__ == '__main__': main()
