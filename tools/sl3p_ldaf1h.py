#!/usr/bin/env python3
"""Measured LDAFR packet framing, with checksums and sparse address ranges.

This does not decrypt the camera UPD container or execute downloaded code.
The prologue and remaining trailer are separate from the length-delimited
records; their semantics must not be inferred from resemblance to S-records.
"""
from __future__ import annotations
from collections import Counter
from dataclasses import dataclass
import hashlib
import json

MAGIC = b'LDAFR'
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 100000

@dataclass(frozen=True)
class Packet:
    offset: int
    address: int
    data: bytes
    count: int


def parse_packets(blob: bytes) -> tuple[list[Packet], dict]:
    if not isinstance(blob, bytes) or not 10 <= len(blob) <= MAX_BYTES:
        raise ValueError('invalid packet source length/type')
    if blob[:5] != MAGIC or blob[6:10] != b'\xff'*4:
        raise ValueError('unrecognized ten-byte LDAFR prologue')
    packets=[]
    cursor=10
    while blob[cursor:cursor+5] == MAGIC:
        if len(packets) >= MAX_RECORDS or cursor+6 > len(blob):
            raise ValueError('record limit or incomplete count')
        count=blob[cursor+5]
        end=cursor+6+count
        if count < 5 or end > len(blob):
            raise ValueError(f'record length invalid at {cursor}')
        if sum(blob[cursor+5:end]) & 255 != 255:
            raise ValueError(f'record checksum mismatch at {cursor}')
        address=int.from_bytes(blob[cursor+6:cursor+10], 'big')
        content=blob[cursor+10:end-1]
        if address+len(content) > 2**32:
            raise ValueError('32-bit address overflow')
        packets.append(Packet(cursor,address,content,count))
        cursor=end
    if not packets:
        raise ValueError('no validated packets')
    trailer=blob[cursor:]
    if len(trailer) > 16:
        raise ValueError(f'unexplained trailing data ({len(trailer)} bytes)')
    report={'packet_count':len(packets),'data_packet_count':sum(bool(p.data) for p in packets),
            'no_data_packet_addresses':[p.address for p in packets if not p.data],
            'prologue_byte5':blob[5], 'packet_count_values':dict(Counter(p.count for p in packets)),
            'all_packet_checksums_verified':True,'parsed_bytes':cursor,
            'trailer_offset':cursor,'trailer_bytes':len(trailer),'trailer_hex':trailer.hex(),
            'trailer_semantics_verified':False}
    return packets,report


def segments(packets: list[Packet]) -> list[tuple[int,bytes]]:
    """Sort and coalesce adjacent ranges; reject overlaps, never fill holes."""
    spans=sorted((p.address,p.data) for p in packets if p.data)
    out=[]
    start=None
    body=bytearray()
    for address,data in spans:
        if start is not None and address < start+len(body):
            raise ValueError('overlapping packet address ranges')
        if start is None or address != start+len(body):
            if start is not None: out.append((start,bytes(body)))
            start=address
            body=bytearray()
        body.extend(data)
    if start is not None: out.append((start,bytes(body)))
    return out


def summarize(blob: bytes) -> tuple[list[tuple[int,bytes]],dict]:
    packets,report=parse_packets(blob)
    image=segments(packets)
    report['mapped_data_bytes']=sum(len(b) for _,b in image)
    report['segments']=[{'address':a,'size':len(b),'end_exclusive':a+len(b),
                         'sha256':hashlib.sha256(b).hexdigest(),
                         'fwupdate_address':a+b.find(b'fwupdate\0') if b'fwupdate\0' in b else None}
                        for a,b in image]
    report['first_packet_addresses']=[p.address for p in packets[:12]]
    report['last_packet_addresses']=[p.address for p in packets[-4:]]
    return image,report


def main():
    from sl3p_loader_source_probe import acquire
    from sl3p_lens_plaintext1f import URL,SOURCE_BYTES,reconstruct
    from sl3p_lens_records1g import verify_lens
    source=acquire(URL,SOURCE_BYTES)
    plain,proof=reconstruct(source)
    del plain
    results=[]
    for p in verify_lens(source)['payloads']:
        content=source[p['offset']:p['offset']+p['size']]
        if not content.startswith(MAGIC): continue
        try:
            _,report=summarize(content)
            report['status']='packet_checks_pass_trailer_uninterpreted'
        except ValueError as exc:
            report={'status':'rejected','reason':str(exc)}
        report['records']=p['record_indexes']
        report['source_size']=len(content)
        report['source_sha256']=hashlib.sha256(content).hexdigest()
        results.append(report)
    print('LDAF_PACKETS1H_JSON_BEGIN')
    print(json.dumps({'source_proof':proof,'payloads':results,'firmware_executed':False,
                      'payload_dumped':False},separators=(',',':')))
    print('LDAF_PACKETS1H_JSON_END')

if __name__=='__main__': main()
