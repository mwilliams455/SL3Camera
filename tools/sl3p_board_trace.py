#!/usr/bin/env python3
"""Read fixed public-source board files; no firmware extraction or execution.

The archive is SHA-256 pinned. Output is a bounded, line-numbered selection,
not a complete source release, and cannot establish the SL3-P runtime target.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile
import tempfile
import zipfile
from sl3p_public_source_probe import download, SOURCES
from sl3p_oss_audit import OSS_SHA256, MEMBERS

FILES = {
    'uboot': (
        'u-boot/configs/pvc04v_MC501_defconfig',
        'u-boot/include/configs/pvc04v_MC501.h',
        'u-boot/board/socionext/sc2006a/sc2006a.c',
        'u-boot/arch/arm/cpu/armv8/milbeaut/misc.c',
        'u-boot/arch/arm/cpu/armv8/milbeaut/lowlevel_init.S',
        'u-boot/arch/arm/cpu/armv8/milbeaut/Kconfig',
    ),
    'linux': (
        'linux-4.19.124/arch/arm64/configs/pvc04v_DC1231_defconfig',
        'linux-4.19.124/arch/arm64/boot/dts/socionext/pvc04v-DC1231-rtos.h',
        'linux-4.19.124/arch/arm64/boot/dts/socionext/pvc04v-DC1231.dtsi',
        'linux-4.19.124/drivers/block/ipcu.c',
        'linux-4.19.124/drivers/snihotplug/sni_hotplug.c',
        'linux-4.19.124/drivers/snidsp/sni_dsp_drv_m20v.c',
    ),
}
MATCH = re.compile(r'boot|rtos|ipcu|firmware|milbeaut|pvc04|sc2006|cpu|amp|memory|reserved|cmdline|initramfs|load|entry|nand|sdmmc|mmc|decrypt|encrypt|secure|aes|sha256|signature|MC501|DC1231', re.I)
SENSITIVE = re.compile(r'(?i)(?:private.?key|aes.?key|password)\s*(?:=|\[)|-----BEGIN|\b[0-9a-f]{32,}\b')


def summarize(name: str, data: bytes, line_budget: int = 100) -> dict:
    text = data.decode('utf-8', 'strict')
    lines = text.splitlines()
    indices = set()
    for i, line in enumerate(lines):
        if MATCH.search(line):
            indices.update(range(max(0, i-1), min(len(lines), i+2)))
    if name.endswith('_defconfig'):
        indices = {i for i in indices if MATCH.search(lines[i])}
    chosen = sorted(indices)
    output = []
    redacted = 0
    for i in chosen[:line_budget]:
        if SENSITIVE.search(lines[i]):
            redacted += 1
            continue
        output.append([i+1, lines[i][:240]])
    return {'path': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'total_lines': len(lines), 'matching_context_lines': len(chosen),
            'truncated': len(chosen) > line_budget, 'redacted_lines': redacted,
            'selected_lines': output}


def selected_members(stream, names: tuple[str, ...]) -> list[dict]:
    wanted = set(names)
    found = {}
    total = 0
    with tarfile.open(fileobj=stream, mode='r|*') as archive:
        for count, member in enumerate(archive, 1):
            if count > 100000:
                raise ValueError('too many source members')
            if member.isfile():
                total += member.size
                if total > 1024**3:
                    raise ValueError('source size budget exceeded')
            if member.name not in wanted:
                continue
            if member.name in found:
                raise ValueError('duplicate selected source member')
            if not member.isfile() or member.size < 0 or member.size > 1024**2:
                raise ValueError('selected source is not a bounded regular file')
            source = archive.extractfile(member)
            if source is None:
                raise ValueError('selected source missing')
            with source:
                data = source.read(1024**2+1)
            if len(data) != member.size:
                raise ValueError('selected source size mismatch')
            found[member.name] = summarize(member.name, data)
    if wanted != found.keys():
        raise ValueError('fixed selected source paths missing: ' + ', '.join(sorted(wanted - found.keys())))
    return [found[name] for name in names]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--part', choices=sorted(FILES), required=True)
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='sl3-board-') as td:
        p = Path(td) / 'official.zip'
        downloaded = download(SOURCES['q3_oss'], p)
        if downloaded['sha256'] != OSS_SHA256:
            raise ValueError('source hash changed; manual review required')
        with zipfile.ZipFile(p) as archive, archive.open(MEMBERS[args.part]) as member:
            result = selected_members(member, FILES[args.part])
        print('BOARD_TRACE_JSON_BEGIN')
        print(json.dumps({'probe':'BOARD_TRACE1D', 'part':args.part,
                          'source_sha256':OSS_SHA256, 'files':result}, separators=(',', ':')))
        print('BOARD_TRACE_JSON_END')

if __name__ == '__main__': main()
