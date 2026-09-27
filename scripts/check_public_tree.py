#!/usr/bin/env python3
"""Fail CI on tracked non-text assets or excluded local-input paths.

This is a conservative source-only repository check, not a complete secret,
privacy or licensing scanner. Manual review is still required before a push.
"""
from __future__ import annotations
import subprocess
import sys
from pathlib import Path

ALLOWED_SUFFIXES = {'.py', '.md', '.txt', '.json', '.csv', '.yml', '.yaml'}
ALLOWED_NAMES = {'.gitignore', '.gitattributes', 'LICENSE', 'NOTICE'}
BLOCKED_DIRS = {'firmware', 'inputs', 'private', 'local', 'scratch', 'work',
                'extracted', 'payloads', 'candidates', 'outputs', 'results',
                'secrets', 'credentials'}
MAX_BYTES = 1024 * 1024


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        names = subprocess.check_output(
            ['git', 'ls-files', '-z'], cwd=root
        ).decode('utf-8').split('\0')
    except (OSError, subprocess.CalledProcessError, UnicodeError) as exc:
        print(f'Cannot inspect tracked paths: {exc}', file=sys.stderr)
        return 2
    problems = []
    count = 0
    for name in filter(None, names):
        relative = Path(name)
        path = root / relative
        count += 1
        if relative.is_absolute() or '..' in relative.parts:
            problems.append(f'{name}: unsafe path')
            continue
        if any(part.lower() in BLOCKED_DIRS for part in relative.parts[:-1]):
            problems.append(f'{name}: local-input/output directory is tracked')
        if relative.name not in ALLOWED_NAMES and relative.suffix.lower() not in ALLOWED_SUFFIXES:
            problems.append(f'{name}: not an allowed source/document extension')
        if path.is_symlink() or not path.is_file():
            problems.append(f'{name}: not a regular file')
            continue
        if path.stat().st_size > MAX_BYTES:
            problems.append(f'{name}: exceeds source-only size limit')
            continue
        try:
            data = path.read_bytes()
            data.decode('utf-8')
        except (OSError, UnicodeError) as exc:
            problems.append(f'{name}: cannot read UTF-8 text ({exc})')
            continue
        if b'\0' in data or data.startswith(b'version https://git-lfs.github.com/spec/v1'):
            problems.append(f'{name}: binary content or LFS pointer')
    if not count:
        problems.append('No tracked files found')
    if problems:
        print('\n'.join(problems), file=sys.stderr)
        return 1
    print(f'Source-only tracked-file check passed: {count} files')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
