# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1I. The recovered lens component contains a Memory command object and constructor-linked LDAFR reader/backend. Code confirms the packet marker, checksum, address order and STOP handling. The camera UPD protection, key, base still renderer and APK remain unresolved. The synthetic suite contains 240 tests.**

This is research source, not a Photon fork. No Leica firmware, reconstructed binary, Looks, private photographs, credentials or signing keys are committed.

## Start here

- [RESEARCH1I report](docs/RESEARCH1I_REPORT.md)
- [Continuation handoff](docs/RESEARCH1I_HANDOFF.md)
- [Selected completed-job measurements](evidence/research1i/summary.json)
- [Sparse reconstruction and code evidence in 1H](docs/RESEARCH1H_REPORT.md)
- [Validated LENS directory in 1G](docs/RESEARCH1G_REPORT.md)

## Current evidence

The official SLLens11.plf plus zero padding matches the complete expected SHA-256 of the protected SL3-P lens section. This is independent content recovery, not decryption. LENS CRCs and LDAFR packet checks remain required before code analysis.

The callee at 0x25BC0 is an ASCII case-insensitive string comparator, not a decryptor. The enclosing method at 0x1DB18 identifies itself through an adjacent name method as Memory. Its constructor-supplied backend resolves to a record-processing loop at 0x11D40 and completion delegation at 0x11E38.

The concrete reader at 0x11AB8 checks LDAFR character constants, validates the complemented byte sum, extracts length N-5, reads a big-endian normal-record address, and recognizes STOP. Its separate opening-record reader at 0x11A34 assembles the opening word little-endian. The varying opening byte, optional STOP suffix and destination implementation remain unresolved. This is a lens-packet consumer, not the camera's UPD protection handler.

Use reconstructed packet addresses, not raw file offsets or the superseded flat address 0x447E1. The correct fwupdate string address is 0x41458. Entry-relative static reachability and constructor links are not a runtime trace or proof of an exposed hardware command interface.

## Synthetic tests

Use an isolated Python environment; repository CI uses Python 3.13.

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The 240 tests need neither real firmware nor Capstone. They validate tools and reference mathematics, not photographic fidelity. A separate research workflow cross-checks 2,048 synthetic Thumb BL targets against Capstone operands.

## Explicit real-source analysis

```sh
python -m pip install -r requirements-analysis.txt
python tools/sl3p_lens_semantics1i.py
python tools/sl3p_lens_dispatch1i.py
python tools/sl3p_lens_backend1i.py
```

These commands fetch and verify the pinned public source, reconstruct sparse regions in memory, and emit bounded static analysis. They do not execute firmware, flash a device or publish binaries. The callsite tool retains exploratory linear windows; use the report's constructor and reader evidence rather than treating every linear decode as a function.

The lens-callsite1i workflow checks selected evidence assertions in addition to tests. Ordinary main-branch CI remains synthetic. Public summaries are reviewed selections, not full logs. Checksums do not authenticate vendor signatures. The Capstone distribution/module version distinction documented in 1H remains preserved.

Keep firmware, extracted content, Looks and private inputs out of Git. The source guard and .gitignore do not replace manual review.

## Next target and development order

Resolve the destination interface supplied from static address 0x2000ADA0 and the reader's storage interface from 0x2000AC9C before claiming physical flash or reset behavior. Keep camera-UPD protection-consumer research separate; do not presume the lens path contains the camera key.

Base still rendering -> source-calibrated Photon integration -> optional Leica Looks -> video. AF remains separate. No added HDR, Cobalt or M-series stand-in. Neither 4.2.2 nor a new user upload is required. Existing M-series projects remain untouched. L-Log mathematics is a later-video reference, not a recovered still transform.
