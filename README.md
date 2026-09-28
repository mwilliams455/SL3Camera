# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1J. The recovered lens component's storage adapter, byte-verification destination and completion-to-reset path are now connected. The traced fwupdate loop verifies bytes rather than programming them. The camera UPD protection, key, base still renderer and APK remain unresolved. All 261 pure tests pass.**

This is research source, not a Photon fork. No firmware binary, reconstructed image, Look, private media, credentials or signing keys are committed.

## Start here

- [RESEARCH1J report](docs/RESEARCH1J_REPORT.md)
- [Continuation handoff](docs/RESEARCH1J_HANDOFF.md)
- [Selected completed-job evidence](evidence/research1j/summary.json)
- [Current research status](docs/RESEARCH_STATUS.md)
- [LDAFR consumer in 1I](docs/RESEARCH1I_REPORT.md)
- [Packet reconstruction in 1H](docs/RESEARCH1H_REPORT.md)

## Established evidence and boundaries

The official standalone SLLens11.plf plus zero padding matches the complete intended SL3-P lens-section SHA-256. This is independent content recovery, not decryption. LENS CRCs and LDAFR packet checks remain required before code analysis.

The Memory command's backend calls destination table slot +12, a byte comparator at 0x770. It compares incoming data with memory at packet address +0x80000 and returns 4 on mismatch or 0 on equality. Separate slot +8 reaches programming-like controller code. The storage adapter resolves to a method forming command 03 followed by three address bytes MSB-first; its physical bus and chip are not identified.

Static copying from 0x50C to 0x20000554 supplies 1,044 known bytes out of a requested 2,128. The other 1,084 bytes remain unknown. Within the known prefix, the completion routine reaches an AIRCR software-reset request. No firmware or hardware was executed, and vendor-specific bank-switch semantics remain unverified.

Use packet-reconstructed addresses, not LFU offsets or the abandoned flat mapping from 1H. Constructor links and static control flow do not prove external command exposure or runtime path feasibility. This is a lens-side path, not a camera UPD decryptor.

## Synthetic tests

Repository CI uses Python 3.13. In an isolated environment:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

All 261 tests use synthetic data and need neither firmware nor Capstone. They validate tools, not photographic fidelity. Real-source analysis is separate:

```sh
python -m pip install -r requirements-analysis.txt
python tools/sl3p_lens_verify1j.py
```

That command fetches the pinned public source, verifies identities and framing, and emits selected static checks without executing firmware or saving binaries. The interface/storage exploratory tools retain linear candidate windows; use the final verifier and report for established boundaries. The Capstone distribution/module version distinction documented in 1H remains applicable.

Read-only evidence workflows have no device access, binary artifacts or Git write-back. Main CI is synthetic and does not download firmware. Committed evidence is a reviewed selection, not full logs; checksums do not authenticate vendor signatures. Keep private inputs out of Git; the source guard and .gitignore do not replace manual review.

## Next primary target

Return to a camera-side UPD loading/protection implementation. Pause the lens-peripheral detour unless a specific camera-UPD bridge appears. Do not repeat blind key screens or presume that a lens reset/programming routine contains the camera key.

Base still rendering -> source-calibrated Photon integration -> optional Leica Looks -> video. AF remains separate. No HDR, Cobalt or M-series substitute. Neither 4.2.2 nor another upload is required. No M-series code or APK was changed. Published L-Log mathematics remains a later-video reference, not a recovered still transform.
