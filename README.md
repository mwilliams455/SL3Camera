# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1G. The independently recovered lens region now has validated directory boundaries and CRC-32 checks: 40 entries, 14 absent entries, 26 nonempty references, 20 distinct payloads. A second lens package validates the same structure with an explicit absent-entry sentinel. The suite contains 175 synthetic tests. No camera-payload decryptor, key, base still renderer, autofocus implementation or APK has been recovered.**

This repository contains inspection tools, synthetic tests and reviewed derived evidence. It contains no Leica firmware, extracted proprietary payloads, downloaded Looks, private photographs, video, credentials or signing keys. It is not a Photon fork.

## Start here

- [RESEARCH1G report](docs/RESEARCH1G_REPORT.md)
- [RESEARCH1G continuation handoff](docs/RESEARCH1G_HANDOFF.md)
- [Selected completed-job measurements](evidence/research1g/lens_records_summary.json)
- [Unique lens payload inventory](evidence/research1g/unique_payloads.csv)
- [Independent lens-content recovery in RESEARCH1F](docs/RESEARCH1F_REPORT.md)
- [SL3-P 4.2.1 comparison fingerprints](evidence/SL3P_421_COMPARISON_BASELINE.json)
- [Project roadmap](docs/ROADMAP.md)

Earlier reports remain historical records. 1F recovered intended section contents from an independently distributed official source, not by decrypting update bytes. 1G validates the lens container's record structure, not its instruction architecture or camera-update semantics.

## Current result

Official SLLens11.plf has 4,575,234 bytes. Appending 16,396,286 zero bytes produces the complete expected SHA-256 of SL3-P section33 lens, also measured in SL3 and SL2. Most of that 20 MiB region is padding.

The lens file contains a 31-byte fixed header, 40 records of19 bytes, a21-byte EOH marker, and20 distinct payload ranges covering the rest of the file exactly. All20 declared CRC-32 values match. Six records share one251,417-byte payload; two others share a125,206-byte payload. Forty records do not mean40 distinct lenses or images. Selector and kind0/1 meanings remain unestablished.

The separate70200_11.plf contains two records and one1,573,888-byte payload. Its other record uses kind2 and three all-ones fields as an absent-entry sentinel. Both files pass bounds, exact-coverage and CRC checks. The initial rejection of this sentinel is documented rather than hidden.

The existing fwupdate string is now localized to the checksum-verified payload shared by records20–25. No callable function, instruction architecture, address mapping or camera-UPD consumer has been established. Lens and camera update paths may be separate.

## Run synthetic tests

Use Python3.13 in an isolated environment:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The suite contains175 tests:156 inherited plus19 new in1G. Fixtures are synthetic; no firmware or camera is required. Passing tests validate tools and reference mathematics, not photographic fidelity, autofocus, video or Android performance.

## Local firmware inspection

Keep original firmware outside the checkout, or in ignored inputs/. Never force-add it to Git.

```sh
python tools/sl3p_inspect.py '/absolute/path/SL3P_421 (1).lfu' --out outputs/inspection
```

Input is read-only. Optional extraction removes only outer byte inversion; it does not decrypt protected sections. Keep outputs in ignored directories and review evidence before publishing it.

## Separate real-source experiments

Research tests CI is synthetic and does not download firmware. Explicit source-evidence workflows are separate read-only jobs. They fetch named public Leica sources, inspect without execution, and log selected structural fields, hashes and fixed-term locations. No binary artifacts, raw UPD cryptographic metadata or Git write-back are produced. Push triggers are restricted to the relevant research branch and named files.

```sh
python tools/sl3p_lens_records1g.py
```

This command performs network access, requires the recorded standalone identities and complete primary lens-section hash, validates ranges and payload CRCs, and prints a selected JSON report. Check both per-file all_payload_crc32_verified fields: an unfamiliar rejected comparison can be reported separately. It does not save or execute firmware. Full job identifiers are in the report; committed evidence contains reviewed selections, not complete log archives. Content hashes and CRC do not authenticate a vendor signature.

## Development sequence

Base still-image renderer -> Photon integration -> optional Leica Looks -> video. Autofocus/recognition is separate. Source-device and active-lens calibration remain separate from the portable target. Do not introduce HDR, Cobalt or an M-series substitute for the unknown base renderer.

Next: determine inner payload formats and defensible instruction/address mappings, then trace actual references to the localized update-related string. Do not promote a string into a decryption handler or relaunch prior blind key screens. Related-model firmware is never permission to cross-flash cameras. No4.2.2 or Look upload is required.

`tools/llog_reference.py` preserves published video mathematics, not an extracted SL3-P still transform. `.gitignore` and the tracked-file guard reduce accidental uploads but do not replace manual privacy/licensing review. No software license was selected during initialization.
