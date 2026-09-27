# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1F. The intended contents of the protected 20 MiB lens section are recovered from an independently distributed official lens file plus zero padding, with a complete expected SHA-256 match. This is NOT decryption or a camera renderer. All 156 synthetic tests pass. No SL3-P cipher/key, base still-image pipeline or APK has been recovered.**

This repository contains inspection tools, synthetic tests and reviewed derived evidence. It contains no Leica firmware, extracted proprietary payloads, downloaded Looks, private photographs, video, credentials or signing keys. It is not a Photon fork.

## Start here

- [RESEARCH1F report](docs/RESEARCH1F_REPORT.md)
- [RESEARCH1F continuation handoff](docs/RESEARCH1F_HANDOFF.md)
- [Selected completed-job measurements](evidence/RESEARCH1F_SUMMARY.json)
- [SL3-P 4.2.1 comparison fingerprints](evidence/SL3P_421_COMPARISON_BASELINE.json)
- [Earlier SL3/SL3-P comparison](docs/RESEARCH1E_REPORT.md)
- [Project roadmap](docs/ROADMAP.md)
- [Original import provenance](docs/IMPORT.md)

Earlier reports remain historical records. RESEARCH1F supersedes statements that no nonconstant intended section content is available, while the camera protection method and still renderer remain unresolved.

## Current finding

Official SLLens11.plf has 4,575,234 bytes. Appending 16,396,286 zero bytes produces exactly the complete expected hash of SL3-P section33 lens, also measured in SL3 and SL2. The standalone source identity was pinned and the full target verified in a second successful GitHub job. Most of the 20 MiB region is padding, not executable code.

The source begins with LENS-UPDATE-FILE-SOF: and has LENS-UPDATE-FILE-EOH: at offset791. Record layout, payload architecture and update-consumer semantics are still unvalidated. A firmware-update term does not identify a camera UPD decryption routine.

SL2 6.3.0 and Q2 Monochrom5.1.0 pass the observed UPD parser but expose no directly hash-verified nonconstant bytes. Their small loader1 expected hashes match each other; this is an identity lead, not a readable or SL3-P-compatible loader. The SL601 endpoint tested returned HTML-like content and was rejected as firmware.

The prior shared recognition-resource expected hashes and differing LUT-region sizes remain findings about packaged resources, not recovered autofocus or Look implementations.

## Run synthetic tests

Use Python3.13 in an isolated environment:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The suite has156 tests:129 inherited through RESEARCH1E and27 new in RESEARCH1F. Fixtures are synthetic; no firmware or camera is needed. Passing tests validate tools and reference mathematics, not photographic fidelity, autofocus, video or Android performance.

## Local firmware inspection

Keep original firmware outside the checkout, or in ignored inputs/. Never force-add it to Git.

```sh
python tools/sl3p_inspect.py '/absolute/path/SL3P_421 (1).lfu' --out outputs/inspection
```

Input is read-only. Optional extraction removes only outer byte inversion; it does not decrypt protected sections. Keep outputs in ignored directories and review evidence before publishing it.

## Separate real-source experiments

Research tests CI is synthetic and does not download firmware. Explicit source-evidence workflows are separate, read-only jobs: they fetch named public Leica sources, inspect without execution, and log selected hashes/counts/offsets or header candidates. They publish no binary artifacts or raw UPD cryptographic metadata and perform no Git write-back. Probe push triggers are restricted to their research branches and named files.

The independently pinned lens verification is:

```sh
python tools/sl3p_lens_plaintext1f.py --baseline evidence/SL3P_421_COMPARISON_BASELINE.json --out outputs/lens-check.json
```

This command performs network access, requires the exact recorded source and target hashes, reconstructs in memory and outputs only a numerical report. It does not save firmware. Full job logs are identified in the report; committed summaries are reviewed selections, not complete archives. CRC and content hashes do not authenticate a vendor signature.

## Development sequence

Base still-image renderer -> Photon integration -> optional Leica Looks -> video. Autofocus/recognition is separate. Source-device and active-lens calibration must remain separate from the portable Leica target. Do not introduce HDR, Cobalt or an M-series substitute for the unknown base renderer.

Next: validate the recovered LENS layout and executable candidates, while pursuing an actual UPD protection consumer. Known plaintext provides a useful exact test but does not reveal a key by itself. Do not relaunch previous blind key screens as new research. Related model firmware is never permission to cross-flash cameras. No4.2.2 or Look upload is required.

`tools/llog_reference.py` preserves published video mathematics, not an extracted SL3-P still transform. `.gitignore` and the tracked-file guard reduce accidental uploads but do not replace manual privacy/licensing review. No software license was selected during initialization.
