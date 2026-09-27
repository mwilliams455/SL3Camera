# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1C imported. No protected SL3-P payload has been decoded. There is no SL3-P renderer or APK yet.**

This repository contains read-only inspection tools and synthetic tests. It does not contain Leica firmware, extracted proprietary payloads, downloaded Looks, private photographs, video, credentials or signing keys. It is not a Photon fork.

## Start here

- [Research status and evidence boundaries](docs/RESEARCH_STATUS.md)
- [RESEARCH1C continuation handoff](docs/RESEARCH1C_HANDOFF.md)
- [Project roadmap](docs/ROADMAP.md)
- [Import provenance and original file checksums](docs/IMPORT.md)
- [Selected evidence summary](evidence/RESEARCH1C_SUMMARY.json)

## Run the tests

Use Python 3.13 in an isolated environment:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The baseline has 77 synthetic tests. They generate their own fixtures in temporary directories; no real firmware or camera is needed. Passing tests validate the research tools and reference mathematics, not SL3-P image fidelity, autofocus, video or Android performance.

## Local firmware inspection

Keep your original firmware outside the checkout, or in the ignored `inputs/` folder. Never force-add it to Git.

```sh
python tools/sl3p_inspect.py '/absolute/path/SL3P_421 (1).lfu' --out outputs/inspection
```

The input is read-only. Optional extraction removes only the outer byte inversion; protected sections remain opaque. Store any output under ignored `outputs/`, `extracted/` or `private/`, and manually review any evidence before publishing it.

The other tools retain completed experiments for reproducibility. Do not rerun the same unsuccessful key screen as a new research milestone. The next investigation needs evidence about the actual loader/protection implementation.

## Development sequence

Base still-image renderer -> Photon integration -> optional Leica Looks -> video. Autofocus/recognition is a separate investigation. Source-device and active-lens calibration must remain separate from the portable Leica target. Do not add HDR processing, a Cobalt dependency or an M-series substitute for the unknown SL3-P rendering pipeline.

`tools/llog_reference.py` is a published-equation reference component preserved for later video work, not an extracted SL3-P still-photo transform.

The synthetic CI workflow uses read-only repository permissions and does not download, process or publish firmware. `.gitignore` and the tracked-file guard reduce accidental uploads but do not replace manual privacy/licensing review. No software license was selected during initialization.
