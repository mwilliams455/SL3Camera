# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1E. Official SL3 4.2.0 compared with the supplied SL3-P 4.2.1; 129 synthetic tests pass. No protected SL3-P payload has been decoded. There is no SL3-P renderer or APK yet.**

This repository contains inspection tools, synthetic tests and reviewed derived evidence. It does not contain Leica firmware, extracted proprietary payloads, downloaded Looks, private photographs, video, credentials or signing keys. It is not a Photon fork.

## Start here

- [RESEARCH1E results and next investigation](docs/RESEARCH1E_REPORT.md)
- [Selected RESEARCH1E measurements and completed run identifiers](evidence/RESEARCH1E_SUMMARY.json)
- [SL3-P 4.2.1 comparison fingerprints](evidence/SL3P_421_COMPARISON_BASELINE.json)
- [Project roadmap](docs/ROADMAP.md)
- [Original import provenance](docs/IMPORT.md)

Earlier [RESEARCH1C status](docs/RESEARCH_STATUS.md) and [handoff](docs/RESEARCH1C_HANDOFF.md) remain historical records; RESEARCH1E supersedes their current-status and source-access statements. The previously unpushed RESEARCH1D pair of tools and 29 tests are now included without source changes.

## Current findings

SL3 and SL3-P share the measured 61-entry UPD layout. Of 46 protected SL3-P sections, 25 have size and expected-content-hash matches in SL3; 23 remain after excluding the two already-known all-FF regions. All eight numbered hm_d_nw candidates and hm_d_reid match expected-content hashes, but no recognition model or autofocus implementation has been decoded. Main program and loader hashes differ. Different models and versions prevent attributing all changes solely to the P model.

Both lut_data regions are verified zero fills, but their sizes differ: SL3 2.125 MiB versus SL3-P 8.375 MiB. This does not identify Look format, count, precision or update policy. M11-P 2.6.4 was successfully decompressed, but no exact UPD-family marker or compatible protection consumer was established by the bounded scan.

## Run the synthetic tests

Use Python 3.13 in an isolated environment:

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The suite has 129 tests: 77 inherited through RESEARCH1C, 29 from RESEARCH1D, and 23 new RESEARCH1E tests. They generate their own fixtures in temporary directories; no real firmware or camera is needed. Passing tests validate tools and reference mathematics, not SL3-P image fidelity, autofocus, video or Android performance.

## Local firmware inspection

Keep original firmware outside the checkout, or in ignored inputs/. Never force-add it to Git.

```sh
python tools/sl3p_inspect.py '/absolute/path/SL3P_421 (1).lfu' --out outputs/inspection
```

Input is read-only. Optional extraction removes only the outer byte inversion; protected sections remain opaque. Keep outputs under ignored outputs/, extracted/ or private/, and review evidence before publishing it.

## Separate real-source experiments

Research tests CI is synthetic and does not download firmware. The three 1E source-evidence workflows are separate, read-only jobs: they download named public Leica sources, inspect them without execution, and log only selected hashes/counts/offsets and comparison results. They publish no firmware artifacts and perform no Git write-back. Their push triggers are restricted to the research/loader-consumer1e branch and named probe files. The pinned pair probe checks both the measured SL3 file SHA-256 and the canonical SL3-P fingerprint projection.

Full job logs are referenced by run ID in the report; committed summaries are selected measurements, not complete log archives. CRC and content hashes do not authenticate a vendor signature.

## Development sequence

Base still-image renderer -> Photon integration -> optional Leica Looks -> video. Autofocus/recognition is a separate investigation. Source-device and active-lens calibration must remain separate from the portable Leica target. Do not introduce HDR, a Cobalt dependency, or an M-series substitute for the unknown SL3-P renderer.

The next substantive target is a readable, validated UPD-family loading/protection consumer. Do not relaunch the same unsuccessful key screens as new research. A different model's firmware is a comparison source, never permission to flash it onto an SL3-P.

`tools/llog_reference.py` preserves published video reference mathematics; it is not an extracted SL3-P still transform. `.gitignore` and the tracked-file guard reduce accidental uploads but do not replace manual privacy/licensing review. No software license was selected during initialization.
