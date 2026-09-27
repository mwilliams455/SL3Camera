# SL3Camera

SL3-P firmware research and a future device-independent photographic renderer.

**Current milestone: RESEARCH1H. Four recovered lens components have validated LDAFR packet framing. One reconstructs into a coherent Cortex-M/Thumb image with a static reference to `fwupdate`. The camera UPD protection, base still renderer and APK remain unresolved. All 222 synthetic tests pass.**

This is research source, not a Photon fork. No Leica firmware, reconstructed binary, Looks, private photographs, credentials or signing keys are committed.

## Start here

- [RESEARCH1H report](docs/RESEARCH1H_REPORT.md)
- [Continuation handoff](docs/RESEARCH1H_HANDOFF.md)
- [Selected completed-job measurements](evidence/research1h/summary.json)
- [Validated outer LENS directory in 1G](docs/RESEARCH1G_REPORT.md)
- [Independent section-content recovery in 1F](docs/RESEARCH1F_REPORT.md)

## Current evidence

The official standalone SLLens11.plf plus zero padding exactly matches the protected SL3-P lens section's expected SHA-256. This independent content recovery is not decryption. Its LENS directory and payload CRC-32s were established in 1G.

Four inner payloads are packet streams. All 62,993 packets pass the observed count/address/data/checksum relation. The three observed STOP trailer forms are checked; the extra suffix and prologue-byte meanings remain unknown. Sparse reconstruction preserves gaps instead of inventing bytes.

The component shared by LENS records20–25 has240,369 addressed data bytes in three regions. Its Cortex-M/Thumb interpretation is supported by the vector table, startup transfers and coherent mapped code. The exact chip remains unknown. The corrected fwupdate string address is0x41458; a literal load at0x1e646 is followed by a call to0x25bc0. This reference is outside the current partial exception-seeded traversal. Neither its callee's purpose nor camera-UPD compatibility is established.

**Do not use the provisional flat address0x447e1.** The exploratory sl3p_lens_code1h tool retains that rejected assumption for provenance; use sl3p_ldaf1h and sl3p_sparse_code1h for framed-image work. The ldaf1h workflow records the final interpretation.

## Synthetic tests

Use an isolated Python environment; repository CI uses Python3.13.

```sh
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
```

The222 tests generate synthetic inputs and require neither firmware nor Capstone. They validate research tools, not photographic fidelity, autofocus or Android performance.

## Explicit real-source analysis

```sh
python -m pip install -r requirements-analysis.txt
python tools/sl3p_ldaf1h.py
python tools/sl3p_sparse_code1h.py
```

These commands perform network access, pin the official source identity, check the reconstructed complete lens-section hash and LENS CRCs, and report selected structural/code evidence without saving or executing firmware. Capstone distribution5.0.9 reported module5.0.7/core API[5,0,1280] in the measured jobs; the report preserves those separate values.

Ordinary GitHub CI is synthetic. Separate, read-only research workflows fetch public sources and log bounded evidence; they publish no firmware artifacts or Git write-back. Committed summaries are reviewed selections, not full log archives. CRC and content hashes do not authenticate vendor signatures.

Keep original firmware and any extracted content outside Git or in ignored local-input/output directories. The source-only guard and .gitignore do not replace manual review.

## Next investigation and project order

Trace the enclosing function/callers at0x1e646 and the callee at0x25bc0 before assigning update-handler semantics. Continue looking for a demonstrated camera-UPD protection consumer. Do not restart blind key screens or assume lens-controller code is the camera renderer.

Base still rendering -> Photon integration with independent source-device/active-lens calibration -> optional Leica Looks -> video. AF is separate. No added HDR, Cobalt or M-series stand-in. No4.2.2 or new upload is required. Existing M-series projects are unchanged. Published L-Log mathematics remains a later-video reference, not a recovered still-photo transform.
