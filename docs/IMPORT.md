# Research import provenance

Initialized `mwilliams455/SL3Camera` from the supplied `SL3P_RESEARCH1C_20260927.zip` on 27 September 2026.

Archive SHA-256: `f141f2628b2c0ba9d752e20bfe1d2f7b4226219bb86ad739c65b1e34c4ef9670`.

All files listed in the archive's SHA256SUMS.txt were verified before import. The 12 original tools, four original test files and requirements.txt are imported byte-for-byte; their Git blob hashes were read back from GitHub and matched locally. Original file SHA-256 values are retained in IMPORT_SHA256SUMS.txt. The original 77 tests passed locally immediately before import.

The original handoff is preserved as RESEARCH1C_HANDOFF.md. Its descriptions of environment and completed work refer to the earlier RESEARCH1C session, not newly executed firmware experiments. Its `evidence/` reference describes the original archive. This public repository includes only the selected summary and extended-screen record under evidence/; the complete detailed inventory, raw logs and 1,024 lane results remain in the original research bundle. Do not report these omitted files as published here.

README.md, RESEARCH_STATUS.md, ROADMAP.md and the repository safeguard/CI configuration are new organizational files. They do not change the photographic pipeline or claim new decryption findings. The recorded unsuccessful full firmware screens were not rerun for this import.

No firmware, extracted payloads, downloaded Looks/LUTs, photographs, video, credentials or signing keys were uploaded. Synthetic test constants and temporary fixtures are original test data, not vendor secrets.

## Recheck unchanged baseline source

From the repository root:

```sh
sha256sum -c docs/IMPORT_SHA256SUMS.txt
python -m unittest discover -s tests -v
```

The checksum file is an immutable import reference, not an instruction to prevent future deliberate code changes. Later modifications should have their own commits, tests and evidence status.

## Sources retained from the research report

- First-person UPD-family investigation: https://www.personal-view.com/talks/discussion/21558/leica-q-firmware-hacking
- Cryptography symmetric primitives: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/
- Python random-module documentation: https://docs.python.org/3/library/random.html
- L-Log reference source is recorded in tools/llog_reference.py.

These references do not establish the SL3-P cipher, key or renderer. Source access and substantive research claims are historical RESEARCH1C records unless separately verified in a later experiment.
