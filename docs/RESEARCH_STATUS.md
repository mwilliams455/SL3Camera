# Research status — RESEARCH1C

Recorded baseline: 27 September 2026. Repository initialization is organizational work, not a new firmware breakthrough.

## Verified container observations

The supplied `SL3P_421 (1).lfu` is 201,752,064 bytes with SHA-256 `b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8`.

Removing the outer XOR-FF transform exposes the tested UPD/leica/MC7251 wrapper. The directory begins at 0x2ec, contains 61 records of 92 bytes each, and covers the payload from 0x1a00 to EOF. Section file offsets use base 0x200. CRC-32 9de57378 matches. These are consistency checks, not vendor-signature authentication.

46 flag-3 sections remain opaque. All 15 flag-2 section hashes match directly; those records are empty or constant-fill. The 8.375 MiB `lut_data` region is zero-filled and hash verified. Its update/storage semantics remain unknown.

Two protected 128 KiB records, indexes 8 and 10, have expected hashes matching all-FF content. Four equal-size/equal-expected-hash pairs (8/10, 15/16, 19/20 and 21/22) have differing stored representations and differing 16-byte metadata.

## Inferences, not recovered implementation

Under the expected-content-hash interpretation, the 16-byte field cannot be a deterministic plaintext-only fingerprint. This does not identify it as an IV, salt, key or authentication tag. Neither entropy nor section labels identify a cipher, CPU architecture, network model or rendering algorithm. Target offsets are not established runtime addresses.

Recognition-related names, the large `lens` region and calibration-like labels are investigation targets only. Downloadable FOTOS Looks are a plausible explanation for reserved LUT storage, not a demonstrated explanation of this section.

## Completed bounded tests

RESEARCH1B audited 173,040,640 opaque bytes in 42,246 complete 4 KiB tiles plus two 512-byte records. No complete tile was below entropy 7.8. This does not exclude small plaintext islands or prove encryption.

RESEARCH1C tested 252 selected known-fill/context checksum expressions, 14 global-field digest hypotheses and 12 raw public-point interpretations: no matches. Its specified direct AES-mode/key/byte-convention screen tested 85,995 distinct generated candidate keys: no prefix hits. This does not identify or reject AES generally, nor eliminate unknown keys or other derivations.

The specified complete-word MT19937, xorshift128 and bounded binary-recurrence tests had no accepted held-out predictions. They do not exclude arbitrary generators or prove cryptographic strength. See the preserved tool implementations and continuation handoff for exact scopes.

## Validation versus photographic progress

All 77 original unit tests passed again before import. The imported tools, tests and dependency file were checked against the original archive by complete Git blob hashes. Tests include positive controlled decoding cases and a prefix-success/full-hash-failure case.

No real SL3-P protected plaintext, still-rendering curve, colour matrix, processing order, autofocus implementation or video path has been recovered. There are no photographic, GPU, Android, codec or camera-performance validation results.

## Next research gate

Find evidence of the actual package-loading/protection implementation, or a demonstrably related unprotected component that supplies a testable hypothesis. Do not repeat the same failed key generator under a new label. A second firmware version is optional; 4.2.2 is not required.

Before interpreting nonconstant code/resources, require the full expected section length and SHA-256, then independently establish architecture, mapping and resource structure. Preserve the priority of the base still renderer over Looks and video.
