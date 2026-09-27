# SL3-P research — RESEARCH1G

27 September 2026. Target: supplied SL3-P 4.2.1. Stage: firmware access and base still-renderer research.

## Result

The independently reconstructed lens region can now be divided using a validated LENS directory layout. The 4,575,234-byte `SLLens11.plf` contains 40 directory entries, 14 absent entries, and 26 nonempty references to 20 distinct payload ranges. All 20 distinct payloads match the CRC-32 values declared in their records. The header and unique payloads account for the whole standalone file, with no gaps, partial overlaps or unexplained trailing bytes.

A second independently hash-pinned file, `70200_11.plf`, validates the same 19-byte record structure and checksum convention after explicitly recognizing its all-ones absent-entry sentinel. It has two records: one absent and one 1,573,888-byte payload with a matching CRC-32. Its payload has no complete size/SHA-256 match among the 20 payloads of SLLens11.

This is not camera-payload decryption, key recovery, a recovered camera update handler, or a still renderer. No instruction architecture, runtime load mapping or executable call graph was established. There is no APK.

## Provenance and reproducible execution

The primary file was fetched again from Leica's official HTTPS endpoint, pinned to both its full size and SHA-256. Its reconstruction to the entire 20 MiB section passed the original section hash again before any record interpretation.

| Input | Bytes | SHA-256 |
|---|---:|---|
| Supplied SL3-P 4.2.1, unchanged local rehash | 201,752,064 | b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 |
| SLLens11.plf | 4,575,234 | 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600 |
| SLLens11 followed by zero fill to the target section size | 20,971,520 | 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1 |
| 70200_11.plf | 1,573,978 | 4e26dce0ec3a4e64454b46e9df9d4dcdfb319be6a3cb479fb95521fe0ed70d32 |

Official sources:
- https://leica-camera.com/sites/default/files/SLLens11.plf
- https://leica-camera.com/sites/default/files/70200_11.plf
- Leica catalogue listing the first asset as Firmware SL Lenses: https://leica-camera.com/en-GB/downloads?field_media_document_language=984&page=2

Local DNS still failed; actual acquisitions and real-data calculations ran in isolated GitHub Actions. The firmware bytes stayed in memory and were not executed or published as artifacts. Reports contain container fields, selected fixed-term locations and numeric measurements, not payload dumps or UPD cryptographic metadata.

Final real-source verification: run **36338148378**, job **108672861989**, commit **2f84e853464b80cc586a88bc463d2bea87e026df**. Its output explicitly records `all_payload_crc32_verified: true` for both files. A green audit job alone should not be used to infer that an arbitrary future comparison parsed correctly; examine the recorded per-file result.

## Validated structure

The fixed opening marker is 21 bytes. The count is an unsigned big-endian 16-bit value at file offset 29. The table begins at offset 31. An exact 21-byte EOH marker follows the table. Thus payload storage begins at `52 + 19 * count`: byte 812 for SLLens11 and byte 90 for 70200.

Each 19-byte record is interpreted as `>HBIIII`:

| Relative byte offset | Width | Measured role |
|---|---:|---|
| 0 | 2 | Big-endian ordinal, matching the zero-based record position |
| 2 | 1 | Kind/category value; roles 0 and 1 remain unknown |
| 3 | 4 | Big-endian selector; not established as a model ID, address or version |
| 7 | 4 | Big-endian absolute file offset for a present payload |
| 11 | 4 | Big-endian byte length, except the explicit absent sentinel |
| 15 | 4 | Big-endian CRC-32 of the declared present payload |

Offsets and lengths are supported by exact whole-file coverage, CRC matches and validation on two files. The selector's semantic interpretation is deliberately not promoted by its numeric pattern. Header words resembling a version or date likewise remain recorded values, not a verified release date.

## CRC-32 result

For every distinct present payload, the stored final record word equals `zlib.crc32(data[offset:offset+size])`, i.e. the tested CRC-32/ISO-HDLC convention. Other tested candidates included alternate reflected initialization/final XOR conventions, non-reflected MPEG-2/BZIP2 forms, Adler-32 and a byte sum. Only CRC-32/ISO-HDLC matched consistently across all 20 primary payloads and the secondary payload.

This is an unkeyed corruption check, not authentication and not the camera's encryption mechanism. Absent entries are not counted as CRC-verified payloads. Shared references to one byte range are not counted as separate images.

`parse_layout` enforces structural bounds and coverage; `verify_lens` additionally requires at least one payload and all present payload CRC-32 checks. Corruption that preserves the header and file length is rejected by `verify_lens`.

## Shared data and absent-entry encodings

Records 20–25 all reference the same range: offset 2,458,563, length 251,417. Records 28–29 share a second range: offset 2,727,144, length 125,206. Different selector values therefore do not necessarily correspond to independent stored payloads.

The first file's 14 absent records all have kind 2 and zero length; their unused offsets/check values vary. The second file uses kind 2 with offset, length and check all `0xffffffff`. The initial strict parser treated this as an out-of-bounds length and rejected it. The final parser recognizes exactly this kind-2/all-three-words sentinel, while retaining all ordinary bounds checks. Tests reject partial sentinels and the same all-ones values under another kind.

Intermediate failed run: 36337873828, job108672096667. That was a parser-discovery failure, not evidence of corrupt Leica firmware. Follow-up run36337969677 retained the validated primary result and reported the still-rejected comparison. Final run36338148378 validated both files with the explicit sentinel support.

## Update-related lead localized

The previously observed case-insensitive `fwupdate` term is at byte 247,797 inside the 251,417-byte shared payload referenced by records20–25. It is at absolute standalone-file offset2,706,360. Payload SHA-256:

`970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db`

The measured token is only `fwupdate`, not a demonstrated function name. No caller, control-flow path, CPU architecture or camera-UPD parsing routine has been identified. A lens update component may be entirely separate from the camera updater. The selected signature scan does not establish an executable format; short S0 matches are not valid Motorola S-record files by themselves.

This pass provides a precise checksum-verified candidate for subsequent inner-format and code analysis, not a claim that the protection consumer is present.

## Validation and retained files

Nineteen new synthetic tests cover complete coverage, shared ranges, alias checksum conflicts, ordinal/count/EOH failures, bounds, partial overlap, corruption, the exact all-ones sentinel, rejection of malformed sentinels, and non-vacuous checksum verification. All 175 local tests passed (156 inherited plus19 new). The real-source run passed all19 new tests before accessing the two real files. Cumulative main-branch CI status is recorded separately after publication.

New files:
- `tools/sl3p_lens_layout_probe1g.py`: retained exploratory header measurements; not a validated payload parser.
- `tools/sl3p_lens_records1g.py`: range audit, checksum hypotheses, strict `verify_lens`, and explicitly pinned real-source command.
- `tests/test_lens_records1g.py`.
- `.github/workflows/lens-layout1g.yml`: separate read-only real-source workflow.
- `evidence/research1g/lens_records_summary.json` and `unique_payloads.csv`: reviewed selected-field transcription, not a full log archive.

No original binary, reconstructed payload, private image, Look, credential or key was committed. Existing M-series projects were not touched.

## Next substantive target

Investigate the inner format and instruction architecture of checksum-verified payloads, prioritizing the shared251,417-byte payload containing the update-related token. Establish an address mapping and actual code references before assigning update-handler semantics. Do not treat kind0 as code or kind1 as calibration solely from their sizes. A focused format/ISA probe is warranted; another blind camera-key list is not.

The camera's protected main program remains unopened. The photographic sequence remains SL3-P base still rendering, Photon integration with independent source-device/lens calibration, optional Looks, then video. No 4.2.2 or further user upload is required for this next step.
