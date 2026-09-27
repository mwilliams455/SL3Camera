# SL3-P handoff — RESEARCH1I

27 September 2026. Repository mwilliams455/SL3Camera. Research branch research/lens-callsite1i. Start from the live main ref; do not assume a historical hash is current.

## Main finding

A lens-side LDAFR consumer is now identified through actual constructor and method references. This is NOT camera-UPD decryption, key recovery or base still rendering. No APK exists.

Pinned source SLLens11.plf: 4,575,234 bytes, SHA256 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600. Appended zeros to 20,971,520 bytes match the original lens-section SHA256 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1. Source URL https://leica-camera.com/sites/default/files/SLLens11.plf .

Target inner SHA256 970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db. Use sl3p_ldaf1h.verify_packets and SparseImage, never the obsolete flat mapping. Original SL3-P SHA256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 remains unchanged.

## Established code chain

- 0x25BC0: ASCII case-insensitive string comparator; -1/0/+1. Helper 0x2E830 folds only A–Z. Not a decryptor.
- 0x1DB18: Memory command method; entry-relative CFG reaches fwupdate at 0x1E646; common return at 0x1E68A. Name method 0x1E68E returns Memory. Method table 0x40130 contains odd pointers 0x1DB19 and 0x1E68F.
- Constructor 0x1DAF8 installs table and stores fourth argument at +0x0C. The branch checks a parsed numeric argument and case-insensitive fwupdate, subtracts 0xC00, calls backend slot +8, then slot +12 if low-byte status is zero.
- Initialization near 0xB890 constructs reader via 0x11A18, backend via 0x11B78, then Memory via 0x1DAF8. Backend object 0x2000ACFC; Memory object 0x2000AC28; these are static operands, not measured live objects.
- Backend table 0x3ECB4: pointers 0x11B93, 0x11C43, 0x11D41, 0x11E39, 0x11E4B. Relevant code: 0x11D40 record loop and 0x11E38 destination completion delegation.
- Reader table 0x40028: pointers 0x11A35 and 0x11AB9. Opening reader 0x11A34 checks LDAFR, copies byte5, and decodes opening bytes6..9 LITTLE-endian. Normal reader 0x11AB8 checks LDAFR, validates complemented sum over count/address/data, stores N-5 length, decodes normal address BIG-endian, and recognizes STOP via direct character comparisons.
- Backend progresses by length+11 after a ten-byte prologue. STOP suffix meaning remains unknown; inspected reader tests only STOP prefix. Do not weaken offline file bounds to imitate the firmware's fixed 0x109-byte I/O request.

## Next experiment

Identify the backend destination object supplied from 0x2000ADA0 and the reader's storage interface supplied from 0x2000AC9C. Trace their constructors/table stores. Destination slot +0x0C receives address, data and length; slot +0x10 is called by 0x11E38. Do not name these physical flash writes or reset until resolved. Then assess the value of this lens route for the separate camera-UPD protection investigation; do not assume a shared cipher or processor.

Do not repeat old key lists or claim a renderer from this result. Preserve base stills -> source-calibrated Photon -> optional Looks -> video. No HDR, Cobalt, M-series substitute, cross-flashing or changes to other camera projects.

## Validation and files

240 pure unit tests pass (222 inherited +18 new). The final real-source run 36345916740 / job108694896433 at commit92a87b8932fe3c8a2c111bcc83397cf5a58a70cf also passes 2,048 additional synthetic BL target comparisons against Capstone and selected evidence assertions. Publication commit and main CI are in delivered evidence/research1i/repository_status.json.

New tools: sl3p_lens_callsite1i.py, sl3p_lens_semantics1i.py, sl3p_lens_dispatch1i.py, sl3p_lens_backend1i.py. Test file test_lens_callsite1i.py. Analysis dependencies are separate in requirements-analysis.txt. The initial tool's linear windows are exploratory; use semantic/constructor/reader results for conclusions.

Local DNS and Capstone were unavailable; do not claim local real-firmware disassembly. GitHub Actions acquires the pinned public source into memory, validates it and performs static analysis only. No firmware execution/emulation or binary artifact upload. Source-only public repo; keep firmware, extracted data, Looks and private photos out of commits. The downloadable research bundle is cumulative source/evidence, not a complete repository export; older reports retain historical statuses.
