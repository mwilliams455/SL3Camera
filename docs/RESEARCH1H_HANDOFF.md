# SL3-P continuation handoff — RESEARCH1H

Date: 27 September 2026. Repository: mwilliams455/SL3Camera. Research branch: research/lens-inner1h. Real-source validated code commit: 635d5b7998958aa4742ce7648c9b88cd935e3830. Final main publication is recorded separately in delivery evidence.

## User direction

Continue the existing SL3-P 4.2.1 investigation. Base still-image rendering first, Photon integration with independent source-device/active-lens calibration, optional Leica Looks second, video later. No HDR, Cobalt or M-series stand-in for an unknown SL3-P transform. No requirement for 4.2.2 or another user upload. Do not spend another turn rerunning old blind key screens. Existing camera projects must remain untouched.

## Established input identity

Original SL3P_421 (1).lfu: 201752064 bytes, SHA256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8. UPD directory 61 entries; 46 opaque. No camera cipher/key/main-program decryption.

Independent official source https://leica-camera.com/sites/default/files/SLLens11.plf : 4575234 bytes, SHA256 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600. Appended zeros to20971520 bytes match lens section33 expected SHA256 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1. This is independent recovery, not camera decryption.

Inherited verify_lens establishes40 LENS records,14 absent,20 unique CRC32-verified ranges. Target records20–25 share offset2458563,length251417,SHA256 970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db.

## New inner framing

Four unique payloads (20–25,28–29,38,39) begin LDAFR. First10 bytes are a special prologue: marker5,unknown byte1,addressFFFFFFFF4. Do not interpret its unknown byte as count.

Normal packet: LDAFR5,countN1,addressBE4,data(N-5),checksum1. Total6+N. Count/address/data/checksum byte sum mod256 equals255. Parse by lengths, not marker searching. All62993 packets across four payloads pass (62991 carry data). STOP trailers are exactly STOP, STOP00, STOP01 in measured files. Optional suffix/prologue meanings and zero-data final packet semantics remain unknown.

Use tools/sl3p_ldaf1h.py verify_packets. It checks whole observed framing, data presence, checksums, sparse overlaps and bounds. Do not concatenate payloads as flat code. Sparse ranges retain holes as unavailable and never allocate the full32-bit address span.

Target regions (end exclusive):
- 0x0..0x920,2336 bytes; SHA256 ed6a1bcf2d3eaa01f7af76eef6c74a0b6a95b3cfdb6cba913bc7b8a9154e26b4.
- 0x8000..0x421c9,238025 bytes; SHA256 67f94d8b46544972d1c4439bc2b0284f183742208207cd01828f98ada79add96.
- 0x7fff0..0x7fff8,8 bytes; SHA256 4fcb18d9ded612b8c2da8ab27a180d687b6fed0bc5de0d9100e89db948fe0af8.

## Code interpretation and next target

tools/sl3p_sparse_code1h.py uses actual packet addresses and mapped-byte-only instruction/literal reads. Cortex-M/Thumb interpretation strongly supported, exact chip unknown. Vector table at0; MSP0x2000d298; reset pointer0x40309. Startup at0x40308 resolves literal-loaded calls to0x418 and0x7c4, then tail branch0x415e6.

Partial exception-seeded traversal11893instruction starts,2419direct edges allmapped,220unresolved indirect stops,274return/PCwrite stops,6traps. Not a complete call graph or execution proof. Do not turn these metrics into a decryption claim.

Correct fwupdate string address0x41458. Old flat assumption0x447e1 is INVALID/superseded. Literal pool0x1e788 contains0x41458. Instruction0x1e646 loadsR0;0x1e648 calls0x25bc0;0x1e64c comparesR0 with0;0x1e64e branches0x1e680 if nonzero. This reference was not reached by the partial seeded walk; it was located as a separate static literal reference.

NEXT: identify the enclosing function and callers around0x1e646 and inspect0x25bc0's argument handling. Establish whether this is a name lookup, command dispatch or update path. Do not label0x25bc0 a decryptor/file-open/flash function yet. The lens update subsystem may be unrelated to camera UPD protection. Further tracing should be bounded and grounded in this exact image, not guesses about camera hardware.

## Reproduction and validation

222 local and GitHub synthetic tests pass. 47new tests =12inner+8flat-helper+17LDAF+10sparse. Final source job36339912507/job108677847487/commit635d5b7998958aa4742ce7648c9b88cd935e3830 also passes3independent operand checks and2complete synthetic sparse traversals. These extra5 are not included in the222unit-test count.

Capstone pip distribution5.0.9; moduleversion5.0.7; coretuple[5,0,1280]. Preserve all values. Capstone was not installed locally; real binary reads/disassembly were performed on GitHub in memory. Local network unavailable. No firmware execution, binary upload or M-series changes.

Commands: python -m pip install -r requirements.txt; python -m unittest discover -s tests -v. For explicit network/disassembly: python -m pip install -r requirements-analysis.txt; python tools/sl3p_ldaf1h.py; python tools/sl3p_sparse_code1h.py. Existing lens-inner1h workflow and sl3p_lens_code1h tool retain exploratory FLAT hypotheses; use the ldaf1h workflow for final packet-addressed evidence.

docs/RESEARCH1H_REPORT.md and evidence/research1h/summary.json preserve reviewed measurements. They are not complete execution-log archives. Require actual source acquisition, pinned hashes, LENS CRCs and LDAFR checks before claiming any fresh binary result. Base SL3-P still renderer, camera protection and APK remain unresolved.
