# SL3-P continuation — RESEARCH1J

28 September 2026. Repository: mwilliams455/SL3Camera. Research branch: research/lens-interfaces1j. Parent main: 652644d1174f2d0a451a3beddae3b49c838a5991. Publication commit and main CI are recorded in delivered evidence/research1j/repository_status.json after finalization.

## Result and limits

A constructor-linked lens storage/verification/completion path is now understood. Camera UPD decryption, its key, and the SL3-P base still renderer remain unresolved. No APK. The lens code is not the camera image processor. Do not use the superseded flat mapping from 1H; all addresses below are packet-reconstructed or statically relocated.

The original SL3-P file remains 201752064 bytes, SHA-256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8, rehashed unchanged in this pass. acquire_image() requires the official SLLens11.plf identity, the complete padded lens-section hash, LENS CRCs and LDAFR checks before analysis. No binary was published, emulated or run.

## New established chain

- Destination object operand 0x2000ADA0: ctor 0xDA04 called at 0xADAA, installs table 0x904.
- Slots: +0 -> 0x738; +4 -> 0x740; +8 -> 0x762; +12 -> 0x770; +16 -> 0x796.
- 1I's backend 0x11D40 calls destination +12 for packet data. This is **verification**, not programming: compare bytes at packet address + 0x80000, return 4 mismatch / 0 equal. Complete method [0x770,0x796), 18 instruction starts. No calls or packet-data writes.
- Separate +8 forwards to veneer 0x728 and a programming-like controller routine. Do not conflate these slots.
- Reader's underlying object 0x2000AC9C: ctor 0x10870, table 0x3E4D8, method +8 -> 0x108A0. Forwards to member +8, table slot +0x2C.
- That storage member: ctor 0x1036C, table 0x3BDBC, slot +0x2C -> 0x10454. Builds 03 plus three address bytes MSB-first and forwards read request. Exact physical bus/chip not identified.

## RAM copy and reset

Copy loop 0x7A0 copies 0x214 words from 0x50C to 0x20000554: 2128 bytes requested, only 1044 supplied, 1084 unknown. relocate_known_ranges() preserves missing regions; no filler or complete RAM image. All inspected routines/literal pools are within the available prefix.

Veneers 0x720/0x728/0x730 -> RAM 0x2000058C/0x200005FA/0x200006C6, corresponding source 0x544/0x5B2/0x67E. The final routine calls reset helper 0x20000554 at 0x2000073C. Reset helper loads AIRCR 0xE000ED0C, preserves 0x700, ORs 0x05FA0004, stores, DSB, waits. This is a software-reset request; no physical reset occurred. Earlier vendor-register commands are not a verified bank-switch specification.

## Reproducibility

261 pure tests pass locally and in final source job 36383716961/job108804596111, source commit 3874e9e23acdd0d7851269b27978526bb780cb39. The job also checks a synthetic relocated literal, two BL targets and preservation of a missing tail, then asserts selected real-source identities/operands. Main CI is separate and synthetic.

New tools: sl3p_lens_interfaces1j.py (exploratory references), sl3p_lens_storage1j.py (exploratory tables), sl3p_lens_destination1j.py (partial RAM reconstruction and windows), sl3p_lens_verify1j.py (final bounded summary). New tests: test_lens_interfaces1j.py (21). Capstone is an optional analysis dependency; local Capstone/network were unavailable. Real disassembly ran on GitHub. Exploratory windows can include adjacent code/data; final verification uses exact comparison/reset boundaries.

## Next primary target

Pause the lens-peripheral detour unless a specific camera-UPD connection appears. Return to the actual camera loading/protection consumer: compatible readable updater/loader or an independent component with a provable content identity and format consumer. Existing SL3/SL2 matching expected hashes and known lens plaintext are validation targets, not keys. Do not rerun the failed guessed-key screens or presume more lens routines must unlock the main camera firmware.

Base still renderer first, source-calibrated/device-independent Photon integration next, optional user-supplied Leica Looks next, video last. No HDR, Cobalt, M-series stand-in or new upload required. Keep firmware, raw crypto metadata, Looks and private media out of the public repository and artifacts.
