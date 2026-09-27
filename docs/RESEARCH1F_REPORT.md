# SL3-P research — RESEARCH1F

27 September 2026. Target remains the supplied SL3-P 4.2.1. Stage: firmware access and base still-renderer research. No SL3-P cipher/key or base renderer has been recovered; no APK was produced.

## Principal result: first nonconstant section contents recovered independently

The official standalone `SLLens11.plf` file, followed by zero padding to 20,971,520 bytes, matches the complete expected SHA-256 of SL3-P section 33, `lens`. The same expected section hash was measured in SL3 4.2.0 and now SL2 6.3.0.

This recovers intended nonconstant section contents through an independently distributed source. It is NOT decryption of the protected update bytes, a recovered key, or evidence that the camera's still-image pipeline has been opened. Content-hash verification also does not authenticate a vendor signature.

| Component | Bytes | SHA-256 |
|---|---:|---|
| Original SL3-P 4.2.1 | 201,752,064 | b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 |
| Official SLLens11.plf | 4,575,234 | 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600 |
| SLLens11.plf plus 16,396,286 zero bytes | 20,971,520 | 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1 |

The last value equals the complete expected-content hash in the original directory. It is not a prefix match or a similarity score. Most of the 20 MiB region is appended padding; do not describe it as 20 MiB of recovered executable code.

Source: https://leica-camera.com/sites/default/files/SLLens11.plf . Leica's downloads catalogue lists it as firmware for SL lenses. The initial five-source probe discovered the match. A separate verification job downloaded it again, required the exact standalone length and source SHA-256, reconstructed the full region in memory, and required the exact target length and SHA-256. Both jobs succeeded.

## What the readable header tells us

The standalone file begins with `LENS-UPDATE-FILE-SOF:`. A second marker, `LENS-UPDATE-FILE-EOH:`, starts at offset 791. The header is not the camera UPD directory. One case-insensitive `fwupdate` term occurs at offset 2,706,360; no exact UPD-NUL marker or decrypt term was found by the bounded scan.

A big-endian 16-bit value at offset 29 is 40. The arithmetic 31 + 40 * 19 = 791 provides a candidate fixed-header/table layout. This is only a layout hypothesis: record count, record meanings, model IDs, checksums, payload boundaries and instruction architecture have NOT been established. The existing header probe emits selected numeric header candidates and fixed-term counts, not firmware payload dumps.

A firmware-update word inside lens content is not proof of a camera UPD decryption routine. A successful lens-section reconstruction does not supply camera tone curves, colour matrices, exposure logic or image-detail processing.

## Older UPD-family packages actually inspected

| Source | Bytes | SHA-256 | Result |
|---|---:|---|---|
| SL2 6.3.0, SL2__630.lfu | 122,170,880 | 15938acd8110e6908fece073c56e20287591c2d3f720bdf025a106c74737b732 | Strict UPD parser and CRC passed; 48 entries, 41 opaque, one empty, six verified fills |
| Q2 Monochrom 5.1.0, q2m_510.lfu | 118,262,784 | 91964ac6a9edcd5428c3d113d90627f028ed7a1a24ce597c4baba69f12be86ac | Strict UPD parser and CRC passed; 46 entries, 37 opaque, one empty, eight verified fills |
| 70200_11.plf | 1,573,978 | 4e26dce0ec3a4e64454b46e9df9d4dcdfb319be6a3cb479fb95521fe0ed70d32 | LENS magic; not accepted as UPD; no tested whole-file/trailing-fill match to baseline |
| SL Typ 601 endpoint, 601__41_.lfu | 82,863 response bytes | ae6590033d4c6281e3caccd4983b2f28e4355353dca83eaa35664652a6a5891c | HTML-like response starting with <!DO; rejected, not inspected as firmware |

The SL2 internal identifier is MC792; Q2 Monochrom is DC1802M. Both older packages use the observed 92-byte UPD directory entry convention, but neither exposes directly hash-verified nonconstant bytes after outer normalization. A shared format does not establish a shared cipher, keys, processor or hardware.

SL2 has expected-size/hash matches for SL3-P `lens`, `hm_c_ddr` and `hm_d_ddr`, totalling 24 MiB. Other matches involve already-known all-FF padding and must not be promoted to meaningful code recovery. Q2 Monochrom yielded no matching protected baseline content under the tested full-length/full-hash comparison; its clear counterparts only reproduced known FF padding.

SL2 and Q2 Monochrom share the same expected hash for their 4,096-byte `loader1`: 4913f493636ed435d185ca3e5bea7a49eec28195606c99845d38ec68d91ccc5b. Both representations remain opaque. The SL3-P loader is a different-sized, different-hash target; no interchangeable loader is implied.

Older section names include `zboot`, `dtb`, `zimage` and `rootfs1/2`. These are clues for future source research, not parsed operating-system evidence. A lone `aes_` marker in opaque Q2 bytes is not evidence of an AES implementation.

Official source URLs:
- https://leica-camera.com/sites/default/files/SL2__630.lfu
- https://leica-camera.com/sites/default/files/q2m_510.lfu
- https://leica-camera.com/sites/default/files/70200_11.plf
- https://leica-camera.com/sites/default/files/601__41_.lfu

Catalogue provenance: https://leica-camera.com/en-GB/downloads?field_media_document_language=984&page=2 and https://leica-camera.com/de-DE/downloads?field_media_document_language=985 . Endpoints and actual measured responses must be distinguished; the SL601 listing did not produce a valid firmware download in this experiment.

## Methods and completed validation

New tools: `sl3p_lineage_probe1f.py` and `sl3p_lens_plaintext1f.py`. New tests: 19 lineage tests and eight plaintext-verification tests, making 156 total with the inherited 129.

The bounded standalone comparison tested the entire raw or byte-complemented file, unchanged or followed only by all-zero/all-FF trailing padding, against protected baseline section sizes up to 32 MiB. It did not scan arbitrary substrings, trim source files or accept partial hashes. The successful source was subsequently pinned independently.

All 156 tests passed locally and in the second GitHub job. They validate tools and reference mathematics, not camera operation or photographic fidelity. Synthetic tests cover corrupted source/target hashes, invalid lengths and magic, wrong padding, no truncation, no prefix-only acceptance, duplicate-pair counting, and exclusion of private string dumps.

Completed GitHub evidence:
- Lineage discovery: run 36336584568, job 108668480818, commit d54c831aa013721edd6b44a458bd6876cd98de02; 148 tests passed and source guard passed for 46 tracked files.
- Independent lens verification: run 36336749196, job 108668945682, commit 5bf6582f3322605c285a128ef56634c61504c116; 156 tests passed and source guard passed for 49 tracked files.

Reviewed summaries are selected transcriptions of these job outputs, not a complete log archive. The original SL3-P was rehashed unchanged; its 61-row canonical fingerprint projection was also rechecked against the preserved baseline. New firmware acquisitions ran on GitHub because local network resolution was unavailable. Unknown downloaded formats were rejected by the UPD parser rather than forced into it.

No firmware or extracted payload was executed or committed. Source acquisition used approved Leica HTTPS hosts. The reconstructed lens bytes remained in memory; other inspection files were temporary and deleted. No binary Actions artifacts, raw UPD cryptographic metadata, Looks, photographs, credentials or keys were published. Existing M-series projects were untouched.

## Next substantive investigation

1. Parse and validate the independently recovered LENS container: test the candidate table arithmetic, derive actual record boundaries and checks, and establish which payloads contain readable code. Treat a lens update consumer separately from a camera UPD consumer.
2. Use the exact nonconstant lens plaintext and the original protected section as a validation target for implementation-backed protection hypotheses. Known plaintext does not itself recover a cryptographic key. Do not restart the old blind key list merely because a new plaintext source exists.
3. Follow the measured small-loader identity across related public packages where it may be readable, while requiring full-format, bounds and content-hash validation plus actual call/data-flow evidence.

Stage order remains base SL3-P still rendering, Photon integration with proper source calibration, optional Looks, then video. Firmware 4.2.2 and additional user uploads are not prerequisites. L-Log reference maths and M-series transforms are not substitutes for the still-unknown SL3-P base rendering implementation.
