# SL3-P handoff — RESEARCH1F

Date: 27 September 2026. Supersedes RESEARCH1E for current research state.
Repository: mwilliams455/SL3Camera. Work branch: research/upd-lineage1f.

## First read

Read RESEARCH1F_REPORT.md and ../evidence/RESEARCH1F_SUMMARY.json. Main started at 7266ac767cfc0db5192d499eda64153a4ca4d275; re-read live refs rather than assume the final promotion state.

## What changed

We have the first exact nonconstant intended content for a protected SL3-P region, recovered from an independently distributed official source, NOT by decryption.

SLLens11.plf: https://leica-camera.com/sites/default/files/SLLens11.plf
Length 4575234. SHA256 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600.
Append 16396286 zero bytes to length 20971520. Complete SHA256 becomes 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1, exactly matching SL3-P section33 lens. Matching region also measured in SL3 and SL2. Most of this region is padding, not code.

Original SL3-P421 unchanged: 201752064 bytes, SHA256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8. The 61-row baseline remains evidence/SL3P_421_COMPARISON_BASELINE.json.

## New actual evidence

The standalone header starts LENS-UPDATE-FILE-SOF:. LENS-UPDATE-FILE-EOH: appears at791. u16BE at29 is40; 31+40*19=791 is a candidate table layout, NOT a validated record specification. fwupdate appears at2706360; no exact UPD-NUL or decrypt string. Do not claim this is a camera decryption routine, a recognized instruction set, or an image-rendering table.

SL2_630 (122170880 bytes, SHA15938acd8110e6908fece073c56e20287591c2d3f720bdf025a106c74737b732) validates UPD/CRC;48sections:41opaque,6fills,1empty. Shared expected-content baseline regions beyond knownFF are lens,hm_c_ddr,hm_d_ddr.
Q2M510 (118262784 bytes, SHA91964ac6a9edcd5428c3d113d90627f028ed7a1a24ce597c4baba69f12be86ac) validates UPD/CRC;46sections:37opaque,8fills,1empty. No protected baseline match. Their 4096-byte loader1 expected hash is identical (4913f493636ed435d185ca3e5bea7a49eec28195606c99845d38ec68d91ccc5b), but both are opaque and not interchangeable with SL3-P.

601__41_.lfu endpoint returned HTML-like content, not firmware. 70200_11.plf is another LENS file but did not match the tested baseline whole-file/padding hypotheses. Do not claim the SL601 firmware was inspected or that all PLF contents match lens section33.

## Verification

New files: tools/sl3p_lineage_probe1f.py, tools/sl3p_lens_plaintext1f.py, two corresponding test files and separate read-only source workflows. 156 tests total:129 inherited+19+8. All156 passed locally and in run36336749196/job108668945682 at5bf6582f3322605c285a128ef56634c61504c116. Initial discovery run36336584568/job108668480818 passed148 tests. Both real-source jobs completed successfully; the second pinned source hash, length and full target hash. Reports are selected job-output transcriptions, not complete logs.

Source binaries remained temporary/in-memory; no firmware execution, raw crypto metadata, binary artifacts, private photos or Looks published. The repository is public. Local DNS prevented acquisitions, so actual downloads/inspection ran in isolated GitHub jobs. Existing M-series projects unchanged.

## Next work

Parse and validate LENS record boundaries/checks from the verified public source. A candidate table arithmetic is not enough: establish payload ranges, validate checksums where present and only then analyze executable candidates with architecture/load mapping evidence. Treat lens updating separately from camera UPD loading.

The independent nonconstant plaintext provides a stronger test target for implementation-backed protection hypotheses. It does NOT make generic AES key recovery feasible by itself. Do not simply repeat previous85,995key/PRNG/block searches. Continue seeking actual UPD protection consumer code, including the now-measured small-loader lineage.

No SL3-P still renderer, base tone/colour transform, complete autofocus implementation or APK exists yet. Preserve order: base still renderer -> Photon -> optional Looks -> video. Device-independent target with source-camera calibration; no Cobalt, added HDR or M-series substitute. No4.2.2/LUT upload prerequisite.
