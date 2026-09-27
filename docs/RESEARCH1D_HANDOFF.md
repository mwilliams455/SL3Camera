# SL3-P continuation handoff — RESEARCH1D

27 September 2026. Repository `mwilliams455/SL3Camera`; branch `research/loader-evidence1d`.

## Start here

Read `RESEARCH1D_REPORT.md` and the selected evidence. Main remains `8501e976ddb5b77bbf220579ffcba6fdb8083114`. Successful source-trace code was `a4341f44ea281ca79b4b8d0d122ccdd57f42ddff`; later documentation and helper-label correction must not be confused with that exact tested commit.

No protected SL3-P payload, base renderer or APK has been recovered. This milestone found real public platform code and nine cross-model expected-content matches. Do not describe it as decryption.

## Inputs and reproducibility

Target: SL3P_421 (1).lfu; SHA-256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8; 201752064 bytes; MC7251.

Official SL3 4.2.0 comparison: SHA-256 120a43f442036f62c0092d8976342e264082cfd45f0c3e8471c705efb40a6bc5; 195198464 bytes; MC7231. Do not flash it to SL3-P.

Q3 OSS package: SHA-256 ab6531df4770a0dd0e67d090f470321bc294078e020b2f21286f1dc8d0e7bb18; URL is fixed in `tools/sl3p_public_source_probe.py`. Nested member paths are fixed in `tools/sl3p_oss_audit.py`.

Local environment cannot retrieve remote files; bounded read-only GitHub-hosted jobs successfully did. They publish metadata/excerpts only. Downloaded bytes are temporary, not committed or uploaded as artifacts.

Useful runs:
- 36333369461: official inventories (SL3 job 108659460773; OSS 108659460864; Q3 108659460917).
- 36333640794: nested lexical audit (U-Boot 108660218995; Linux 108660219010; FreeRTOS 108660218920).
- 36333965675: failed initial targeted trace; retained for diagnostics.
- 36334141716: corrected targeted trace, both jobs successful, all 99 tests in each job (U-Boot 108661633802; Linux 108661633928).

## Findings to preserve

Nine named records, indices 50-58, have equal expected SHA-256 and sizes between SL3 4.2.0 and target SL3-P 4.2.1: eight `hm_d_nw_*` records and `hm_d_reid`, 14 MiB total. They remain opaque. Main loader/program/compress_pr expected hashes differ. The selected comparison is not a complete byte-by-byte cross-model diff.

Public source U-Boot path `u-boot/configs/pvc04v_MC501_defconfig`, line 43: decompress a kernel already at 0x400200000 to 0x403700000, then boot with device tree 0x401290000. This is the next loading-boundary lead, not LFU decryption. Actual source paths are under `arch/arm/mach-milbeaut` and `board/socionext/sc2006a-evb`; do not guess other layouts.

Linux source supports IPCU-mediated storage, shared RTOS buffers/movie-address fields and CPU handover to Linux. `sni_hotplug.c` SMC wrappers show RTOS communication, not established firmware crypto. These are published platform-source observations; no definitive mapping to SL3-P chip, build or section names exists.

## Next task

Follow who populates the compressed-kernel memory region and how IPCU/RTOS file-service requests reach their provider. Require actual source references before identifying an updater or decryption service. The published source may omit the proprietary producer; record that boundary honestly rather than treating absence of matches as proof of absence.

Do not repeat the old header-key searches. Do not attempt to execute opaque firmware. A candidate needs full length plus expected SHA-256 and meaningful structural checks.

The first real-source trace failures were fixed: wrong U-Boot paths, and non-UTF-8 Linux comments. The extra regression preserves hashes over original bytes. `not_direct_fill_matches` classifies stored data, never hidden plaintext.

## Constraints

No firmware, payloads, Looks, user photos/video, credentials or keys in this public repository. No changes to other camera projects. No Cobalt, added HDR, M-series placeholder rendering or device-specific assumptions in the Leica target. Preserve image quality. Base still rendering first, Looks second, video later; AF is separate. SL3-P 4.2.2 is not required and the user need not upload Looks now.
