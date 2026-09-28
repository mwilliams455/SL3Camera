# SL3-P RESEARCH1D — public loader-source evidence

Date: 27 September 2026  
Repository: `mwilliams455/SL3Camera`  
Research branch: `research/loader-evidence1d`  
Preserved main baseline: `8501e976ddb5b77bbf220579ffcba6fdb8083114`  
Successful real-source trace: `a4341f44ea281ca79b4b8d0d122ccdd57f42ddff`

## Result

This pass obtained actual public platform source and a useful cross-model resource relationship, rather than repeating the failed header-key screens. No protected SL3-P executable or photographic transform has been decoded. There is no renderer or APK.

The original SL3-P 4.2.1 file remains the target. SL3 and Q3 files are comparison inputs only, not replacement firmware or substitute photographic rendering.

## 1. Provenance and access

Leica's Q3 downloads page links an open-source package. A bounded GitHub-hosted read-only probe retrieved it after local outbound downloads failed. The package is pinned by SHA-256 before nested source inspection:

- Archive: `pm-19562-OSS_codes.zip`
- Bytes: `277144657`
- SHA-256: `ab6531df4770a0dd0e67d090f470321bc294078e020b2f21286f1dc8d0e7bb18`
- Selected members: `20260601_OSS/u-boot.tar.gz`, `20260601_OSS/linux-4.19.124.tar.gz`, `20260601_OSS/FreeRTOS-202212.00.tar.bz2`

No downloaded source or firmware is executed. Archives are read as streams, with size/member-count limits and no extraction to member-supplied paths. Downloads are temporary; workflows publish bounded metadata and public-source excerpts, not binary assets.

The firmware inventory also retrieved official SL3 4.2.0 and Q3 4.1.1. Both were accepted by the strict container inspector, but neither yielded a directly hash-verified nonconstant section. They did not provide an exposed loader.

Sources: [Q3 downloads](https://leica-camera.com/en-SE/photography/cameras/q/q3-black/downloads), [SL3 downloads](https://leica-camera.com/en-int/photography/cameras/sl/sl3-black/downloads), [inventory run](https://github.com/mwilliams455/SL3Camera/actions/runs/36333369461).

## 2. SL3 comparison: nine shared expected-content fingerprints

Official `SL3__420.lfu` is 195198464 bytes, SHA-256 `120a43f442036f62c0092d8976342e264082cfd45f0c3e8471c705efb40a6bc5`, identifier `MC7231`. The target file is 201752064 bytes, SHA-256 `b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8`, identifier `MC7251`.

The SL3 package has the same observed 61-entry container layout and the same 46 opaque / 15 directly verified division. Its `loader1`, `program` and `compress_pr` expected hashes differ from the SL3-P baseline.

However, the eight `hm_d_nw_1st` through `hm_d_nw_8th` records (1441792 bytes each), and `hm_d_reid` (3145728 bytes), match the target's expected SHA-256 values and lengths. This is 14680064 bytes, exactly 14 MiB, across nine records. The selected comparison was checked against a freshly generated local SL3-P inventory, preserving section indexes.

This strongly supports shared expected content in these recognition-related candidates. It does not recover weights, identify an inference framework, establish eight subject classes, or prove identical autofocus behavior. The names remain functional clues. The comparison does not establish identical protected bytes or a common decryption key. It also does not justify using SL3 base colour processing as SL3-P processing.

Evidence: inventory job `108659460773`; selected hashes and target comparison in the accompanying evidence record. Leica explicitly labels this other firmware as compatible with SL3, not SL3-P; no cross-flashing is part of this work.

## 3. What the public source actually establishes

### U-Boot: an explicit RAM-to-kernel boot stage

`u-boot/configs/pvc04v_MC501_defconfig` has SHA-256 `19dd82ae2f92bc8b9cafd5d2a60202006688287cdd8a0a801cc442fe338b8771`. Lines 5-12 select Milbeaut/SC2006A support and an MC501 device tree. Line 43 specifies:

```text
unzip 0x400200000 0x403700000; booti 0x403700000 - 0x401290000
```

Thus this configuration describes decompressing an already memory-resident kernel and booting it with a separate device tree. It is not itself an LFU update-container parser or decryption operation. Determining how the compressed kernel reaches that address is a more focused next question than adding arbitrary key guesses.

`arch/arm/mach-milbeaut/Kconfig` selects ARM64. The MC501 device-tree files contain four Cortex-A53 CPU nodes and SC2006-family compatibility strings. The included DTSI and top-level DTS differ in their SC2006A/SC2006B naming. These are facts about the published source tree, NOT identification of the physical SL3-P processor or its selected build.

### Linux: explicit coordination with an RTOS

The inspected DC1231 configuration enables IPCU-related support. `drivers/block/ipcu.c` describes block-device emulation over IPCU; its request definitions distinguish Linux reading from and writing to an RTOS. `pvc04v-DC1231-rtos.h` defines shared IPCU buffer/synchronization and movie-address offsets.

`drivers/snihotplug/sni_hotplug.c` explicitly supports switching CPU execution from an RTOS to Linux on Milbeaut evaluation boards. It includes RTOS notifications and `psci_ops.sni_r` / `sni_w` wrappers with comments describing communication through SMC.

This establishes a Linux/RTOS cooperation design in the released platform source. It does not prove that the SL3-P uses these exact configurations, that any particular `postboot*` record is Linux, that the SMC operations decrypt firmware, or that the photo renderer is in one specific operating-system domain.

A DSP driver file was located and hashed, but the targeted lexical excerpt filter returned no matching lines. Its filename alone is not evidence that a photographic algorithm has been recovered.

Source-file hashes and line references are preserved with the evidence. Full current trace: [run 36334141716](https://github.com/mwilliams455/SL3Camera/actions/runs/36334141716), jobs `108661633802` and `108661633928`.

## 4. Negative findings and limits

The public-source search is bounded lexical reconnaissance, not an exhaustive semantic audit. Some large/binary files are skipped; reported context is capped. In the selected Linux trace, the DC1231 DTSI and IPCU driver excerpts were truncated at the configured context limit.

Apparent `loader1` matches in U-Boot were unrelated upstream examples, and `compress_pr` matched a generic FPGA test name. No camera-specific LFU loader/decryptor was identified. The FreeRTOS member did not provide useful matches for the selected camera/platform markers. Generic crypto configuration does not establish the update cipher.

Still unknown: the protection algorithm and key derivation, the meaning of the 16-byte section field, executable section roles, SL3-P base tone/colour processing, photographic exposure placement, actual AF-model format and runtime, and the correct insertion stage for downloaded Looks.

## 5. Validation and corrected failures

The suite increased from 77 to 99 synthetic tests. All 99 passed locally and in each successful corrected real-source trace job. The 37-file source-only guard passed at the tested trace commit.

The initial targeted source run `36333965675` failed despite passing its synthetic tests: the U-Boot path selection did not match the actual archive layout, and a Linux source comment contained non-UTF-8 bytes. Paths were corrected from the observed inventory. Text inspection now escapes undecodable bytes while hashing the original bytes, with a new regression test. The corrected real run `36334141716` completed successfully in both jobs. These failures and corrections are retained rather than hidden by the later pass.

The optional cross-package helper's subset is named `not_direct_fill_matches`: it describes stored bytes only. Opaque content could decode to a fill, so the helper must not label unknown plaintext nonconstant.

Test success validates inspection tools, boundaries and reference mathematics; it does not validate camera rendering or physical device behavior.

## 6. Next evidence-driven step

Trace the producer of the compressed-kernel memory region and the IPCU/RTOS file-service boundary in the public platform sources. Look for an actual call chain into update parsing, image loading or secure-service dispatch. In parallel, preserve the nine cross-model expected-hash fingerprints as constraints for any candidate decoder.

Before interpreting any decoded output, require the complete section length and expected hash, then validate structure. Do not repeat the old bounded key screens as a new milestone. Do not infer an LFU cipher from generic AES/SMC support.

The application sequence remains: base still-image renderer, Photon integration, optional Looks, then video. No existing renderer or APK was modified. `main` remains the initial research baseline; changes are isolated on the research branch.
