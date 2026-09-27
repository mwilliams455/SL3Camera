# SL3-P research — RESEARCH1E

27 September 2026. Target remains the supplied SL3-P 4.2.1. Stage: firmware access and base still-renderer research. No protected SL3-P payload has been decoded; no renderer or APK was produced.

## Result

This pass overcame the previous firmware-download blocker using isolated GitHub Actions jobs. The official SL3 4.2.0 package is demonstrably in the same observed UPD container family as the supplied SL3-P package. Its parsed directory supplies a useful cross-model comparison, not a decryption method.

Of 46 protected SL3-P sections, 25 have matching size and expected-content SHA-256 in SL3 4.2.0. Two are the already known 128 KiB all-FF sections. The remaining 23 occupy 40,592,384 stored bytes (38.711914 MiB). Their stored payload hashes and metadata16 hashes differ across all matching protected pairs.

The expected hashes are strong evidence of intended content identity under the current directory interpretation. They do not reveal the content, prove that it is executable, authenticate a vendor signature, establish shared keys, or identify the loader algorithm. The 23 count excludes only the two proven FF regions: defaults or reserved data may be among the other matches.

## Inputs and actual execution

| Input | Bytes | SHA-256 | Result |
|---|---:|---|---|
| Supplied SL3-P 4.2.1 | 201,752,064 | b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 | Original re-inspected locally; baseline projection matches all 61 rows |
| Official SL3 4.2.0 | 195,198,464 | 120a43f442036f62c0092d8976342e264082cfd45f0c3e8471c705efb40a6bc5 | Downloaded and parsed on GitHub; repeated comparison pinned to this full hash |
| Official M11-P 2.6.4 | 63,659,410 | b654f3be4fd9f17d4f9949c62ebbd55fa8b58aac401bc06d60c607761018698f | Downloaded and decompressed on GitHub |
| M11-P 2.6.1 endpoint | Not obtained | Not measured | HTTP 502; do not claim it was inspected |

Sources were discovered or verified on Leica's official download pages. Public SL3 source: https://leica-camera.com/sites/default/files/SL3__420.lfu . Source page: https://leica-camera.com/en-int/photography/cameras/sl/sl3-black/downloads . M11-P source: https://leica-camera.com/sites/default/files/LEICA_M11-P_2.6.4.FW . These are research comparisons, not cross-model camera updates.

No firmware was executed. SL3 bytes were inspected in a temporary directory and deleted. M11 bytes were processed in memory. No firmware, raw metadata16 values, credentials, Looks or photographs were committed or uploaded as Actions artifacts. Only preselected marker counts/offsets and derived inventory/hash data were logged.

## SL3 comparison

Both files pass the unchanged strict outer-container parser and CRC checks. Both have 61 entries, four empty records, 11 verified fills and 46 opaque sections. Neither exposes a hash-verified nonconstant readable section. Identifiers differ: SL3 is MC7231; SL3-P is MC7251. Matching format is not proof of identical hardware or cryptographic implementation.

The 23 protected sections matching after excluding known FF fills are:

- eep_act_a/b, eep_exp_a/b, history;
- tc_fpga, lens, hm_c_ddr, hm_d_ddr, pzm_data;
- lpc_data, lpc_code, raw_kizu_c, raw_kizu_d;
- hm_d_nw_1st through hm_d_nw_8th, and hm_d_reid.

There are 31 matching protected *pairs* but only 25 distinct matched SL3-P *sections*, because duplicate expected-content regions match more than one counterpart. The tools keep these counts separate and retain duplicate names and shifted indexes.

### Recognition-resource lead

All eight numbered hm_d_nw regions and hm_d_reid have matching full expected-content hashes and sizes across the two packages. Their combined stored size is 14 MiB. This is substantially stronger than similarity of names alone. Recognition/tracking remains a name-based functional hypothesis; no model weights, preprocessing, inference code or autofocus-control loop has been decoded. Identical resources would not establish identical end-to-end AF behavior.

### Still-renderer boundary

The expected hashes differ for loader1, program, compress_pr, all six non-fill postboot records, eep_ow_a/b, eep_adj, eep_fix, osdover, osddata, muf_header, usbcharge, hr_c_prog, hr_d_prog, hr_c_ddr and welcom_fs. That is 21 protected sections.

These are comparisons between different models AND different version labels (SL3 4.2.0 versus SL3-P 4.2.1). We cannot attribute every difference to the P model, or localize a rendering change within a differing region. In particular, there is no evidence that an SL3 renderer can simply be relabelled SL3-P.

### LUT region

SL3 lut_data is 2,228,224 bytes (2.125 MiB); SL3-P is 8,781,824 bytes (8.375 MiB). Both are hash-verified zero fills. The difference is 6.25 MiB. This proves a different packaged region size, not LUT count, grid size, precision, supported Look types, or camera update/preservation behavior. Separately installed Looks remain a plausible explanation, not a demonstrated consumer function.

The directory also differs around Bluetooth/adjustment names: SL3 has bt2_info, while SL3-P has dsh_adj; bt_info is 128 KiB in SL3 and 256 KiB in SL3-P. Directory names alone do not establish what these regions do.

## M11 candidate-source investigation

The existing M11 marker/LZ convention successfully decoded M11-P 2.6.4 to 97,688,904 bytes. The packed-body MD5 matched; declared input and output bounds were enforced. Decoded SHA-256: 670802b2185afd5fc2d111e889b268a4a00d8092d03dc4dc7e476a0d5bed411f.

None of eight exact UPD-family markers was found in the decoded image: UPD-NUL, leica-NUL, loader1, postboot1_r, compress_pr, eep_ow_a, lut_data or MC7251. Generic firmware, bootloader and cryptographic words were found, but are not a validated SL3-P update consumer. This is a bounded marker scan, not exhaustive semantic disassembly. The decompression algorithm was already known in the M11 project; the new result is obtaining and inspecting this specific source successfully.

## Reproducibility and validation

New source tools: sl3p_loader_source_probe.py, sl3p_related_upd_probe.py, sl3p_pair_probe1e.py. New synthetic tests: 14 + 5 + 4 = 23. The previously unpushed RESEARCH1D pair of tools and 29 tests were imported without altering their content.

All 129 tests passed locally and in GitHub run 36335642926, job 108665853162, commit a6f2183fafccc0e08229575cbc877a1533a3ea79. Source-only guard passed for 41 tracked files in that run. Other successful research runs: 36335008904 (M11, job 108664072119) and 36335132163 (SL3 discovery, job 108664427813).

Selected machine-readable measurements are in evidence/RESEARCH1E_SUMMARY.json. That file is a reviewed transcription of selected job-output fields, not a complete log archive. The full execution logs are associated with the run identifiers above. The baseline fingerprints were regenerated from the unchanged original upload and exactly checked against the pinned canonical projection hash.

Run local synthetic tests with `python -m unittest discover -s tests -v` after installing requirements.txt. Real-source commands are separate and perform explicit network access. No broad unsuccessful key screen was rerun as a research milestone.

## Next investigation

Prioritize a readable UPD-family loader or a validated caller of the protection mechanism. We now have a measured SL3-family comparison anchor rather than an assumed family connection. A focused next source search can examine older related official packages or matching companion resources and test whether a nonconstant section is directly readable. The shared small lpc_code/data and tc_fpga expected hashes provide additional identity targets, but their names do not make them update decoders.

For any candidate, require full-format/bounds validation, source provenance, a complete expected hash, and actual call/data-flow evidence before treating it as the consumer. M11 generic crypto vocabulary is lower-priority than a demonstrated UPD parser. Do not guess more keys without a concrete implementation lead.

The photographic project order is unchanged: establish the SL3-P base still renderer; integrate it into Photon with proper source calibration; add optional Looks; then investigate video. No 4.2.2 or LUT upload is required for the present research.
