# Research status — RESEARCH1J

Updated 28 September 2026. Detailed methods, evidence and boundaries are in RESEARCH1J_REPORT.md. Earlier milestone reports are historical records.

## Verified

The supplied SL3-P 4.2.1 container parses and passes its stored checksum and range checks. Its 61 entries include 46 opaque protected regions; the others are empty or constant-filled. lut_data is hash-verified zero fill. Its storage/update semantics remain unknown.

Standalone SLLens11.plf plus zero padding exactly reproduces the intended protected lens-section contents. This independent recovery is not decryption. Its outer LENS record layout, CRCs and four inner LDAFR packet streams have been validated. One sparse component supports coherent Cortex-M/Thumb code analysis.

A Memory command object selects fwupdate using a string comparator and calls a constructor-linked LDAFR backend. The packet reader's executable code confirms count/checksum/address/STOP handling.

RESEARCH1J resolves the backend's packet destination to byte verification against memory plus 0x80000, distinct from its programming-like slot. Its storage adapter forms a 03 command with a three-byte address. Statically relocated completion code reaches an AIRCR software-reset request. Only 1,044 of 2,128 requested copy bytes are available; missing bytes are never invented.

## Not established

Camera UPD cipher, keys, key derivation and a working protected-section decoder remain unidentified. The decoded lens routines do not demonstrate a camera UPD consumer. The exact lens microcontroller, storage chip and bank activation semantics are not established. No hardware or firmware was run.

No SL3-P base still curve, colour matrix, exposure policy, autofocus model or photographic/video renderer has been recovered. FOTOS Looks remain separate, optional future inputs; an empty LUT section does not establish how they are stored or applied.

## Validation

261 pure unit tests pass locally and on GitHub. The final real-source job additionally validates selected constructor/method/instruction relationships, a relocated synthetic literal, two branch targets and a preserved missing tail. These validate tools and bounded static observations, not image quality or camera behaviour. See the report for exact job identities.

## Next gate

Prioritise a readable camera-side loading/protection consumer with a demonstrated relationship to this UPD container. Existing cross-model expected-content fingerprints and known lens plaintext are tests for a future decoding hypothesis, not a recovered key. Do not repeat the failed blind key screens or extend lens peripheral analysis without a concrete camera-UPD connection.

Base still renderer -> source-calibrated Photon integration -> optional Looks -> video. No added HDR, Cobalt, M-series replacement or 4.2.2 dependency. Firmware binaries, extracted payloads, raw crypto metadata and private media remain outside the public repository.
