# SL3-P research — RESEARCH1H

27 September 2026. Target remains the supplied SL3-P 4.2.1. This pass establishes inner packet framing and a coherent Cortex-M/Thumb interpretation of one independently recovered lens component. It does not decrypt the camera UPD payload, identify its key, recover the base still renderer, or produce an APK.

## Principal result

Four of the 20 CRC-verified distinct LENS payloads are LDAFR packet streams rather than flat executable images. Their 62,993 length-delimited packets all pass the measured one-byte checksum. Two packets contain no data; 62,991 carry data. Strict parsing accounts for the prologue, every packet and an observed STOP trailer. Address ranges are reconstructed sparsely, without filling gaps or allocating a four-gigabyte buffer.

The shared 251,417-byte payload referenced by records 20–25 reconstructs to 240,369 addressed data bytes in three regions. It contains a consistent Cortex-M exception-vector table, a valid Thumb startup sequence and a literal reference to the `fwupdate` string. The exact microcontroller and the function consuming that string remain unestablished. This identifies executable lens-component material, not the camera processor or a camera-update decryptor.

## Source identity and execution

All new real-source experiments used the official source below and required the complete independent-source and reconstructed-section hashes before interpreting inner content. The inherited LENS parser also reverified every declared payload CRC-32.

- Source: https://leica-camera.com/sites/default/files/SLLens11.plf
- Source bytes: 4,575,234; SHA-256 `9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600`.
- Source plus 16,396,286 zero bytes: 20,971,520 bytes; SHA-256 `555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1`, matching the original SL3-P lens section.
- Target inner payload: SHA-256 `970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db`, at standalone offset 2,458,563, length 251,417.
- Original SL3-P file rehashed locally without modification: 201,752,064 bytes; SHA-256 `b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8`.

New downloads and Capstone analysis ran in isolated GitHub Actions because local network resolution was unavailable. Firmware remained in memory in those jobs; no camera or downloaded firmware was executed. Only selected measurements and a short disassembly excerpt were logged. No firmware binaries, reconstructed memory image, Looks, private photographs or raw camera cryptographic metadata were published.

Final real-source run: **36339912507**, job **108677847487**, source commit **635d5b7998958aa4742ce7648c9b88cd935e3830**. The job completed the 222-test suite, five additional synthetic disassembly checks, all four packet reconstructions and the sparse-code analysis. Selected measurements in `evidence/research1h/summary.json` are a reviewed transcription, not a full log archive.

## Correction: packet coordinates are not image addresses

The first exploratory vector screen detected plausible vectors at file offset 20. A flat-image assumption provisionally placed `fwupdate` at 0x447E1 and gave a poor code walk. That address is **superseded**, not a second valid address.

Repeated LDAFR headers revealed transport records interleaved with the data. A separate length/checksum analysis then established the packet interpretation. After reconstructing the packet-specified address ranges, the string is at **0x41458**. The earlier flat result is retained as a rejected hypothesis; `sl3p_lens_code1h.py` must not be used as the final decoder for this framed payload. Use `sl3p_ldaf1h.py` and `sl3p_sparse_code1h.py`.

The reset vector happens to retain the same stored pointer value across these interpretations; this did not make the flat file-to-address mapping correct.

## Observed LDAFR framing

Each stream begins with a special ten-byte prologue: `LDAFR`, a varying byte, and four 0xFF bytes. The varying byte is not interpreted as a packet length or a hardware identifier. Normal packets start after that prologue.

| Normal-packet offset | Width | Observed role |
|---|---:|---|
| 0 | 5 | Fixed `LDAFR` marker |
| 5 | 1 | Count N, at least 5 |
| 6 | 4 | Big-endian address |
| 10 | N − 5 | Data bytes |
| 5 + N | 1 | One-byte checksum |

Total normal packet length is `6 + N`. The sum of the count, address bytes, data and checksum modulo 256 equals 255. Parsing follows lengths, not a search for the next marker. Synthetic tests demonstrate that marker-like bytes inside data are not incorrectly split.

The byte-count/address/checksum relationship resembles Motorola S3 records, whose documented checksum is the low byte of the ones-complement sum. This resemblance is not used to assume all S-record semantics: these are binary LDAFR streams with a separate prologue and trailer, not validated textual S-record files. Reference: Texas Instruments compiler documentation, https://software-dl.ti.com/codegen/docs/tiarmclang/rel4_0_2_LTS/compiler_manual/hex_utility_description/description-of-the-object-formats-stdz0792390.html .

| LENS record references | Wrapped bytes | Checked packets | Addressed data bytes | Coalesced regions | Trailer |
|---|---:|---:|---:|---:|---|
| 20–25 | 251,417 | 1,003 | 240,369 | 3 | STOP followed by 0x00 |
| 28–29 | 125,206 | 4,642 | 74,129 | 14 | STOP followed by 0x01 |
| 38 | 774,196 | 28,674 | 458,768 | 2 | STOP |
| 39 | 774,196 | 28,674 | 458,768 | 2 | STOP |

The latter two include a final zero-data packet at address 0x100000; it is retained separately and not counted as image bytes. Its execution/termination meaning is not established. The meanings of the optional STOP suffix and prologue byte also remain unknown. `verify_packets` recognizes only the complete observed trailer forms and requires actual data. It rejects unknown trailers, corrupt packet checksums, truncation, overlaps, and address overflow. These checks are not cryptographic authentication.

## Target sparse address map

| Start | End, exclusive | Bytes | SHA-256 |
|---|---|---:|---|
| 0x00000000 | 0x00000920 | 2,336 | ed6a1bcf2d3eaa01f7af76eef6c74a0b6a95b3cfdb6cba913bc7b8a9154e26b4 |
| 0x00008000 | 0x000421C9 | 238,025 | 67f94d8b46544972d1c4439bc2b0284f183742208207cd01828f98ada79add96 |
| 0x0007FFF0 | 0x0007FFF8 | 8 | 4fcb18d9ded612b8c2da8ab27a180d687b6fed0bc5de0d9100e89db948fe0af8 |

The map includes code, vectors, literals and other data. It must not be described as 240,369 bytes of instructions. Unknown gaps remain unreadable, not silently filled with zeros or 0xFF. Packet-specified addresses and static consistency support this interpretation; no physical flash dump or camera execution validates an exact chip memory map.

## Cortex-M/Thumb evidence and startup

At reconstructed address zero the vector table has initial stack value **0x2000D298**, an odd reset pointer **0x40309**, ten mapped nonzero exception entries and zero values in the checked reserved slots. The exception-table arrangement is consistent with Arm CMSIS documentation: https://arm-software.github.io/CMSIS_5/Core/html/group__NVIC__gr.html .

The reset handler at **0x40308** resolves into three literal-loaded transfers:

- 0x4030A calls 0x00000418 via R0, loaded immediately beforehand.
- 0x4030E calls 0x000007C4 via R0, loaded immediately beforehand.
- 0x40312 branches to 0x000415E6 via R0, loaded immediately beforehand.

The last transfer ends the reset sequence. The tool no longer disassembles its following literal pool as though it were fall-through instructions.

A bounded traversal seeded from the exception table visits **11,893 instruction starts** and records **2,419 direct control-flow edges**, all mapping to supplied bytes. It also resolves the three adjacent literal-loaded transfers above. Stops include 220 unresolved indirect-control transfers, 274 return/PC-write stops and six trap stops. These are descriptive traversal metrics, not complete coverage, a proven call graph, or evidence that all paths execute. Indirect calls, jump tables and full path feasibility remain unresolved.

Capstone was installed as distribution **5.0.9**, while its module reported **5.0.7** and core API tuple `[5, 0, 1280]`; all three are recorded rather than concealing the difference. The parser's literal-address calculations were cross-checked against Capstone operands in three synthetic cases. Two complete synthetic sparse traversals verified resolving a mapped literal-loaded branch and refusing an unmapped target.

## The actual fwupdate reference

The reconstructed string has a literal pointer at **0x1E788**. The following measured sequence loads that pointer and invokes a function:

```text
0x1E646  LDR R0, [PC, #0x140]  ; pool 0x1E788 contains 0x41458
0x1E648  BL  0x25BC0
0x1E64C  CMP R0, #0
0x1E64E  BNE 0x1E680
```

The address calculation is independently checked by the pure Thumb literal helper. The target function's role is still unknown. This could be a name lookup or another use of the string; it is not established as flashing, decryption, a file-open operation or an UPD parser. This reference was **not reached by the current partial exception-seeded traversal**. It is a consistent static reference found separately, not proof that this path is active.

Next, establish the enclosing function, its callers, and what **0x25BC0** does with R0. Inspect the string-consuming path for actual framing, checksum or cryptographic operations before describing it as an update handler. The lens firmware may have no role in the camera's UPD protection.

## Validation and boundaries

The cumulative suite is **222 tests**: 175 inherited plus 12 inner-format tests, eight flat-coordinate/literal helper tests, 17 packet tests and ten sparse-image tests. All pass locally and in the final source job. The five additional Capstone checks ran on GitHub, not locally. Local Capstone installation was unavailable; no local real-firmware disassembly is claimed.

All eight new Python source/test files were compared with their GitHub blob hashes and matched. Publication and fresh-archive validation are recorded separately in the delivered evidence. The ordinary main-branch CI remains synthetic and does not download firmware; explicit research workflows are read-only and separately scoped.

The base SL3-P still-image pipeline, protected main program and protection key remain unresolved. No M-series repository, JPEG renderer, exposure policy or APK was modified. The development sequence remains base still rendering, device-independent Photon integration, optional Looks, then video. Neither 4.2.2 nor another user upload is required for the next code investigation.
