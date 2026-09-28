# SL3-P research — RESEARCH1J

28 September 2026. Target remains the supplied SL3-P 4.2.1. This pass resolves the previously unknown lens storage adapter and destination methods, including a statically reconstructed RAM-resident completion path ending in a Cortex-M software-reset request. It does not decrypt the camera UPD payload or recover an SL3-P photographic transform.

## Principal result

The observed `Memory` / `fwupdate` branch is a **verification-and-completion path**, not a packet-programming loop. The destination method called for each packet compares supplied bytes with addressed memory plus 0x80000 and returns 4 on mismatch or 0 on equality. A separate destination table slot reaches programming-like controller code. After successful verification, the traced completion call reaches vendor-register operations and then the standard Cortex-M reset-request sequence.

This distinction is now supported by constructor references, method-table words, instruction operands and static relocation. It prevents the misleading conclusion that any method accepting an address, buffer and length must write those bytes. It also gives a sensible stopping point for this lens-side detour: no camera-UPD protection consumer was found along this traced path.

## Provenance and scope

Real-source analysis used `https://leica-camera.com/sites/default/files/SLLens11.plf` in isolated, read-only GitHub Actions jobs. Source identity, the complete zero-padded intended lens section, LENS CRCs and LDAFR packet checks were required before interpreting code. Content hashes provide exact identities, not authentication of a vendor signature.

| Input | Bytes | SHA-256 |
|---|---:|---|
| Original SL3-P 4.2.1, rehashed locally without modification | 201,752,064 | b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 |
| Official standalone lens source | 4,575,234 | 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600 |
| Complete intended lens section, including zero padding | 20,971,520 | 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1 |
| Inner component shared by records 20–25 | 251,417 | 970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db |

Addresses refer to the packet-reconstructed lens image, not offsets in the camera LFU file. RAM addresses are statically derived from copy instructions; no firmware was executed, emulated, flashed or run on a device. Local networking and Capstone were unavailable, so downloads and real-source disassembly ran on GitHub. Local work covered source inspection, pure synthetic tests and archive validation.

## 1. The destination object separates comparison from programming

Initialization loads 0x2000ADA0 at 0xADA6 and calls constructor 0xDA04 at 0xADAA. That constructor installs table 0x904 at object offset zero.

| Table slot | Method | Observed behaviour |
|---:|---:|---|
| +0 | 0x738 | Calls a state-reading helper at 0x7BE. |
| +4 | 0x740 | Calls veneer 0x720, then checks the 512 KiB interval [0x80000, 0x100000) for FF bytes. |
| +8 | 0x762 | Forwards address, buffer and length to veneer 0x728 and RAM-resident programming-like code. |
| +12 | 0x770 | Compares packet data byte-for-byte with memory at packet address + 0x80000. |
| +16 | 0x796 | Calls veneer 0x730, leading to the RAM completion routine. |

The complete comparison method occupies [0x770, 0x796), with 18 instruction starts. It returns 4 at the first mismatch and 0 after all bytes match. It contains no calls or data-store instructions; its stack save/restore is not a packet-data write. The final verifier requires this boundary, bias, return status and lack of data stores/calls.

RESEARCH1I had established that backend 0x11D40 invokes destination slot +12 for each valid packet. Resolving that slot therefore identifies its role as verification. The programming-like method is **slot +8**, a different interface operation. This pass does not reconstruct every caller or the complete erase/program/verify lifecycle.

A secondary-bank interpretation is plausible from the 0x80000 bias and separate controller operations. The exact bank identity, activation mechanism and microcontroller model remain unverified; do not infer them from an address or command pattern alone.

## 2. The packet reader ultimately requests a three-byte-address read

The reader's underlying object at 0x2000AC9C is constructed by 0x10870, which installs table 0x3E4D8. Its slot +8 method, 0x108A0, forwards the read to slot +0x2C of its member at object offset +8.

That member is supplied through the observed initialization sequence from an object constructed by 0x1036C. Its installed table is 0x3BDBC; slot +0x2C resolves to 0x10454.

The complete bounded method [0x10454, 0x104C8) checks an address/length expression against a stored limit, obtains an underlying-interface status, and constructs four command bytes: **03, address bits 23–16, bits 15–8, bits 7–0**. It forwards that command, a destination buffer and a read length through another interface. The read length is narrowed to 16 bits at that call.

The exact command construction is established. Describing it as a serial-memory-style read is an interpretation; the physical bus, storage manufacturer and part number have not been identified. No assertion of a complete overflow-safe bounds check is made merely because a comparison exists.

This path provides storage bytes to the LDAFR parser already established in 1I. It does not identify a host filesystem, a camera UPD reader or a colour-processing stage.

## 3. RAM veneers can be followed without inventing missing bytes

The copy loop at [0x7A0, 0x7BE) loads source 0x50C, destination 0x20000554 and a count of 0x214 **words**, then uses word-indexed loads and stores. Its requested copy is therefore 2,128 bytes, not 532 bytes.

Only 1,044 bytes of that source interval are present in the reconstructed update component. The remaining 1,084 bytes are unavailable. The new relocation helper copies only intersections with known sparse regions and preserves holes as unreadable; it does not pad them with zeros or FF.

| Veneer | RAM target, Thumb bit removed | Corresponding source address |
|---:|---:|---:|
| 0x720 | 0x2000058C | 0x544 |
| 0x728 | 0x200005FA | 0x5B2 |
| 0x730 | 0x200006C6 | 0x67E |

All three targets, the inspected routines and their relevant literal pools fall within the available prefix. The missing tail therefore does not prevent these particular traces, but a complete RAM-image claim would be false. Missing update bytes are not proof of a defective firmware file: corresponding installed-memory contents are unknown.

The programming-like routine uses 16-byte-aligned destinations, advances in 16-byte groups and issues command/data writes in a 0x5E000000-based controller address space, with readiness polling through 0x5DFF0020 and related registers. The prepare and completion routines also operate on this controller family. These observations are not an identified cipher or established bank-swap specification.

## 4. The completion path reaches a software reset request

Destination slot +16 reaches 0x200006C6 through veneer 0x730. The completion routine disables interrupts, performs vendor-register operations and readiness polling, and calls 0x20000554 from 0x2000073C.

The reset helper at [0x20000554, 0x20000568) loads **0xE000ED0C**, retains bits masked by **0x700**, ORs in **0x05FA0004**, stores the result, performs a data-synchronization barrier and loops. This identifies a Cortex-M AIRCR software-reset request, not merely a function named reset. Arm's CMSIS documentation describes NVIC_SystemReset as requesting reset through SYSRESETREQ in AIRCR:

https://arm-software.github.io/CMSIS_6/latest/Core/group__NVIC__gr.html

The final verifier checks the literal values, instruction sequence, store and wait loop, as well as the completion-to-reset branch. **No reset was actually performed.** The meanings of the vendor-specific operations preceding it remain unestablished. In particular, this pass does not claim an exact bank swap, complete boot protocol or reset of the SL3-P camera's main processor.

## 5. Validation

The cumulative pure suite contains **261 tests: 240 inherited plus 21 new**. All passed locally and in the final real-source GitHub job. New fixtures cover table pointers and slots, sparse copy coverage and holes, range boundaries, invalid requests and bounded literal searches. No real firmware or Capstone is needed for those tests.

The final source job additionally cross-checks one synthetic relocated literal and two Thumb BL target operands against Capstone, and checks that the synthetic missing tail remains unavailable. These are additional checks, not 2,048 new tests or firmware execution. The final real-source verifier requires selected constructor links, method pointers, comparison behaviour, read-command operands, copy coverage and reset instructions before emitting its summary.

| Purpose | Run | Job | Source commit |
|---|---:|---:|---|
| Interface-reference scan | 36382893657 | 108802137169 | 85e79b606ce6e9da51e4332a3b1eef26301f1650 |
| Constructor tables | 36382982406 | 108802425792 | c72f3c2dd7d31cf827bb4376f06893dea8495808 |
| Destination and read adapter | 36383087736 | 108802735591 | 12711b792517ae1982893ac234cd70c975b22be0 |
| Partial relocation and RAM routines | 36383270944 | 108803249988 | 68c948c7dbb39773031922975623e7f2fc0f840c |
| Final 261-test run and selected static verifier | 36383716961 | 108804596111 | 3874e9e23acdd0d7851269b27978526bb780cb39 |

The final source-only guard passed across 89 tracked files. Selected committed evidence is a reviewed transcription of the completed outputs, not a full log archive. Exploratory tools retain bounded linear windows that can include following instructions or data; the final verifier uses exact comparison/reset boundaries. Partial static traces are not proof of external command exposure, runtime path feasibility or the complete behaviour of every possible object.

## Research decision

The lens-side detour has answered its immediate questions: packet consumption, storage-read forwarding, byte verification, distinct programming-like operations and completion-to-reset. It has **not** demonstrated any relationship to the camera's UPD protection beyond packaging inside the intended lens section.

The next primary investigation should return to a **camera-side loading/protection implementation**: a readable compatible updater/loader, or an independently distributed component whose complete identity and actual format consumer can be demonstrated. Use the existing cross-model content fingerprints and known plaintext as validation targets. Do not repeat blind key screens or continue following lens peripheral methods without a concrete bridge to the camera UPD format.

The SL3-P main program, protection key and base still renderer remain unresolved. No tone curve, colour matrix, autofocus model, Look or video transform was recovered here. No M-series code or APK was modified. Development order remains base still rendering, source-calibrated Photon integration, optional Looks, then video. No 4.2.2 or new user upload is required.
