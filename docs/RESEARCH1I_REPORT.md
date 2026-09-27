# SL3-P research — RESEARCH1I

27 September 2026. Target: supplied SL3-P 4.2.1. The camera UPD protection, its key and the base still-image renderer remain unresolved. No APK or photographic transform was produced.

## Principal result

The `fwupdate` reference found in 1H has now been traced through a `Memory` command object, its constructor-supplied backend, and two concrete reader methods. The reader explicitly recognizes **LDAFR**, checks the same packet checksum reconstructed in 1H, decodes the normal-record address as big-endian, and recognizes **STOP**. This is executable-code evidence for a lens-packet consumer, not merely a plausible string or file-layout inference.

It is **not** evidence of the camera's UPD decryptor. The camera's protected program has not been opened. Lens code, camera image processing and downloadable Looks remain separate targets.

## Provenance

All real-source code analysis ran in isolated GitHub Actions on the official standalone source. The source was checked before reconstruction; the complete padded region was checked against the SL3-P lens-section hash; the inherited LENS and LDAFR parsers rechecked payload CRCs, packet checksums and sparse bounds.

| Input | Bytes | SHA-256 |
|---|---:|---|
| Original SL3-P 4.2.1, locally rehashed unchanged | 201,752,064 | b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8 |
| Official SLLens11.plf | 4,575,234 | 9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600 |
| Standalone source plus zero padding | 20,971,520 | 555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1 |
| Inner component shared by LENS records 20–25 | 251,417 | 970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db |

Official source: https://leica-camera.com/sites/default/files/SLLens11.plf . No binary was executed, flashed, emulated or published. Local network resolution and local Capstone were unavailable, so local validation covered the pure test suite; real downloads and disassembly were performed on GitHub. Checksums do not authenticate a vendor signature.

All addresses below refer to the sparse packet-reconstructed lens image from 1H, not to offsets in the LFU file. The abandoned flat mapping is not reused.

## 1. The immediate callee is a string comparator

Function **0x25BC0** compares two NUL-terminated byte strings, folding ASCII A–Z to a–z. It returns zero when equal and a signed -1 or +1 on a mismatch. The complete bounded control-flow trace contains 36 instruction starts and three return sites. Its only direct call is to **0x2E830**, which applies the same ASCII uppercase-to-lowercase conversion.

The original reference at **0x1E646** loads the `fwupdate` pointer into R0, and **0x1E648** calls this comparator. Its role is command selection, not decryption, file opening or flashing. The register-argument interpretation is consistent with the Arm procedure-call standard; this does not establish original C++ names or signatures. Reference: https://github.com/ARM-software/abi-aa/blob/main/aapcs32/aapcs32.rst .

A broad halfword scan yielded 131 candidate calls to the comparator. They are not presented as 131 proven callers: scanning every halfword can include data or the second half of an instruction.

## 2. The enclosing object identifies itself as Memory

The enclosing method starts at **0x1DB18** and returns through **0x1E68A**. A bounded, entry-relative traversal visits 1,150 instruction starts, including the `fwupdate` callsite. It also finds comparisons with `read` and `write`.

The method calls **0x25B74**, whose code is consistent with a stateful, delimiter-based tokenizer. Its observed delimiter is a space. A subsequent call uses the format string **%X**, a pointer to the first token and a local output word, then checks for a return value of one. This supports hexadecimal numeric-argument parsing, although the entire formatting-library implementation has not been reconstructed.

Function **0x1E68E** returns the string **Memory** at **0x41A30**. A table at **0x40130** contains the odd Thumb pointers **0x1DB19** and **0x1E68F**, linking the dispatcher and name method.

Constructor **0x1DAF8** installs this table at object offset zero and stores its fourth argument at object offset **+0x0C**. The update branch subsequently uses that member as a backend object. This is substantially stronger boundary evidence than finding a push instruction near a string.

Entry-relative reachability is not reset-to-command reachability or a runtime trace. This investigation has not identified how an external user or camera process reaches the command object. It provides no instructions for invoking it on hardware.

## 3. Resolving the two indirect update calls

The matching command branch subtracts **0xC00** from the parsed local word and passes the adjusted value to backend table slot **+8**. If the low byte of the returned value is zero, it then invokes backend table slot **+12**. The reason for the numeric adjustment remains unestablished.

The constructor call chain near **0xB890–0xB8B8** supplies the backend rather than leaving its class entirely unknown:

| Component | Constructor | Installed table | Relevant methods |
|---|---|---|---|
| Memory command object | 0x1DAF8 | 0x40130 | dispatcher 0x1DB18; name method 0x1E68E |
| Backend passed to Memory | 0x11B78 | 0x3ECB4 | slot +8: 0x11D40; slot +12: 0x11E38 |
| Reader passed to that backend | 0x11A18 | 0x40028 | slot 0: 0x11A34; slot +4: 0x11AB8 |

The measured initialization sequence places the backend at **0x2000ACFC** and the Memory object at **0x2000AC28**. These are static address operands, not independently measured physical memory. The targets above are resolved for this observed constructor chain, not every hypothetical runtime object.

Backend method **0x11D40** obtains a 0x114-byte workspace, initializes it, reads a ten-byte opening record, then processes subsequent records. Successful records supply an address, data pointer and length to another interface. The next-record position advances by **data length + 11**, consistent with the previously reconstructed normal packet size. Status values are checked and propagated; their public enumeration names are not known.

Backend method **0x11E38** delegates to slot **+0x10** of the destination object stored at backend offset +8, then returns one. Calling this an actual reset or flash-commit routine would be premature: the destination implementation remains unresolved.

## 4. Actual reader code confirms the packet interpretation

### Opening-record reader: 0x11A34

This method requests ten bytes from an underlying interface. It compares the first five bytes individually with the immediate character values **L D A F R**. It copies byte 5 to one output and assembles bytes 6–9 as a **little-endian** word for another output.

The opening record therefore differs from normal packets. In the known streams, bytes 6–9 are all FF, so either byte order would have produced the same measured value. The code now resolves that ambiguity for this reader. It does not establish the meaning of the varying opening byte or require that every possible input use all-FF bytes.

### Normal-record reader: 0x11AB8

The method requests a 0x109-byte read into its working buffer, then performs the following operations:

- It compares the first five bytes individually with **LDAFR**.
- With count N at byte 5, it sums N bytes starting at byte 5, complements the low byte and compares it with the checksum at byte **5 + N**.
- After a valid checksum it stores **N − 5** as the data length, assembles bytes 6–9 into a **big-endian** address, and points to data beginning at byte 10.
- When the LDAFR marker is absent, it checks the first four bytes for **STOP** and returns a distinct completion status if they match.

This independently supports the 1H equation `(count + address bytes + data bytes + checksum) mod 256 = 255`. It also supports the normal-packet address order and the separation of the special opening record from normal packets.

The earlier selected-string search found no literal-loaded `LDAFR` or `STOP` strings here because the code compares character constants directly. An empty string-search result therefore does not mean that a format is unsupported.

The STOP branch examined here tests four characters. It does not interpret the optional 00/01 suffixes seen in the files. That narrows this reader's behavior; it is not proof that no other consumer uses the suffixes. Likewise, a fixed 0x109-byte read depends on an underlying storage interface: the offline parser must not imitate it by reading beyond the supplied file. Its stricter truncation, bounds and overlap checks remain intact.

## 5. What is still missing

The constructor chain and packet reader establish a lens-side record-processing path. They do not establish a camera-UPD parser, AES or another cipher, key derivation, signature verification, or a portable image renderer. No rendering curves, colour matrices, autofocus model or video transform were recovered here.

The next focused question is the **destination interface**: backend member +8 is supplied from **0x2000ADA0** in the observed initialization sequence. Its table slots +0x0C and +0x10 receive record data and the subsequent completion call. The reader's underlying interface, supplied from **0x2000AC9C**, also needs identification. Follow their constructors and code before naming storage hardware, flash operations or reset behavior.

Do not extend lens analysis indefinitely on the assumption that it must reveal the camera key. Camera-UPD protection-consumer research remains a separate requirement. Lens code that consumes LDAFR is not automatically code that consumes the camera's UPD directory.

## Completed validation and reproducibility

**240 unit tests pass locally and on GitHub:** 222 inherited plus 18 new tests for Thumb BL decoding, ASCII folding and bounded sparse string reads. Separately, **2,048 deterministic synthetic Thumb BL encodings** agree with Capstone's decoded target operands. These cross-checks ran on GitHub, not locally. The reference ASCII-fold function is tested across all 256 byte values; firmware functions were not executed.

The final source experiment asserts selected method pointers, constructor references, the comparator helper call, the enclosing method's return boundary and selected names before emitting its report. Code analysis uses the pinned Capstone distribution in requirements-analysis.txt. Its previously documented distribution/module version difference remains applicable.

Completed real-source runs:

| Purpose | Run | Job | Source commit |
|---|---:|---:|---|
| Full comparator and command-object trace with new tests | 36345523899 | 108693788905 | 195743150c111b416b94e89fdfa2bcc77a14969b |
| Constructor-supplied backend tables | 36345747420 | 108694416944 | e5b47e8eba3c985465ee9368fe3e205ce94aa95f |
| Resolved backend and independent BL checks | 36345853240 | 108694713437 | 52480725e7d0ae216e7b31a3734a1b3bd24b485b |
| Reader methods and final selected evidence assertions | 36345916740 | 108694896433 | 92a87b8932fe3c8a2c111bcc83397cf5a58a70cf |

Source-only checks passed; the final source job inspected 80 tracked files. Committed evidence is a reviewed selection from these outputs, not a full log archive. The five new Python source/test files match their GitHub blob hashes. Main-branch publication and fresh-archive checks are recorded separately in delivered evidence.

The initial callsite tool retains exploratory linear windows; those are not complete function definitions, and some neighboring data can decode as instructions. The semantic results above use the complete comparator branch analysis, constructor links and bounded reader methods instead. No claim of complete runtime control flow is made.

No original or reconstructed binary, Look, private photograph, credential or raw UPD cryptographic metadata was committed. No M-series code or APK was changed. Development order remains SL3-P base still rendering, source-calibrated Photon integration, optional Looks, then video. No 4.2.2 or further user upload is required to continue.
