# SL3-P project handoff — RESEARCH1C

Date: 27 September 2026.

## User direction

Continue investigating existing 4.2.1. User does not have 4.2.2. Do not make another upload a prerequisite or repeat the request. Still rendering first, downloadable Looks second, video third. AF/recognition is separate. Device-independent target, active-camera source calibration, no Cobalt dependency, no introduced HDR, no visible quality sacrifice. Do not replace the unknown still renderer with the already published L-Log maths.

## Input

`SL3P_421 (1).lfu`, 201,752,064 bytes.
SHA256 `b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8`.
Unchanged at completion.

## Existing container

XOR-FF outer normalization; UPD/leica/MC7251. Directory at0x2ec, 61x92-byte entries, payload at0x1a00, file-offset base0x200. CRC9de57378 valid. 46flag3 opaque;15flag2 direct hashes match. Known expected FF plaintext:128KiB sections8/10; section60 is directly verified FF. Duplicate postboot names must remain distinct. Target offsets are not established RAM load addresses.

No protected section decoded. No ISA, runtime address, curve, matrix, model or image-processing implementation recovered. LUT region is still8.375MiB of zero, not a recovered Look or confirmed update policy.

## New RESEARCH1C results

1. All46protected metadata16 fields are distinct and nonzero; all reserved16 are zero. Matching expected-content pairs8/10,15/16,19/20,21/22 have different fields. Thus the field is not a deterministic plaintext-only fingerprint under the expected-digest interpretation. Does not identify IV/key/salt/tag.
2. 252known-fill/context checksum tests,14global64 digest tests,12raw x/y curve-point checks: no matches. These exclusions are narrow; no signature verification.
3. Extended key screen:85,995distinct keys =63,705prior candidates plus22,290new derived candidates. Ten protected-byte conventions, both00/FF plaintext conventions, CBC/CFB128/OFB/CTR-BE/CTR-LE. First64bytes of section8. Zero prefix hits. The8,599,500predicate combinations include repeated/overlapping hypotheses, not that many distinct keys. Keys hidden from header or other derivations/modes are not ruled out. Do not claim AES identified.
4. Seed-independent predictable-mask testing on8/10:512MT19937 tests,512specified xorshift128 tests,1,024low-order binary-recurrence lane tests. No matches. Full-word MT only; linear fit4096bits/holdout4096bits/maxdegree1024. Does not rule out arbitrary PRNGs or prove strong crypto.
5.77/77unit tests pass (37inherited+40new). Three controlled complete-UPD examples show correct positive decoding-screen behavior and rejection when only the prefix matches but later ciphertext is corrupted. No real-camera or renderer validation.

## Files / reproduction

`tools/sl3p_metadata_audit.py`, `tools/sl3p_extended_screen.py`, `tools/sl3p_stream_probe.py`.
Each takes firmware path and `--out`JSON. `python -m unittest discover -s tests -v` runs77tests.
Full parameters/results are under `evidence/`. No firmware payload included in the package.

## Next direction

Pursue actual loading/decryption implementation evidence from public UPD-family research, demonstrably related unprotected loader/update resources, or validated loader code. Public Q/Q3 discussion has similar fields but no working decoder. Searches this turn did not find a usable matching implementation. Local internet HTTP failed DNS; web and GitHub searches worked.

Do not spend the next turn simply relaunching the same85,995candidate screen. New cryptographic testing should be motivated by a concrete format/caller finding. No4.2.2 dependency. Do not claim that a different firmware version would decrypt this one automatically.

Once nonconstant plaintext passes its complete stored hash, establish architecture/load mapping and trace the base still renderer. Keep present M-series projects unchanged. No APK is warranted yet.
