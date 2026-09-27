# SL3-P continuation — RESEARCH1G

27 September 2026. Repository mwilliams455/SL3Camera. Research branch research/lens-layout1g. Recheck live main before any write. Publication and final CI identifiers are in evidence/research1g/repository_status.json in the downloadable bundle.

Read docs/RESEARCH1G_REPORT.md and evidence/research1g/lens_records_summary.json. 1F recovered the intended lens section from an independent official file; 1G now validates its internal record boundaries and CRCs. Still no camera decryptor/key/base renderer/AF implementation/APK.

## Inputs and access

Original SL3P_421 (1).lfu:201752064 bytes, SHA256 b53a5aa7fe111c9f63b28e7cf889d8af5b5bc9397912738aba595e79923e47d8. Rehashed locally unchanged.
SLLens11.plf:4575234 bytes, SHA9c5330c22c74fcc2c5f0efedf93f88c29db8d32ddf7476c688144190ce898600. Public Leica endpoint under /sites/default/files/. Appending16396286 zero bytes reproduces SL3-P section33's complete20971520-byte expected hash555040b9ef40ac269b6b520c6096d5ad78db5336a9ac599bf6b9f64b93cf8dc1.
Comparison70200_11.plf:1573978 bytes, SHA4e26dce0ec3a4e64454b46e9df9d4dcdfb319be6a3cb479fb95521fe0ed70d32.
Local DNS unavailable. Real sources were acquired/inspected in isolated GitHub jobs. No payload/cryptographic metadata dumps or binary artifacts published.

## New established layout

SOF marker21 bytes. u16BE count at29; table at31; each record19 bytes: >HBIIII = ordinal,kind,selector,absoluteoffset,size,CRC32. EOH marker21 bytes follows. Header size52+19*N.
SLLens11:40 records,14 absent,26 nonempty references,20 unique payloads,header812,unique payload bytes4574422. Complete range coverage and all20 CRCs match zlib.crc32 exactly.
Records20..25 share offset2458563,size251417,SHA970c5051271b02f65db6fef638837818dc807a083e201220d8aac8ecdecf98db. Records28..29 share offset2727144,size125206. Other nonempty ranges are distinct.
70200:2 records,header90,one absent kind2 with offset/size/check allFFFFFFFF. Other record offset90,size1573888,CRC3354654083,SHAbbdb099b15e4122111cb15215cb273bd85c709d11f87f313ea9048fdbbdcea7c. Whole coverage and CRC validate. No full-payload match to primary file.
Kind0/1 and selector semantic meanings remain unknown. 40 entries are NOT40 distinct lenses or images. Header values resembling dates are not established release dates.

## Concrete code-research target

fwupdate token at relative247797 within the shared251417-byte payload; absolute2706360 in standalone file. Only a string; no callable function identified. No ISA, runtime mapping, inner compression layout or code references established. Next: use exact payload CRC/SHA to gate inner-format/ISA checks; trace code only after mapping is defensible. Lens update code may not parse camera UPD at all.

## Reproduce and test

python tools/sl3p_lens_records1g.py explicitly downloads both pinned public sources, verifies primary complete section reconstruction, audits layouts/CRCs and prints selected JSON. Check BOTH per-file all_payload_crc32_verified flags; a future rejected comparison may be reported rather than an overall exception. parse_layout is structural only; verify_lens is strict checksum gate.
python -m unittest discover -s tests -v:175 tests=156+19. All175 passed locally. Real-source run36338148378/job108672861989/commit2f84e853464b80cc586a88bc463d2bea87e026df passed19newtests and verified both sources. Main fullCI recorded separately.
Intermediate failure36337873828 was the all-ones sentinel before its interpretation was added; do not call the actual source corrupt or hide that rejection. No bounds check was disabled.

Keep base still rendering -> Photon -> Looks -> video. Target remains device-independent, sourcecal separate; no Cobalt, addedHDR or M-series substitute. No4.2.2/LUTupload prerequisite. No blind-key screen restart.
