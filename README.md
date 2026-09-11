# DLMS/COSEM Security — Engineering Reference

A seven-volume reference on the security stack of DLMS/COSEM (IEC 62056), the
protocol behind most of the world's smart electricity meters. Roughly 60,000
words, written for the engineer who has to **implement, review and debug** it
on a microcontroller — not for the person writing a standards summary.

Built from **DLMS UA 1000-2 Ed. 8.0 (Green Book, 8th edition)** as its sole
normative source. Every official test vector in it has been reproduced
independently, and the script that does so is in this repository.

---

## Start here

| If you want to… | Go to |
| :--- | :--- |
| Understand how the manual is built and what its labels mean | [Volume 0 — Index and source policy](00-INDEX.md) |
| Learn the subject properly, in order | [Volume 1](VOL-1-Foundations-and-Association-Security.md) → [Volume 2](VOL-2-Symmetric-Core-and-Wire-Format.md) |
| Debug a live association failure | [Volume 6 §31 — failure-mode matrix](VOL-6-Debugging-Attacks-Labs-and-SME-Capstone.md) |
| Decode a ciphered APDU byte by byte | [Volume 2](VOL-2-Symmetric-Core-and-Wire-Format.md) |
| Write the firmware | [Volume 5](VOL-5-Embedded-Firmware-Implementation.md) |
| Check your AES-GCM layer against the official vectors | [`dlms_test_vectors.py`](dlms_test_vectors.py) |

---

## The volumes

| Vol | Chapters | Covers |
| :--- | :--- | :--- |
| **[0 — Index and source policy](00-INDEX.md)** | — | The single normative source, the claim-labelling convention, the volume map, verified test vectors, the knowledge map |
| **[1 — Foundations and association security](VOL-1-Foundations-and-Association-Security.md)** | 1–6 | Cryptographic prerequisites, the DLMS security architecture, the three security concepts, application association, LLS and all six HLS mechanisms |
| **[2 — The symmetric core and the wire format](VOL-2-Symmetric-Core-and-Wire-Format.md)** | 7–13 | AES, AES-GCM in depth, GMAC, the Security Control byte bit by bit, the IV and invocation counter, System Title, security suites, and the ciphered APDU on the wire |
| **[3 — Keys, PKI and key agreement](VOL-3-Keys-PKI-and-Key-Agreement.md)** | 14–19 | The key hierarchy (GUEK/GBEK/GAK/KEK), AES Key Wrap, global versus dedicated ciphering, ECDSA, ECDH, the three key-agreement schemes, the NIST Concat KDF, X.509 and PKI |
| **[4 — General ciphering and packet analysis](VOL-4-General-Ciphering-and-Packet-Analysis.md)** | 20–24 | General-ciphering and general-signing, multi-layer protection, third-party end-to-end security, COSEM data protection, packet-by-packet captures, Wireshark technique, vendor differences |
| **[5 — Embedded firmware implementation](VOL-5-Embedded-Firmware-Implementation.md)** | 25–30 | Module architecture, memory budgets, secure key storage from flash to secure element, RNG on an MCU, the provisioning lifecycle, key rotation |
| **[6 — Failure analysis, attacks, labs and capstone](VOL-6-Debugging-Attacks-Labs-and-SME-Capstone.md)** | 31–38 | The failure-mode matrix, attack analysis, key-compromise blast radius, the top 50 mistakes, 12 labs, 45 interview questions with answers, an SME capstone with a rubric, glossary |

**Volumes 1 and 2 are the load-bearing ones.** Internalise those and you can
sit in front of a capture of a ciphered `glo-get-request` and reason about it
correctly. Volumes 3–6 build outward from that core.

---

## The claim-labelling convention

Every substantive statement carries one of five labels. This is the part worth
copying even if you read nothing else.

| Label | Means |
| :--- | :--- |
| **[SPEC]** | A specification requirement, traceable to a Green Book clause or table |
| **[THEORY]** | General cryptographic theory — true independently of DLMS |
| **[IMPL]** | An implementation recommendation. Sound engineering, not mandated |
| **[VENDOR]** | Behaviour that varies between manufacturers. Never assume it is DLMS |
| **[INFER]** | An engineering inference from [SPEC] + [THEORY]. Reasonable, but verify |

Where the Green Book alone cannot settle a question, the text says so outright
rather than guessing:

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»**

That marker appears most often around COSEM interface-class detail, which
lives in the Blue Book (DLMS UA 1000-1) and is outside this source set.

---

## Verified test vectors

[`dlms_test_vectors.py`](dlms_test_vectors.py) reproduces the official Green
Book vectors from Table 40 (`glo-get-request`, all three protection modes) and
Table 43 (HLS mechanism 5, GMAC, both directions) against a reference AES-GCM
implementation.

```bash
pip install -r requirements.txt
python3 dlms_test_vectors.py
```

Every vector matches:

```
[SC=0x10 authentication only]
  computed T = 06725D910F9221D263877516  expected 06725D910F9221D263877516 -> MATCH
[SC=0x20 encryption only]
  computed C = 411312FF935A47566827C467BC expected 411312FF935A47566827C467BC -> MATCH
[SC=0x30 authenticated encryption]
  computed T = 7D825C3BE4A77C3FCC056B6B   expected 7D825C3BE4A77C3FCC056B6B  -> MATCH

TABLE 43 - HLS mechanism 5 (GMAC)
  f(StoC) T = 1A52FE7DD3E72748973C1E28  expected 1A52FE7DD3E72748973C1E28  -> MATCH
  f(CtoS) T = FE1466AFB3DBCD4F9389E2B7  expected FE1466AFB3DBCD4F9389E2B7  -> MATCH
```

**This is the practical takeaway of the whole manual.** These are the vectors
your firmware self-test should use. If your AES-GCM layer reproduces Table 40
and Table 43, then your IV construction, AAD construction, tag truncation and
key handling are all correct. Volume 2 walks each one byte by byte.

---

## Who this is for

- Firmware engineers implementing DLMS/COSEM security on constrained hardware
- Anyone reviewing such an implementation, or debugging an association that
  will not come up
- Utility and test-house engineers reading ciphered captures
- Anyone preparing for smart-metering interviews — Volume 6 has 45 questions
  with answers and a capstone with a marking rubric

Assumed background: comfortable C, comfortable reading a specification, basic
familiarity with symmetric cryptography. The manual does not teach AES from
scratch, but it does explain every DLMS-specific use of it.

---

## Related

- [**Embedded systems reference**](https://github.com/ChitranshBaregama/embedded-systems-resources) — bare-metal firmware notes and runnable Cortex-M code
- [**SMS P10 notice board**](https://github.com/ChitranshBaregama/sms-p10-notice-board) — GSM-controlled LED notice board firmware

## Corrections

If you find an error, please open an issue with the Green Book clause that
settles it. Every claim here is traceable to a clause or a test vector, which
means every claim here is falsifiable — that is the point.

## Licence

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — share and adapt
with attribution.
