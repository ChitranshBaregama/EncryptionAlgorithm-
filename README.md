# DLMS/COSEM Security — Engineering Reference

A seven-volume reference on the security stack of DLMS/COSEM (IEC 62056), the
protocol behind most of the world's smart electricity meters. Roughly 60,000
words, written for the person who has to **implement, review and debug** it on
a microcontroller — not for the person writing a standards summary.

Built from **DLMS UA 1000-2 Ed. 8.0 (Green Book, 8th edition)** as the sole
normative source. Every official test vector in it has been reproduced
independently; nine errors in a widely-circulated secondary guide are
documented, with the Green Book clause that settles each one.

---

## Why this exists

DLMS/COSEM security is badly served by the material available to a working
engineer. The specification is precise but assumes you already know the
cryptography and says nothing about firmware. Secondary guides fill the gap
and get details wrong — details that produce a meter which passes your bench
test and fails interoperability.

This manual sits in between: specification-accurate, with the firmware layer
the specification deliberately leaves out, and with every claim labelled by
how much weight it can bear.

---

## The claim-labelling convention

Every substantive statement carries one of five labels. This is the part worth
copying even if you never read the rest.

| Label | Means |
| :--- | :--- |
| **[SPEC]** | A specification requirement, traceable to a Green Book clause or table |
| **[THEORY]** | General cryptographic theory — true independently of DLMS |
| **[IMPL]** | An implementation recommendation. Sound engineering, not mandated |
| **[VENDOR]** | Behaviour that varies between manufacturers. Never assume it is DLMS |
| **[INFER]** | An engineering inference from [SPEC] + [THEORY]. Reasonable, but verify |

And where the supplied sources cannot settle a question, the text says so
outright rather than guessing:

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»**

That marker appears most often around COSEM interface-class detail, which
lives in the Blue Book (DLMS UA 1000-1) and is outside the source set here.

---

## The volumes

| Vol | File | Covers |
| :--- | :--- | :--- |
| **0** | [Master index and errata](00-MASTER-INDEX-AND-ERRATA.md) | Source policy, knowledge map, and the nine documented errata |
| **1** | [Foundations and association security](VOL-1-Foundations-and-Association-Security.md) | Cryptographic prerequisites, the security architecture, application association, LLS and HLS |
| **2** | [Symmetric core and wire format](VOL-2-Symmetric-Core-and-Wire-Format.md) | AES, AES-GCM, GMAC in depth; the Security Control byte; IV and invocation counter; System Title; security suites; ciphered APDU wire format; verified test vectors |
| **3** | [Keys, PKI and key agreement](VOL-3-Keys-PKI-and-Key-Agreement.md) | Key architecture (GUEK/GBEK/GAK/KEK), key wrap, ECDSA, ECDH, the three key-agreement schemes, NIST Concat KDF, X.509 and PKI |
| **4** | [General ciphering and packet analysis](VOL-4-General-Ciphering-and-Packet-Analysis.md) | General-ciphering and general-signing, multi-layer protection, third-party end-to-end security, packet-by-packet captures, Wireshark, vendor differences |
| **5** | [Embedded firmware implementation](VOL-5-Embedded-Firmware-Implementation.md) | Module architecture, memory budgets, secure key storage, RNG on an MCU, provisioning lifecycle, key rotation |
| **6** | [Debugging, attacks, labs and capstone](VOL-6-Debugging-Attacks-Labs-and-SME-Capstone.md) | Failure-mode matrix, attack analysis, key-compromise blast radius, the top 50 mistakes, 12 labs, 45 interview questions with answers, an SME capstone with a rubric |

**Volumes 1 and 2 are load-bearing.** Internalise those and you can sit in
front of a capture of a ciphered `glo-get-request` and reason about it
correctly. Volumes 3–6 build outward from that core.

---

## Verified test vectors

[`dlms_test_vectors.py`](dlms_test_vectors.py) reproduces the official Green
Book vectors from Table 40 (`glo-get-request`, all three protection modes) and
Table 43 (HLS mechanism 5, GMAC, both directions) against a reference AES-GCM
implementation.

```bash
pip install cryptography
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

This is why the errata below can be stated as fact rather than opinion: the
arithmetic was checked, not argued about.

---

## Errata — nine errors in a widely-circulated security guide

Documented in full in [Volume 0 §0.4](00-MASTER-INDEX-AND-ERRATA.md#04-errata-corrections-to-the-supplied-security-guide).
Every one of these would produce a non-interoperable meter if carried into
firmware.

| # | Error | Severity |
| :--- | :--- | :--- |
| E-1 | HLS authentication mechanism IDs shifted by one — GMAC is mechanism **5**, not 4 | Critical |
| E-2 | Security Control byte bit layout wrong — suite ID is the low nibble, compression is bit 7 | Critical |
| E-3 | GMAC inputs wrong | Critical |
| E-4 | HLS SHA-256 described as HMAC; it is a plain hash | Major |
| E-5 | Ciphered APDU tags 0xC8 / 0xC9 misidentified | Major |
| E-6 | Service-specific ciphered tags missing entirely | Moderate |
| E-7 | Blue Book and Green Book IEC numbers swapped | Moderate |
| E-8 | "Security setup" attribute numbering unverifiable from the available sources | Source gap |
| E-9 | Terminology drift: "GEK", "Frame Counter", "transport-level security" | Terminology |

E-2 is the instructive one. The three commonly-quoted Security Control values
(`0x10`, `0x20`, `0x30`) happen to decode identically under both the correct
and the incorrect bit layout, because Suite 0 is all zeros either way. The
error only surfaces the moment you touch broadcast keys, compression, or
Suite 1/2 — at which point the wrong layout sends you to the wrong key with
the wrong algorithm.

---

## Who this is for

- Firmware engineers implementing DLMS/COSEM security on constrained hardware
- Anyone reviewing such an implementation, or debugging an association that
  will not come up
- Utility and test-house engineers reading ciphered captures
- Anyone preparing for interviews in smart metering — Volume 6 has 45
  questions with answers and a capstone with a marking rubric

Assumed background: comfortable C, comfortable reading a specification, basic
familiarity with symmetric cryptography. The manual does not teach AES from
scratch, but it does explain every DLMS-specific use of it.

---

## Related

- [**Embedded systems reference**](https://github.com/ChitranshBaregama/embedded-systems-resources) — bare-metal firmware notes and runnable Cortex-M code
- [**SMS P10 notice board**](https://github.com/ChitranshBaregama/sms-p10-notice-board) — GSM-controlled LED notice board firmware

## A note on sources

This manual asserts nothing as specification that does not trace to the Green
Book 8th edition. Where a secondary source was used, it is cited as secondary
and its errors are listed. Where the answer requires a document that was not
available, that is marked as a source gap rather than filled with a guess.

If you find an error here, please open an issue with the clause that settles
it. That is exactly the process that produced the errata above.

## Licence

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) — share and adapt
with attribution.
