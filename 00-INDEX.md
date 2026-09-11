# DLMS/COSEM Security — Engineering Reference

**Volume 0 — Index, Source Policy, and Verified Test Vectors**

> Written for the embedded firmware engineer who will implement, review and
> debug DLMS/COSEM security on a microcontroller — not for the person writing
> a standards summary.

This manual is built from the Green Book, 8th edition, as its sole normative
source. Nothing is asserted as specification that does not trace to a clause
or table in it, and everything that is engineering judgement rather than
specification is labelled as such (§0.2).

**Contents**
[Primary source](#01-primary-source) ·
[Claim labels](#02-claim-labelling-convention) ·
[Volume map](#03-volume-map) ·
[Verified test vectors](#04-verified-test-vectors) ·
[Knowledge map](#05-knowledge-map) ·
[How to use this manual](#06-how-to-use-this-manual)

---

## 0.1 Primary source

| Ref | Document | Role in this manual |
|-----|----------|---------------------|
| **[GB]** | DLMS UA 1000-2 Ed. 8.0, *DLMS/COSEM Architecture and Protocols* (Green Book, 8th Edition, 2014-07-07) | **Normative.** Every protocol fact, field name, table and test vector in this manual traces to this document. |

The Green Book security material lives in **clause 9.2 "Information security in
DLMS/COSEM"**, pages 146–206, and is structured exactly as the DLMS UA intends
the subject to be learned:

```
9.2.1  Overview
9.2.2  The DLMS/COSEM security concept
       9.2.2.2  Identification and authentication
       9.2.2.3  Security context
       9.2.2.4  Access rights
       9.2.2.5  Application layer message security
       9.2.2.6  COSEM data security
9.2.3  Cryptographic algorithms
       9.2.3.2  Hash function
       9.2.3.3  Symmetric key algorithms  (AES, GCM, GMAC, key wrap)
       9.2.3.4  Public key algorithms     (ECC, ECDSA, key agreement, KDF)
       9.2.3.5  Random number generation
       9.2.3.6  Compression
       9.2.3.7  Security suite
9.2.4  Cryptographic keys – overview
9.2.5  Keys used with symmetric key algorithms
9.2.6  Keys used with public key algorithms  (PKI, X.509, provisioning)
9.2.7  Applying cryptographic protection
       9.2.7.2  Protecting xDLMS APDUs
       9.2.7.3  Multi-layer protection by multiple parties
       9.2.7.4  HLS authentication mechanisms
       9.2.7.5  Protecting COSEM data
```

This manual follows that skeleton and adds the firmware layer the
specification deliberately leaves out.

---

---

## 0.2 Claim-labelling convention

Every substantive statement in this manual carries one of five labels. Read
them; they are the difference between a specification requirement and my
opinion.

| Label | Meaning |
|-------|---------|
| **[SPEC]** | A DLMS/COSEM specification requirement, traceable to a Green Book clause or table. |
| **[THEORY]** | General cryptographic theory. True independently of DLMS. |
| **[IMPL]** | An implementation recommendation. Sound engineering, not mandated by the specification. |
| **[VENDOR]** | Behaviour that varies between manufacturers. Never assume it is DLMS. |
| **[INFER]** | Practical engineering inference drawn from [SPEC] + [THEORY]. Reasonable, but verify. |

And where the Green Book alone cannot settle a question:

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»**

You will see that marker most often around COSEM interface-class detail
(attribute and method numbering of "Security setup" and "Association LN"),
because that lives in the **Blue Book** (DLMS UA 1000-1), which is outside
the source set used here. Where you see that marker, check the edition that
applies to your project rather than trusting this manual.

---

---

## 0.3 Volume map

| Vol | File | Chapters | Covers |
|-----|------|----------|--------|
| **0** | `00-INDEX.md` | — | Source policy, claim labels, volume map, verified test vectors, knowledge map |
| **1** | `VOL-1-Foundations-and-Association-Security.md` | 1–6 | Crypto prerequisites, security architecture, the three concepts, application association, LLS, HLS |
| **2** | `VOL-2-Symmetric-Core-and-Wire-Format.md` | 7–13 | AES, AES-GCM, GMAC deep dive, Security Control byte, IV/Invocation Counter, System Title, security suites, ciphered APDU wire format, verified test vectors |
| **3** | `VOL-3-Keys-PKI-and-Key-Agreement.md` | 14–19 | Key architecture, key wrap/KEK, global vs dedicated, ECDSA, ECDH, the three key agreement schemes, NIST Concat KDF, X.509 and PKI |
| **4** | `VOL-4-General-Ciphering-and-Packet-Analysis.md` | 20–24 | General-ciphering, general-signing, multi-layer protection, third-party end-to-end, COSEM data protection, packet-by-packet captures, Wireshark, vendor differences |
| **5** | `VOL-5-Embedded-Firmware-Implementation.md` | 25–30 | Firmware module architecture, memory budgets, secure key storage, RNG on MCU, provisioning lifecycle, key rotation |
| **6** | `VOL-6-Debugging-Attacks-Labs-and-SME-Capstone.md` | 31–38 | Failure-mode matrix, attack analysis, key-compromise blast radius, top-50 mistakes, 12 labs, 45 interview questions with answers, SME capstone with rubric, glossary |

Volumes 1 and 2 are the load-bearing ones. If you internalise those, you can
already sit in front of a capture of a ciphered `glo-get-request` and reason
about it correctly. Volumes 3–6 build outward from that core.

---

---

## 0.4 Verified test vectors

The Green Book contains official test vectors. I reproduced them
independently with a standard AES-GCM implementation. All seven match:

| Vector | [GB] source | Result |
|--------|-------------|--------|
| glo-get-request, authentication only (SC `0x10`) | Table 40 | ✅ tag `06725D910F9221D263877516` |
| glo-get-request, encryption only (SC `0x20`) | Table 40 | ✅ ciphertext `411312FF935A47566827C467BC` |
| glo-get-request, authenticated encryption (SC `0x30`) — ciphertext | Table 40 | ✅ matches |
| glo-get-request, authenticated encryption (SC `0x30`) — tag | Table 40 | ✅ tag `7D825C3BE4A77C3FCC056B6B` |
| HLS mechanism 5, Pass 3 `f(StoC)` | Table 43 | ✅ tag `1A52FE7DD3E72748973C1E28` |
| HLS mechanism 5, Pass 4 `f(CtoS)` | Table 43 | ✅ tag `FE1466AFB3DBCD4F9389E2B7` |
| Full assembled ciphered APDU (all three SC modes) | Table 40 | ✅ byte-identical |

**Practical consequence:** these are the vectors your firmware self-test
should use. If your AES-GCM layer reproduces Table 40 and Table 43, your
IV construction, AAD construction, tag truncation, and key handling are all
correct. Volume 2 walks each one byte by byte.

[GB] Table 44 additionally provides an ECDSA (mechanism 7) vector on P-256.
I have not independently verified it — verifying ECDSA requires the exact
per-signature nonce `k`, which the Green Book does not publish, so the
signature values cannot be recomputed deterministically. They can only be
*verified* against the given public keys. Treat Table 44 as authoritative for
verification testing, not for signing self-test.

---

---

## 0.5 Knowledge map

How every concept in this manual depends on every other. Read bottom-up when
learning, top-down when debugging.

```
                 PRODUCTION DLMS SECURITY ARCHITECTURE
                              ▲
                    ┌─────────┴─────────┐
              Secure Firmware      Key Provisioning
                    ▲                    ▲
         ┌──────────┴────────┐    ┌──────┴──────┐
   Secure Key Storage   Counter    Key Rotation  Certificate
   (OTP/eFuse/SE)      Persistence               Management
         ▲                  ▲            ▲            ▲
         └──────────┬───────┘            └──────┬─────┘
                    │                           │
              Key Architecture ◄────────── Key Wrapping
              (GUEK/GBEK/GAK/                (AES-WRAP,
               dedicated/KEK)                 RFC 3394)
                    ▲                           ▲
                    │                           │
              Security Context ◄────────── Key Agreement
              (suite+policy+                (C(2e,0s)
               material)                     C(1e,1s)
                    ▲                        C(0e,2s))
                    │                           ▲
         ┌──────────┼──────────┐                │
         │          │          │          Key Derivation
   Security     Security   Access           (NIST Concat KDF)
   Suite        Control    Rights                 ▲
   (0/1/2)      Byte                              │
         ▲          ▲                        ECDH ◄── ECC
         └────┬─────┘                          ▲       ▲
              │                                │       │
        Ciphered APDU ◄──── System Title    ECDSA ─────┘
        (glo/ded/general)        ▲             ▲
              ▲                  │             │
              │           Invocation Counter   │
              │                  ▲             │
              └────────┬─────────┘             │
                       │                       │
                    AES-GCM ──► GMAC           │
                       ▲                       │
                       │                       │
                      AES                    Hash
                       ▲                    (SHA-256/384)
                       │                       ▲
                       └───────────┬───────────┘
                                   │
                        CRYPTOGRAPHY FUNDAMENTALS
                 (confidentiality, integrity, authenticity,
                  keys, nonces, entropy, replay, MITM)
```

**Reading the map.** Three vertical spines run from bottom to top:

1. **The symmetric spine** (centre): AES → AES-GCM → GMAC → ciphered APDU.
   This is what actually protects 99% of production traffic today. Suite 0
   consists of nothing else.
2. **The asymmetric spine** (right): hash → ECC → ECDSA/ECDH → key agreement →
   key derivation. This exists to solve one problem the symmetric spine cannot:
   *how do two parties who have never met establish a shared key?*
3. **The identity spine** (left-centre): System Title → Invocation Counter →
   IV. This is what makes the symmetric spine safe to use more than once.

The three converge at **Security Context**, which is the single object your
firmware must get right. Everything above that line is operations; everything
below is mathematics.

---

---

## 0.6 How to use this manual

**If you are learning:** Volume 1 → Volume 2, in order, and do not skip the
byte-level examples. Reproduce Table 40 yourself in Python before you write a
line of C.

**If you are debugging a live failure:** jump to Volume 2 Chapter 8 (Security
Control byte decode) and Chapter 10 (IV construction). In my experience
[INFER], the overwhelming majority of DLMS security failures are one of four
things — wrong invocation counter, wrong system title in the IV, AAD built
without the authentication key, or the wrong key set selected — and all four
are visible in the first six bytes of the ciphered APDU.

**If you are reviewing someone's implementation:** Volume 2 Chapter 10 §"Power
loss and counter persistence" and Volume 0 §0.4 (test vectors) are the two
things to check first. A DLMS stack that does not reproduce Table 40 is not
finished, whatever its author says.

---

*End of Volume 0.*

---

**Next:** [Volume 1 — Foundations and Association Security](VOL-1-Foundations-and-Association-Security.md) →
