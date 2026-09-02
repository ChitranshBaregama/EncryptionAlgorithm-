# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 0 — Master Index, Source Policy, and Errata**

Author's note: this manual is written for an embedded firmware engineer who
will implement, review, and debug DLMS/COSEM security on a microcontroller.
It is built from two supplied references and nothing else is asserted as
specification.

---

## 0.1 Primary sources

| Ref | Document | Role in this manual |
|-----|----------|---------------------|
| **[GB]** | DLMS UA 1000-2 Ed. 8.0, *DLMS/COSEM Architecture and Protocols* (Green Book, 8th Edition, 2014-07-07) | **Normative.** All protocol facts, field names, tables, and test vectors trace to this. |
| **[SG]** | *DLMS/COSEM Security — Complete Reference Guide* (supplied `.md`) | **Secondary / tertiary.** Useful framing and field-engineering notes. Contains errors — see §0.4. |

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

And where the supplied material cannot settle a question:

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»**

You will see that marker most often around COSEM interface-class detail
(attribute and method numbering of "Security setup" and "Association LN"),
because that lives in the **Blue Book** (DLMS UA 1000-1), which was not
supplied.

---

## 0.3 Volume map

| Vol | File | Chapters | Covers |
|-----|------|----------|--------|
| **0** | `00-MASTER-INDEX-AND-ERRATA.md` | — | Index, source policy, errata, knowledge map |
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

## 0.4 ERRATA — corrections to the supplied Security Guide

**Read this section before you use `DLMS_Security_Complete_Guide_1_.md` for
anything.** I verified each item against the Green Book, and where arithmetic
was involved, against a working AES-GCM implementation. Every one of these
errors would produce a non-interoperable meter if carried into firmware.

---

### E-1 — HLS authentication mechanism IDs are shifted by one 🔴 CRITICAL

**[SG] §3.1 claims:** mechanism 2 = MD5, 3 = SHA-1, 4 = GMAC, 5 = SHA-256,
6 = ECDSA, 7 = ECDSA+ECDH.

**[GB] Table 75 (clause 9.4.2.2.3) specifies:**

| mechanism_id | Correct name |
|--------------|--------------|
| 0 | `COSEM_lowest_level_security_mechanism_name` |
| 1 | `COSEM_low_level_security_mechanism_name` (LLS) |
| 2 | `COSEM_high_level_security_mechanism_name` — **manufacturer-specific**; the challenge-processing method is secret |
| 3 | `..._using_MD5` |
| 4 | `..._using_SHA-1` |
| 5 | `..._using_GMAC` |
| 6 | `..._using_SHA-256` |
| 7 | `..._using_ECDSA` |

**Why it matters:** `mechanism_id` is the last arc of the OID
`2.16.756.5.8.2.x` carried in the `mechanism-name` field of the AARQ. Get it
wrong and the server rejects the association, or worse, silently negotiates a
weaker mechanism than you intended. The guide's whole §3.4 is titled "HLS
Mechanism 4 (GMAC)" — **GMAC is mechanism 5.**

Note also that the guide invents a distinct mechanism 7 "ECDSA + ECDH". [GB]
Table 42 lists mechanism 7 as **HLS ECDSA**. ECDH key agreement in
DLMS/COSEM is a separate facility (the `key_agreement` method of "Security
setup", and the `key-info` field of `general-ciphering`), not an HLS
mechanism. Conflating the two is exactly the ECDSA/ECDH confusion this manual
forbids.

---

### E-2 — Security Control byte bit layout is wrong 🔴 CRITICAL

**[SG] §7 claims:**

```
Bit:   7    6    5    4    3    2    1    0
     ┌────┬────┬────┬────┬────┬────┬────┬────┐
     │ S1 │ S0 │ E  │ A  │ R  │ C  │ K1 │ K0 │   ← WRONG
     └────┴────┴────┴────┴────┴────┴────┴────┘
```

**[GB] Table 37 (clause 9.2.7.2.4.2) specifies:**

```
Bit:   7        6         5    4         3    2    1    0
     ┌────────┬─────────┬────┬────┬───────────────────────┐
     │ Compr. │ Key_Set │ E  │ A  │  Security_Suite_Id    │   ← CORRECT
     └────────┴─────────┴────┴────┴───────────────────────┘
       bit 7    bit 6     b5   b4         bits 3..0
```

The suite ID occupies the **low nibble**, not the top two bits. Compression is
bit **7**, not bit 2. Key_Set is bit **6**, not bits 1–0.

**Consequence — the guide's decode table is wrong for every non-zero suite:**

| SC | [SG] decode | **[GB] correct decode** |
|----|-------------|-------------------------|
| `0x10` | Authenticated only, Suite 0 | ✅ Authenticated only, unicast, Suite 0 |
| `0x20` | Encrypted only, Suite 0 | ✅ Encrypted only, unicast, Suite 0 |
| `0x30` | Auth + Enc, Suite 0 | ✅ Auth + Enc, unicast, Suite 0 |
| `0x50` | ❌ "Authenticated only, Suite 1" | **Authenticated only, BROADCAST key, Suite 0** |
| `0x70` | ❌ "Auth + Enc, Suite 1" | **Auth + Enc, BROADCAST key, Suite 0** |
| `0xB0` | ❌ "Auth + Enc, Suite 2" | **Compression + Auth + Enc, unicast, Suite 0** |

The three low-value examples coincidentally survive because Suite 0 is all
zeros in both layouts. The moment you touch broadcast keys, compression, or
Suite 1/2, the guide sends you to the wrong key and the wrong algorithm.

**Correct encodings for the higher suites** (unicast, authenticated
encryption): Suite 1 → `0x31`, Suite 2 → `0x32`.

---

### E-3 — GMAC inputs are wrong 🔴 CRITICAL

**[SG] §3.4 claims:**

```
AAD       = SC(1) + Authentication_Key(16) = 17 bytes
Plaintext = StoC_challenge                              ← WRONG
```

**[GB] Table 38 specifies** that for authentication-only protection
(E=0, A=1) the plaintext **P is null** and:

```
A (Additional Authenticated Data) = SC ‖ AK ‖ I
```

where `I` is the information being protected — here, the challenge.

For HLS mechanism 5, [GB] Table 42 gives the formula directly:

```
Pass 3 (client → server):  f(StoC) = SC ‖ IC ‖ GMAC(SC ‖ AK ‖ StoC)
Pass 4 (server → client):  f(CtoS) = SC ‖ IC ‖ GMAC(SC ‖ AK ‖ CtoS)
```

The challenge is **associated data, never plaintext**. That is the entire
point of GMAC: nothing is encrypted, everything is authenticated. If you feed
the challenge in as plaintext you produce a ciphertext the peer does not
expect and a tag that will never verify.

**I verified this computationally.** Using [GB] Table 43's official material
(EK = `000102...0E0F`, AK = `D0D1...DEDF`, SC = `0x10`, client
Sys-T = `4D4D4D0000000001`, IC = `00000001`, StoC = `"P6wRJ21F"`):

```
AAD = 10 D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF 503677524A323146
P   = (empty)
→ T = 1A52FE7DD3E72748973C1E28   ✅ matches [GB] Table 43 exactly
```

The guide's construction does not reproduce the official vector. This one
reproduces it byte for byte.

---

### E-4 — HLS SHA-256 is a plain hash, not HMAC 🟠 MAJOR

**[SG] §3.3 claims:** `HMAC-SHA-256(secret, challenge)`.

**[GB] Table 42, mechanism_id(6):**

```
Pass 3:  SHA-256( HLS_Secret ‖ SystemTitle-C ‖ SystemTitle-S ‖ StoC ‖ CtoS )
Pass 4:  SHA-256( HLS_Secret ‖ SystemTitle-S ‖ SystemTitle-C ‖ CtoS ‖ StoC )
```

Three separate corrections in one:

1. It is a **plain SHA-256 hash**, not HMAC. Different construction, different
   output.
2. The input includes **both system titles**, which the guide omits entirely.
3. The input includes **both challenges**, in an order that is deliberately
   swapped between pass 3 and pass 4 — that asymmetry is what stops an
   attacker from replaying the client's proof back at the client.

---

### E-5 — Ciphered APDU tags 0xC8 / 0xC9 are misidentified 🟠 MAJOR

**[SG] §18.1 claims:** `0xC8` = glo-initiate-request, `0xC9` =
glo-initiate-response.

**[GB] clause 9.5 (COSEMpdu ASN.1):**

| Tag | Decimal | Correct APDU |
|-----|---------|--------------|
| `0x21` | [33] | `glo-initiateRequest` |
| `0x28` | [40] | `glo-initiateResponse` |
| `0xC8` | [200] | **`glo-get-request`** |
| `0xC9` | [201] | **`glo-set-request`** |

This is confirmed independently by [GB] Table 40, whose worked example of a
protected GET begins `C8 1E 30 01234567 ...` — tag `0xC8`, length `0x1E`,
then the security header.

---

### E-6 — The service-specific ciphered tags are missing entirely 🟡 MODERATE

[SG] §18.1 shows every GET/SET/ACTION as "wrapped in `0xDB`". That is one of
two legitimate options, and in practice the *less* common one on
client–server links. The full LN-referencing set from [GB] clause 9.5:

| Plain | Tag | Global | Tag | Dedicated | Tag |
|-------|-----|--------|-----|-----------|-----|
| get-request | `0xC0` | glo-get-request | `0xC8` | ded-get-request | `0xD0` |
| set-request | `0xC1` | glo-set-request | `0xC9` | ded-set-request | `0xD1` |
| event-notification | `0xC2` | glo-event-notification | `0xCA` | ded-event-notification | `0xD2` |
| action-request | `0xC3` | glo-action-request | `0xCB` | ded-action-request | `0xD3` |
| get-response | `0xC4` | glo-get-response | `0xCC` | ded-get-response | `0xD4` |
| set-response | `0xC5` | glo-set-response | `0xCD` | ded-set-response | `0xD5` |
| action-response | `0xC7` | glo-action-response | `0xCF` | ded-action-response | `0xD7` |

Plus the general-purpose wrappers:

| Tag | Decimal | APDU |
|-----|---------|------|
| `0xDB` | [219] | `general-glo-ciphering` |
| `0xDC` | [220] | `general-ded-ciphering` |
| `0xDD` | [221] | `general-ciphering` |
| `0xDF` | [223] | `general-signing` |
| `0xE0` | [224] | `general-block-transfer` |

Note the gap: `0xC6` / `0xCE` / `0xD6` are **not** assigned — there is no
`event-notification-response`. Tags `0xE6` and `0xE7` ([230], [231]) are
reserved for the DLMS Gateway.

---

### E-7 — Blue Book and Green Book IEC numbers are swapped 🟡 MODERATE

[SG] subtitle reads: *"Based on IEC 62056-5-3 (Blue Book), IEC 62056-6-2
(Green Book)"*. Reversed.

- **IEC 62056-5-3** = DLMS/COSEM application layer = **Green Book**
  (DLMS UA 1000-2)
- **IEC 62056-6-2** = COSEM interface classes and OBIS = **Blue Book**
  (DLMS UA 1000-1)

Minor on its own, but it tells you the guide was not carefully checked against
its own cited sources — which is why E-1 through E-6 exist.

---

### E-8 — "Security setup" attribute numbering is unverifiable here ⚪ SOURCE GAP

[SG] §18.3 lists Security setup (IC = 64) attributes 6–9 as
`global_unicast_enc_key`, `global_broadcast_enc_key`, `authentication_key`,
`master_key`.

[GB] consistently refers key handling to **DLMS UA 1000-1 Ed. 12:2014 clause
4.4.7**, and describes key installation as happening through the
**`key_transfer` method** carrying wrapped keys — not through directly
writable key attributes. [GB] clause 9.2.5.4:

> *"the key shall be first generated by the client, then it shall be
> transferred to the server by invoking the `key_transfer` method of the
> 'Security setup' object … The method invocation parameter shall carry the
> key_id(s) and the wrapped key(s)."*

Whether readable/writable key *attributes* exist at all cannot be settled from
the supplied material.

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — check Blue Book
> DLMS UA 1000-1 Ed. 12 clause 4.4.7 for the authoritative attribute and
> method table of the "Security setup" IC, including its version 0 / version 1
> differences.

The same caveat applies to [SG] §18.4's "Association LN" attribute numbering
(Blue Book clause 4.4.3 / 4.4.4).

---

### E-9 — Terminology drift: "GEK", "Frame Counter", "transport-level security" ⚪ TERMINOLOGY

The guide uses several terms that are not Green Book terminology. They are
common in the field and you will hear them in interviews, so learn both — but
write the specification terms in code and documents.

| Guide / field term | **Green Book term** | Note |
|--------------------|---------------------|------|
| GEK | **GUEK** — global unicast encryption key | [GB] 9.2.5.1. "GEK" is field shorthand. |
| Frame Counter (FC) | **Invocation Counter (IC)** | [GB] 9.2.3.3.7.3. "Frame counter" is a lower-layer concept; using it here invites confusion with HDLC framing. |
| Transport-level security | **Application layer message security** | [GB] 9.2.2.5. DLMS security sits at the *application* layer, above HDLC/wrapper. Calling it transport security misplaces it in the stack. |
| "Session keys" | **Dedicated key** (per-AA) or **ephemeral key** (per-exchange) | [GB] 9.2.5.1 distinguishes these; "session key" collapses them. |
| DEK | **Dedicated key** | [GB] never abbreviates it "DEK". Note DEK ≠ "data encryption key". |

---

### Errata summary

| ID | Severity | Subject | Effect if uncorrected |
|----|----------|---------|-----------------------|
| E-1 | 🔴 Critical | HLS mechanism IDs off by one | Association rejected or wrong mechanism negotiated |
| E-2 | 🔴 Critical | SC byte bit layout | Wrong key set, wrong suite, wrong algorithm |
| E-3 | 🔴 Critical | GMAC plaintext vs AAD | Tag never verifies; HLS always fails |
| E-4 | 🟠 Major | SHA-256 mechanism formula | HLS mechanism 6 always fails |
| E-5 | 🟠 Major | 0xC8 / 0xC9 tag identity | Misparsed captures, wrong dispatch in firmware |
| E-6 | 🟡 Moderate | Missing service-specific tags | Parser rejects valid traffic |
| E-7 | 🟡 Moderate | Blue/Green Book IEC numbers | Citing the wrong standard |
| E-8 | ⚪ Gap | Security setup IC attributes | Unverifiable from supplied material |
| E-9 | ⚪ Terminology | Non-specification vocabulary | Miscommunication in design review |

---

## 0.5 Verified test-vector status

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

## 0.6 Final knowledge map

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

## 0.7 How to use this manual

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
loss and counter persistence" and Volume 0 §0.5 (test vectors) are the two
things to check first. A DLMS stack that does not reproduce Table 40 is not
finished, whatever its author says.

---

*End of Volume 0.*
