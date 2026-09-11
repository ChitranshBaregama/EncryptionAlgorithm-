# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 1 — Foundations and Application Association Security**
*Chapters 1–6*

> Read [`00-INDEX.md`](00-INDEX.md) first. It defines the claim labels
> ([SPEC] / [THEORY] / [IMPL] / [VENDOR] / [INFER]) used throughout, and lists
> the official test vectors this manual is verified against.

---

# CHAPTER 1 — CRYPTOGRAPHY FUNDAMENTALS REQUIRED FOR DLMS SECURITY

## 1.1 Why this chapter is short on purpose

You do not need to become a cryptographer to implement DLMS/COSEM security.
You need roughly twenty-eight concepts, and you need them precisely rather
than broadly. Every term below appears later in a specification sentence you
will have to read literally.

The Green Book itself takes this approach — [GB] clause 9.2.3.1 quotes NIST
SP 800-21 for the foundations rather than developing its own theory:

> **[SPEC]** *"Cryptography relies upon two basic components: an algorithm (or
> cryptographic methodology) and a key. The algorithm is a mathematical
> function, and the key is a parameter used in the transformation."*
> — [GB] 9.2.3.1

That sentence is worth pausing on. **The algorithm is public. The key is the
secret.** Everything in DLMS security follows from that split. AES is
published, GCM is published, the Green Book is purchasable — and none of that
helps an attacker who does not have your GUEK.

---

## 1.2 The three basic algorithm types

[GB] 9.2.3.1 divides all cryptography DLMS uses into exactly three families.
Memorise this taxonomy; the Green Book's whole structure follows it.

```
┌──────────────────────────────────────────────────────────────┐
│  1. HASH FUNCTIONS — no key                                  │
│     One-way compression of a message to a fixed-size digest  │
│     DLMS: SHA-256 (suite 1), SHA-384 (suite 2)               │
│     Used by: HLS mech 6, ECDSA, the key derivation function  │
├──────────────────────────────────────────────────────────────┤
│  2. SYMMETRIC KEY — one key, shared                          │
│     Same key applies and removes the protection              │
│     Fast, small, hardware-accelerable                        │
│     DLMS: AES-128/256 in GCM mode; AES key wrap              │
│     Used by: all message protection, HLS mech 5              │
├──────────────────────────────────────────────────────────────┤
│  3. ASYMMETRIC / PUBLIC KEY — a key PAIR                     │
│     Private key applies, public key checks (or vice versa)   │
│     Slow, large, but solves key distribution                 │
│     DLMS: ECC — ECDSA (signature), ECDH (key agreement)      │
│     Used by: HLS mech 7, general-signing, key agreement      │
└──────────────────────────────────────────────────────────────┘
```

**[SPEC]** A critical constraint appears in [GB] 9.2.3.4.1 NOTE 2:

> *"Asymmetric key algorithms are not used for encryption in DLMS/COSEM."*

Read that twice. In DLMS/COSEM, **public key cryptography never encrypts
data**. It signs, it authenticates, and it agrees on symmetric keys. The
actual bulk protection of every APDU is always AES-GCM. This single fact
prevents the most common conceptual error engineers bring in from TLS.

---

## 1.3 The vocabulary, with a one-line example each

I have grouped these by what they do rather than alphabetically, because that
is how they connect.

### Group A — The basic transformation

| Term | Definition | Tiny example |
|------|------------|--------------|
| **Plaintext** | Data before protection. In DLMS, denoted `P`. | The bytes `C0 01 00 00 08 00 00 01 00 00 FF 02 00` — a GET request for the Clock's time attribute. |
| **Ciphertext** | Data after encryption. Denoted `C`. | Those same bytes become `41 13 12 FF 93 5A 47 56 68 27 C4 67 BC` — same length, no visible structure. |
| **Encryption** | Plaintext + key → ciphertext. | Feed the GET request and the GUEK into AES-GCM. |
| **Decryption** | Ciphertext + key → plaintext. | The meter runs the inverse and recovers the GET request. |
| **Key** | The secret parameter. | `000102030405060708090A0B0C0D0E0F` — 16 bytes, the Green Book's example GUEK. |
| **Secret** | Any value whose confidentiality carries security weight. | The HLS secret; the LLS password; every private key. |

Note something about the example above: **the ciphertext is exactly the same
length as the plaintext.** That is a property of counter-mode encryption and
it matters for your buffer sizing — see Volume 2 Chapter 7.

### Group B — The four security properties

These four are constantly confused, including in vendor documentation. They
are genuinely different properties and DLMS gives you independent control over
them.

| Property | Question it answers | DLMS mechanism |
|----------|--------------------|----------------|
| **Confidentiality** | Can an eavesdropper *read* it? | AES-GCM encryption (SC bit 5) |
| **Integrity** | Has it been *changed* in transit? | GCM authentication tag (SC bit 4) |
| **Authenticity** | Did it really come from *who it claims*? | GCM tag + shared key, or ECDSA signature |
| **Non-repudiation** | Can the sender later *deny* sending it? | ECDSA only — see below |

**[THEORY]** Integrity and authenticity are bundled together by a MAC: because
only the key holder can produce a valid tag, a valid tag proves both "this was
not modified" and "this came from a key holder". They are *not* bundled by a
plain checksum — [GB] 9.2.3.3.5 is explicit that a CRC can be recomputed by an
adversary and therefore provides no security.

**Non-repudiation is the odd one out.** A shared symmetric key cannot provide
it, because *both* parties can compute any tag — so neither can prove the
other produced it. Only a signature made with a private key that exactly one
party holds gives non-repudiation. This is why [GB] 9.2.3.4.4 introduces
digital signature specifically in those terms:

> **[SPEC]** *"A digital signature is an electronic analogue of a written
> signature that can be used in proving to the recipient or a third party that
> the message was signed by the originator (a property known as
> non-repudiation)."* — [GB] 9.2.3.4.4

**Why a meter cares:** billing disputes. If a utility wants to prove in front
of a regulator that *this* meter produced *this* register reading, a GMAC tag
is not enough — the utility holds the same key and could have forged it. An
ECDSA signature over the data, made with a private key that never leaves the
meter, is.

### Group C — Authentication vs authorization

| Term | Question | DLMS location |
|------|----------|---------------|
| **Authentication** | *Who are you?* | AARQ/AARE, mechanism_name, LLS password or HLS challenge-response |
| **Authorization** | *What may you do?* | Access rights in the "Association SN/LN" object |

These are separate concepts with separate machinery, and Chapter 3 is devoted
to why. For now: **passing HLS does not grant you the right to open the
disconnect relay.**

### Group D — Keyed integrity primitives

| Term | Definition | Example |
|------|------------|---------|
| **Hash** | Unkeyed one-way digest. Anyone can compute it. | `SHA-256("hello")` — and so can the attacker, so a bare hash proves nothing about origin. |
| **MAC** | *Message Authentication Code.* Keyed digest. Only key holders can compute or check it. | The 12-byte GCM tag on a DLMS APDU. |
| **HMAC** | A specific MAC construction built from a hash. | Used in TLS. **[SPEC]** *Not* used in DLMS/COSEM — [GB] 9.2.3.3.5 selects **GMAC**. |
| **Digital signature** | Asymmetric MAC. Private key signs, public key verifies. | ECDSA over a general-signing APDU. |

**A note you will need in review:** [GB] 9.2.3.3.5 says plainly *"For the
purposes of DLMS/COSEM, the GMAC algorithm as specified in 9.2.3.3.7.2 shall
be used."* If you see HMAC in a DLMS design document, someone has imported a
TLS habit. The same confusion turns up around mechanism 6, where the
specification asks for a plain SHA-256 hash and implementers reach for HMAC
out of reflex.

The MAC generation/verification model, from [GB] Figure 69:

```
        GENERATION                        VERIFICATION
             K                                  K
             │                                  │
             ▼                                  ▼
   M1 ──► Generate MAC ──► MAC1        M2 ──► Generate MAC ──► MAC2
             │                                  │
             └──── transmit M1 ‖ MAC1 ──────────┤
                                                ▼
                                          MAC1 =? MAC2
                                       equal → M2 == M1
                                              and sender knew K
```

**[SPEC]** [GB] 9.2.3.3.5 draws the conclusion you must carry into firmware:
*"It is therefore crucial that MAC keys be kept secret."* An attacker with
your authentication key can forge any tag.

### Group E — Freshness and uniqueness

This is the group embedded engineers most often get wrong, and the group with
the most catastrophic failure mode.

| Term | Definition | DLMS realisation |
|------|------------|------------------|
| **Nonce** | *Number used once.* A value that must never repeat under a given key. | The IV. |
| **IV** | *Initialization Vector.* The per-message varying input to the cipher. | **[SPEC]** 12 octets = System Title (8) ‖ Invocation Counter (4). [GB] 9.2.3.3.7.3 |
| **Random number** | Unpredictable value. | The CtoS and StoC challenges. |
| **Entropy** | Genuine unpredictability, measured in bits. | What your MCU's TRNG must actually supply. |
| **Challenge–response** | Prove key knowledge by transforming a fresh random value. | The whole of HLS. |

**[THEORY] The crucial distinction:** a nonce must be *unique*; a challenge
must be *unpredictable*. These are different requirements.

- A counter is a perfectly good nonce (unique) but a terrible challenge
  (predictable — the attacker knows what you will send next).
- A random value is a good challenge but a risky nonce (birthday collisions).

DLMS uses each correctly: a **counter** for the IV's invocation field, and a
**random string** for the challenges. [GB] Table 42 requires CtoS and StoC to
be random strings of 8–64 octets (32–64 for mechanism 7).

**Why nonce uniqueness is existential** — this is developed fully in Volume 2
Chapter 10, but understand the shape now. In counter-mode encryption, the
cipher generates a keystream from (key, IV) and XORs it with the plaintext. If
you ever encrypt two different messages with the same (key, IV):

```
C1 = P1 XOR keystream
C2 = P2 XOR keystream          ← same keystream, because same (K, IV)

C1 XOR C2 = P1 XOR P2          ← the key has completely cancelled out
```

The attacker now has the XOR of two plaintexts, with no key required. For
structured, predictable data like DLMS APDUs — which begin with known tags and
known OBIS codes — recovering both plaintexts from that is routine. Worse, in
GCM specifically, IV reuse also permits recovery of the **authentication
subkey H**, after which the attacker can forge valid tags for arbitrary
messages. It is a total break of both confidentiality and authenticity.

This is the single most dangerous mistake available to you in a DLMS
implementation, and the most common way to make it is resetting the invocation
counter to zero on power-up.

### Group F — Key management vocabulary

| Term | Definition | DLMS realisation |
|------|------------|------------------|
| **Key derivation** | Turning one secret into one or more keys. | **[SPEC]** NIST Concatenation KDF, [GB] 9.2.3.4.6.5 |
| **Key wrapping** | Encrypting a key with another key, *with integrity*. | **[SPEC]** AES key wrap, RFC 3394, [GB] 9.2.3.3.7.7 |
| **KEK** | *Key Encrypting Key.* The key that wraps other keys. | **[SPEC]** In DLMS this **is the master key**. [GB] 9.2.5.1 |
| **Public key** | Freely distributable half of a key pair. | `Q` in `Q = dG` |
| **Private key** | Secret half. Never transmitted, ever. | `d` |
| **Certificate** | A public key bound to an identity, signed by a CA. | X.509 v3, [GB] 9.2.6.4 |

**[SPEC]** [GB] 9.2.3.3.6 draws the distinction that makes key wrap different
from ordinary encryption:

> *"Key wrapping differs from simple encryption in that the wrapping process
> includes an integrity feature. During the unwrapping process, this integrity
> feature detects accidental or intentional modifications to the wrapped
> keying material."*

**Why that matters in firmware [INFER]:** if you wrap a key with plain AES-ECB
and an attacker flips a bit in transit, you install a *corrupted key* and have
no idea. Every subsequent message fails to decrypt, and you have bricked the
meter's communications with no diagnostic. AES key wrap detects the tamper and
lets you reject the transfer cleanly.

### Group G — The two attacks that shape the design

| Attack | Mechanism | DLMS defence |
|--------|-----------|--------------|
| **Replay** | Attacker records a valid message and re-sends it later. | Invocation counter verification; random challenges. |
| **Man-in-the-middle** | Attacker sits between the parties, relaying and modifying. | Mutual authentication (HLS); authenticated encryption; certificates. |

**Replay, concretely.** An attacker on the meter's communication link records
the ciphered ACTION APDU that opens the disconnect relay. They cannot read it
— it is encrypted. They do not need to. They simply transmit the identical
bytes tomorrow. Without replay protection the meter decrypts it successfully
(it is a genuine message with a genuine tag) and opens the relay.

**[SPEC]** The defence is [GB] 9.2.3.3.7.3:

> *"when the authenticated decryption function is used, the value of the IC is
> verified. Verification of the IC fails … if the value being verified is
> smaller than the lowest acceptable value. If the verification is successful
> the lowest acceptable value is set to the value of the IC verified plus 1."*

The replayed message carries yesterday's invocation counter. Today's lowest
acceptable value is higher. Rejected. Note the precise semantics: **strictly
increasing, not merely different** — and the acceptable floor advances on
every success.

**MITM, concretely.** Under LLS, the client sends a password and the meter
says yes. An attacker who relays that exchange has learned the password and
can impersonate the client forever after. Under HLS, both sides must prove
knowledge of a secret against a *fresh random challenge they did not choose*,
so relaying yesterday's exchange proves nothing today. That is why HLS is
four passes and not two.

---

## 1.4 Chapter 1 summary — the ten sentences that matter

1. The algorithm is public; the key is the secret.
2. DLMS uses exactly three algorithm families: hash, symmetric, asymmetric.
3. **[SPEC]** Asymmetric algorithms never encrypt data in DLMS/COSEM.
4. Confidentiality, integrity, authenticity, non-repudiation are four
   different properties.
5. A MAC gives integrity + authenticity; only a signature gives
   non-repudiation.
6. **[SPEC]** DLMS uses GMAC, not HMAC.
7. A nonce must be unique; a challenge must be unpredictable.
8. IV reuse under one key breaks GCM completely — confidentiality *and*
   authenticity.
9. Key wrap is encryption plus integrity, and the KEK is the master key.
10. Replay is defeated by the invocation counter; MITM by mutual
    authentication.

---

# CHAPTER 2 — THE DLMS/COSEM SECURITY ARCHITECTURE

## 2.1 Why DLMS security is not "just encryption"

If someone tells you a meter is secure "because it uses AES", they have
answered one of six questions. The Green Book's security concept, [GB]
9.2.2.1, is built from six distinct mechanisms operating at different points
in the exchange:

```
1. IDENTIFICATION      Who claims to be talking?      (SAPs, System Titles)
2. AUTHENTICATION      Can they prove it?             (LLS / HLS)
3. SECURITY CONTEXT    Which algorithms and keys?     (suite + policy + material)
4. ACCESS RIGHTS       What may this partner do?      (Association LN/SN)
5. MESSAGE SECURITY    Protect the APDU               (AES-GCM / ECDSA)
6. DATA SECURITY       Protect the data inside        ("Data protection" objects)
```

"Encryption" is a fraction of item 5. A meter can be fully encrypted and still
be trivially compromised — if it accepts any password, if it never checks the
invocation counter, or if every client is authorised to operate the relay.

**[SPEC]** [GB] 9.2.2.2.2.1 makes the independence explicit, and this is one
of the most important sentences in the entire clause:

> *"The security of the message exchange (in Phase 2) is independent of the
> client-server authentication during AA establishment (Phase 1). Even in the
> case where no client-server authentication takes place, cryptographically
> protected APDUs can be used to ensure message security."*

So: **authentication and message security are orthogonal axes.** You can have
either, both, or neither. Concretely, all four combinations are legal:

| Authentication | Message security | Real deployment |
|----------------|------------------|-----------------|
| None | None | Optical-port meter readout of non-sensitive registers |
| None | AES-GCM | A push/DataNotification link where the meter only transmits |
| HLS | None | Legacy install where keys were never provisioned |
| HLS | AES-GCM | **The correct target for any modern deployment** |

---

## 2.2 Where security sits in the stack

This is the diagram to internalise. The critical insight is *where the
security boundary falls* relative to the communication profile.

```
 ┌───────────────────────────────────────────────────────────────┐
 │                    CLIENT (Head-End System)                    │
 └───────────────────────────────────────────────────────────────┘
                              │
        ══════════════ APPLICATION PROCESS ══════════════
                              │
   ┌──────────────────────────▼──────────────────────────────┐
   │   COSEM APPLICATION LAYER (AL)                          │
   │                                                         │
   │   ┌───────────────┐         ┌────────────────────────┐  │
   │   │     ACSE      │         │      xDLMS ASE         │  │
   │   │  AARQ / AARE  │         │  GET/SET/ACTION/ACCESS │  │
   │   │  RLRQ / RLRE  │         │  DataNotification      │  │
   │   └───────┬───────┘         └───────────┬────────────┘  │
   │           │                             │               │
   │    Identification              ┌────────▼────────┐      │
   │    Authentication              │  SECURITY LAYER │      │
   │    (LLS / HLS)                 │                 │      │
   │           │                    │ Security Context│      │
   │           │                    │  · suite        │      │
   │           │                    │  · policy       │      │
   │           │                    │  · material     │      │
   │           │                    │                 │      │
   │           │                    │ Access Rights   │      │
   │           │                    │        │        │      │
   │           │                    │        ▼        │      │
   │           │                    │  AES-GCM        │      │
   │           │                    │  GMAC           │      │
   │           │                    │  AES key wrap   │      │
   │           │                    │  ECDSA / ECDH   │      │
   │           │                    └────────┬────────┘      │
   │           │                             │               │
   │           │                    ┌────────▼────────┐      │
   │           │                    │  CIPHERED APDU  │      │
   │           │                    └────────┬────────┘      │
   │           └─────────────┬───────────────┘               │
   └─────────────────────────┼───────────────────────────────┘
                             │
   ╔═════════════════════════▼═══════════════════════════════╗
   ║          ↑↑↑  SECURITY BOUNDARY IS ABOVE HERE  ↑↑↑      ║
   ╚═════════════════════════╤═══════════════════════════════╝
                             │
   ┌─────────────────────────▼───────────────────────────────┐
   │              COMMUNICATION PROFILE  (any of):           │
   │                                                         │
   │   HDLC profile      │  TCP/UDP profile  │  S-FSK PLC    │
   │   ┌──────────┐      │  ┌─────────────┐  │  ┌─────────┐  │
   │   │   LLC    │      │  │  Wrapper    │  │  │  ...    │  │
   │   ├──────────┤      │  │  (WPDU)     │  │  └─────────┘  │
   │   │  HDLC    │      │  ├─────────────┤  │               │
   │   │ (framing,│      │  │  TCP / UDP  │  │               │
   │   │  FCS)    │      │  ├─────────────┤  │               │
   │   ├──────────┤      │  │     IP      │  │               │
   │   │ Physical │      │  ├─────────────┤  │               │
   │   └──────────┘      │  │  Physical   │  │               │
   │                     │  └─────────────┘  │               │
   └─────────────────────────┬───────────────────────────────┘
                             │
 ┌───────────────────────────▼───────────────────────────────┐
 │                       SERVER (Meter)                       │
 └───────────────────────────────────────────────────────────┘
```

**[SPEC]** The architectural payoff, [GB] 9.2.2.1:

> *"As these security mechanisms are applied on the application process /
> application layer level, they can be used in all DLMS/COSEM communication
> profiles."*
>
> *"NOTE Lower layers may provide additional security."*

### What this means in practice — four consequences

**Consequence 1 — Security is profile-independent.** The identical ciphered
APDU travels over an optical port, an RS-485 bus, a GPRS link, or a mesh RF
network. Your security module has no idea which. **[IMPL]** This is a gift:
architect your firmware so the crypto layer sees only `(apdu_buffer, length)`
and never touches transport state.

**Consequence 2 — HDLC's FCS is not security.** The HDLC frame check sequence
is a CRC. **[THEORY]** A CRC is a linear function; an attacker who modifies
the payload can recompute a valid FCS trivially. It detects line noise, not
adversaries. [GB] 9.2.3.3.5 says this outright: *"these codes can be altered
by an adversary to the adversary's benefit."*

**Consequence 3 — The addresses are outside the protection.** HDLC source and
destination addresses, and wrapper `wPort` values, sit *below* the boundary.
They are neither encrypted nor authenticated by DLMS. An attacker can read and
alter them. **[INFER]** Never make a security decision based on an HDLC
address; the SAP tells you which *association* is claimed, and the
authentication and the invocation counter tell you whether to believe it.

**Consequence 4 — Lower-layer security composes but does not substitute.** A
TLS or IPsec tunnel around the TCP profile protects the link between the
head-end and the concentrator. It does not protect the segment from
concentrator to meter, and it does not give you end-to-end authenticity from
the meter. DLMS application-layer security is the only thing that reaches all
the way to the metering firmware.

---

## 2.3 The security context

**[SPEC]** [GB] 9.2.2.3 defines the security context as three elements:

```
                    ┌─────────────────────────────┐
                    │      SECURITY CONTEXT       │
                    └──────────────┬──────────────┘
                                   │
        ┌──────────────────┬───────┴────────┬──────────────────┐
        ▼                  ▼                                   ▼
┌───────────────┐  ┌────────────────┐            ┌─────────────────────┐
│ SECURITY      │  │ SECURITY       │            │ SECURITY MATERIAL   │
│ SUITE         │  │ POLICY         │            │                     │
│               │  │                │            │ · keys (GUEK, GBEK, │
│ Which         │  │ What protection│            │   GAK, KEK,         │
│ algorithms    │  │ is REQUIRED on │            │   dedicated)        │
│ and key sizes │  │ every APDU in  │            │ · initialization    │
│ are available │  │ this AA        │            │   vectors           │
│               │  │                │            │ · public key        │
│ 0, 1, or 2    │  │ bitmap, Tbl 34 │            │   certificates      │
└───────────────┘  └────────────────┘            └─────────────────────┘
```

> **[SPEC]** *"The security context is managed by 'Security setup' objects."*
> — [GB] 9.2.2.3, referring to DLMS UA 1000-1 Ed. 12:2014 4.4.7

**[IMPL]** In firmware, model this as a single struct instantiated per
association, because that is exactly its scope:

```c
typedef struct {
    uint8_t  suite_id;             /* 0, 1, or 2                        */
    uint8_t  security_policy;      /* bitmap per [GB] Table 34          */

    uint8_t  server_system_title[8];
    uint8_t  client_system_title[8];

    /* Invocation counters — SEPARATE for TX and RX. [GB] 9.2.3.3.7.3   */
    uint32_t ic_tx;                /* our next outgoing IC              */
    uint32_t ic_rx_floor;          /* lowest acceptable incoming IC     */

    /* Key handles, NOT key bytes — see Volume 5 on secure storage      */
    key_handle_t guek;             /* global unicast encryption key     */
    key_handle_t gbek;             /* global broadcast encryption key   */
    key_handle_t gak;              /* global authentication key         */
    key_handle_t kek;              /* master key / key encrypting key   */

    /* Dedicated key: lifetime == lifetime of this AA only              */
    bool         dedicated_present;
    key_handle_t dedicated_key;
} dlms_security_context_t;
```

Two design points that follow directly from the specification:

**Separate TX and RX counters.** [GB] 9.2.3.3.7.3: *"For each encryption key
EK … an invocation counter (IC) is maintained separately for the authenticated
encryption and the authenticated decryption function."* A single shared
counter is a specification violation and will fail interoperability testing.

**Key handles, not key bytes.** If `guek` is a `uint8_t[16]` in RAM, then a
buffer-overflow bug anywhere in your stack can leak it, and a firmware dump
recovers it. Volume 5 develops this; for now, note that the struct is designed
so the keys need never be in application-accessible RAM.

---

## 2.4 The end-to-end architecture, layered view

Bringing Chapters 1 and 2 together — the vertical stack the prompt asked for,
annotated with what each layer contributes:

```
   CLIENT (HES / concentrator / handheld)
        │
        │  ① IDENTIFICATION
        │     Client SAP, Server SAP  → which logical device?
        │     System Titles           → which physical device?
        │     Client user ID          → which operator? [GB] 4.3.6
        ▼
   APPLICATION ASSOCIATION  (ACSE: AARQ / AARE)
        │
        │  ② AUTHENTICATION
        │     mechanism_name OID 2.16.756.5.8.2.x
        │     · id 0  → none
        │     · id 1  → LLS  (password, one-way)
        │     · id 2  → HLS manufacturer-specific
        │     · id 3  → HLS MD5      (deprecated)
        │     · id 4  → HLS SHA-1    (deprecated)
        │     · id 5  → HLS GMAC
        │     · id 6  → HLS SHA-256
        │     · id 7  → HLS ECDSA
        ▼
   SECURITY CONTEXT  ("Security setup" object)
        │     suite (0/1/2) + policy + key material
        ▼
   SECURITY POLICY  ([GB] Table 34)
        │     the MINIMUM protection every APDU in this AA must carry
        ▼
   ACCESS RIGHTS  ("Association LN/SN" object, [GB] Table 35)
        │     per attribute / per method, and MAY demand MORE protection
        │
        │  ┌──────────────────────────────────────────────────┐
        │  │ [SPEC] "The protection to be applied shall meet   │
        │  │  the stronger of the requirement stipulated by    │
        │  │  the security policy and the access rights."      │
        │  │                              — [GB] 9.2.2.4       │
        │  └──────────────────────────────────────────────────┘
        ▼
   MESSAGE SECURITY  ([GB] 9.2.7.2)
        │     build APDU  →  apply protection  →  ciphered APDU
        ▼
   CRYPTOGRAPHIC PRIMITIVES
        │     AES-GCM (encrypt + authenticate)
        │     GMAC     (authenticate only)
        │     AES-WRAP (protect keys in transit)
        │     ECDSA    (sign)
        │     ECDH     (agree keys)
        ▼
   CIPHERED APDU
        │     tag ‖ [system-title] ‖ length ‖ SC ‖ IC ‖ ciphertext ‖ tag
        ▼
   COMMUNICATION PROFILE
        │     HDLC  |  Wrapper + TCP/UDP  |  S-FSK PLC  |  M-Bus  | ...
        ▼
   SERVER (Meter)
```

---

# CHAPTER 3 — THE THREE SECURITY CONCEPTS

## 3.1 Why the separation exists

**Authentication** answers *who are you*.
**Authorization / access rights** answers *what may you do*.
**Message security** answers *can anyone read or modify this*.

These are three independent axes. Collapsing any two of them is the single
most common architectural error in metering deployments [INFER], and DLMS is
carefully built so that you *cannot* accidentally collapse them: they live in
different objects, are configured by different attributes, and are enforced at
different moments.

```
     ┌─────────────────────────────────────────────────────────┐
     │  AUTHENTICATION  —  WHO?                                │
     │  When: once, at AA establishment (Phase 1)              │
     │  Where: AARQ / AARE + reply_to_HLS_authentication       │
     │  Configured by: mechanism_name, secret                  │
     │  Object: "Association LN / SN"                          │
     └─────────────────────────────────────────────────────────┘
                                │  independent
     ┌─────────────────────────────────────────────────────────┐
     │  ACCESS RIGHTS  —  WHAT?                                │
     │  When: on every single service invocation               │
     │  Where: server-side check before executing GET/SET/ACTION│
     │  Configured by: access_mode / method_access per object  │
     │  Object: "Association LN / SN"                          │
     └─────────────────────────────────────────────────────────┘
                                │  independent
     ┌─────────────────────────────────────────────────────────┐
     │  MESSAGE SECURITY  —  READ / MODIFY?                    │
     │  When: on every single APDU, both directions            │
     │  Where: AES-GCM / ECDSA over the APDU                   │
     │  Configured by: security_policy + security_suite + keys │
     │  Object: "Security setup"                               │
     └─────────────────────────────────────────────────────────┘
```

---

## 3.2 The four instructive combinations

### Case A — Authentication without encryption

**Configuration:** HLS mechanism 5 (GMAC), security_policy = 0.

**What happens:** the client proves it knows the shared secret. The
association establishes. Then every GET response travels in **cleartext**.

**What an attacker gets:** everything. The load profile, the tariff registers,
the firmware version, the customer's consumption pattern. They cannot *inject*
commands (they never authenticated), but they can read the entire meter by
passive listening.

**Where you see this [VENDOR]:** older deployments where authentication was
mandated by a tender document but message security was left at defaults.
Extremely common in the field.

### Case B — Encryption without sufficient authentication

**Configuration:** security_policy demands *encrypted* request (bit 3) but not
*authenticated* request (bit 2). SC = `0x20`.

**What happens:** every APDU is encrypted with AES-GCM in encryption-only
mode. **[SPEC]** [GB] 9.2.3.3.7.1: *"In DLMS/COSEM, it is also possible to use
GCM to provide confidentiality only: in this case, the authentication tags are
simply not computed and checked."*

**Why this is dangerous [THEORY]:** encryption-only counter mode is
**malleable**. The ciphertext is `P XOR keystream`. An attacker who flips bit
*n* of the ciphertext flips bit *n* of the decrypted plaintext — without
knowing the key, without breaking the encryption, and with no detection
because there is no tag to check.

Concretely: an attacker who knows the layout of a SET request writing a tariff
threshold can flip the high bit of the value field. The meter decrypts to a
different number and applies it. Confidentiality held; integrity was never
there.

**[IMPL] Rule: never deploy SC = `0x20`.** Encryption-only exists in the
specification for completeness. Authenticated encryption (`0x30`) costs
essentially nothing extra — GCM computes the tag as part of the same pass —
and closes the entire malleability class.

### Case C — Authentication, integrity, and encryption all present

**Configuration:** HLS mechanism 5, security_policy = authenticated +
encrypted on both request and response. SC = `0x30`.

This is the target. Chapter 4 of Volume 2 walks the exact bytes.

### Case D — Access rights blocking an authenticated client

**Configuration:** the client passes HLS perfectly. It then sends an ACTION on
the Disconnect Control object to open the relay.

**What happens:** the server checks the `method_access` field for that method
in *this* association's access-rights list, finds `no_access`, and rejects the
service — with a service error, not an authentication error.

**Why this is the most important case:** it is the one that separates a
security design from a security feature. A meter reading contractor's handheld
and the utility's disconnection system may both authenticate with HLS, on
different associations, with different client SAPs, and completely different
authorisation.

**[SPEC]** [GB] Table 35 shows access rights are far richer than
read/write. The `access_mode` enum, interpreted as an unsigned8:

| Bit | Attribute access | Method access |
|-----|------------------|---------------|
| 0 | read-access | access |
| 1 | write-access | *(not used)* |
| 2 | authenticated request | authenticated request |
| 3 | encrypted request | encrypted request |
| 4 | digitally signed request | digitally signed request |
| 5 | authenticated response | authenticated response |
| 6 | encrypted response | encrypted response |
| 7 | digitally signed response | digitally signed response |

So a single attribute can be configured as *"readable, but only via a request
that is authenticated, encrypted and digitally signed, and the response must
be likewise"* — that is `enum(255)` in [GB]'s own example.

**[SPEC]** And the composition rule, [GB] 9.2.7.2.2:

> *"APDUs with more protection than required by the security policy are always
> allowed. APDUs with less protection than required by the security policy and
> the access rights shall be rejected."*

```
      required_protection = MAX( security_policy , access_rights )

      if (applied_protection ⊇ required_protection)  →  process
      else                                            →  reject
```

**[IMPL]** Implement this as a bitmask superset test, not equality. Equality
testing is a classic bug: it rejects a client that legitimately over-protects.

---

## 3.3 Threat → mechanism → operation → result

The prompt asked for this framing (Rule 17) and it is genuinely how to think
about design review. For each of the three concepts:

| Threat | Security mechanism | Cryptographic operation | Result |
|--------|--------------------|-----------------------|--------|
| Impersonation of the head-end | HLS mutual authentication | GMAC over SC‖AK‖challenge, both directions | Only a holder of the shared key can establish an AA |
| Unauthorised relay operation by a legitimate but low-privilege client | Access rights on the method | *(no crypto — a policy check)* | The service is rejected even though authentication succeeded |
| Passive interception of consumption data | Message security, E bit set | AES-GCM CTR-mode encryption under GUEK | Ciphertext reveals nothing but length |
| Tampering with a SET value in flight | Message security, A bit set | GHASH over AAD ‖ ciphertext, 96-bit tag | Any modification fails tag verification; APDU discarded |
| Replaying a captured disconnect command | Invocation counter verification | IC compared against the RX floor | Stale IC rejected before decryption completes |

Notice that the second row has **no cryptographic operation at all**. Access
rights are a pure policy decision. That is precisely why they must be a
separate concept: no amount of cryptography answers "should this client be
allowed to do this".

---

# CHAPTER 4 — APPLICATION ASSOCIATION SECURITY

## 4.1 What an Application Association is

**[SPEC]** [GB] 9.2.2.1: *"The resources of DLMS/COSEM servers — COSEM object
attributes and methods — can be accessed by DLMS/COSEM clients within
Application Associations."*

An AA is the *context* within which every subsequent service invocation is
interpreted. It is not a connection in the TCP sense; it is a negotiated
agreement on:

| Element | Meaning |
|---------|---------|
| **Application context** | LN or SN referencing; ciphered or unciphered |
| **Authentication mechanism** | Which of the eight mechanisms |
| **xDLMS context** | Conformance block, max PDU sizes, dedicated key |
| **Access rights** | What this partner may do |
| **Security context** | Suite, policy, key material |

**[SPEC]** Critically, [GB] Figure 64 shows these are **pre-configured in the
server**, not invented at runtime:

> *"Application Associations (AAs) pre-configured in Server: Application
> context, Authentication mechanism, xDLMS context, Access rights, Security
> context"*

The client *proposes*; the server *checks the proposal against a
pre-configured association and applies the negotiated contexts*. A meter with
three configured associations (public/reader/management) will accept exactly
those three shapes and nothing else. This is a whitelist model, and it is a
significant part of why DLMS meters are harder to attack than they might be.

---

## 4.2 Naming and addressing — who is who

**[SPEC]** [GB] 9.2.2.2.1: *"DLMS/COSEM AEs are bound to Service Access Points
(SAPs) in the protocol layer supporting the AL. These SAPs are present in the
PDUs carrying the xDLMS APDUs within an AA."*

Four identity concepts, frequently muddled:

| Concept | Size / form | Where it lives | What it identifies |
|---------|-------------|----------------|--------------------|
| **Client SAP** | Address in the lower-layer PDU | HDLC / wrapper header | The client application entity |
| **Server SAP** | Address in the lower-layer PDU | HDLC / wrapper header | The logical device inside the meter |
| **System Title** | **[SPEC]** 8 octets, [GB] 4.3.4 | AARQ/AARE, or the ciphered APDU | The physical device, cryptographically |
| **Client user ID** | Per [GB] 4.3.6 | AARQ | Which *operator* on the client side |

**Two things to be precise about:**

*The SAP is not a security identity.* It rides in the HDLC header, below the
security boundary, and is unauthenticated. It routes; it does not prove.

*The System Title is a security identity.* **[SPEC]** [GB] 4.3.4: *"The system
title Sys-T shall uniquely identify each DLMS/COSEM entity"* — 8 octets, the
leading 3 being the FLAG manufacturer ID, the remaining 5 ensuring uniqueness.
It becomes the fixed field of the IV, and therefore it *is* cryptographically
bound to every message that device sends. Chapter 11 of Volume 2 covers it in
depth.

**The client user ID** exists for a reason worth noting: **[SPEC]** [GB]
9.2.2.2.1 — *"The client user identification mechanism enables the server to
distinguish between different users on the client side and to log their
activities accessing the meter."* One HES, many operators, one audit trail.

---

## 4.3 The three-phase association lifecycle

**[SPEC]** [GB] Figure 64 defines three phases:

```
╔══════════════════════════════════════════════════════════════════╗
║  PHASE 1 — AA ESTABLISHMENT                                      ║
║                                                                  ║
║   COSEM-OPEN.request   ──── carried by AARQ ────►                ║
║   COSEM-OPEN.response  ◄─── carried by AARE ─────                ║
║   (+ for HLS: two more passes via                                ║
║    reply_to_HLS_authentication)                                  ║
╠══════════════════════════════════════════════════════════════════╣
║  PHASE 2 — MESSAGE EXCHANGE                                      ║
║                                                                  ║
║   Unprotected or protected DLMS service request(s)   ────►       ║
║   Unprotected or protected DLMS service response(s)  ◄────       ║
╠══════════════════════════════════════════════════════════════════╣
║  PHASE 3 — AA RELEASE                                            ║
║                                                                  ║
║   COSEM-RELEASE.request   ──── carried by RLRQ ────►             ║
║   COSEM-RELEASE.response  ◄─── carried by RLRE ─────             ║
╚══════════════════════════════════════════════════════════════════╝
```

**[SPEC]** Two notes from [GB] Figure 64 that engineers routinely miss:

> *"NOTE 3 In pre-established AAs no authentication takes place."*

A pre-established AA skips Phase 1 entirely. There is no AARQ. Security relies
wholly on message protection and access rights. **[INFER]** If your deployment
uses pre-established AAs, the security policy is not optional — it is your only
defence.

> *"NOTE 4 The COSEM-RELEASE service can be cryptographically protected by
> including a ciphered xDLMS InitiateRequest / InitiateResponse APDU in the
> RLRQ."*

Release can be protected. Otherwise an attacker can inject an RLRQ and tear
down a legitimate session — a cheap denial of service.

---

## 4.4 The AARQ APDU — field by field

**[SPEC]** [GB] 9.5, `AARQ ::= [APPLICATION 0] IMPLICIT SEQUENCE`, i.e. tag
`0x60`. The security-relevant fields:

| Field | Tag | Security relevance |
|-------|-----|--------------------|
| `protocol-version` | `[0]` | Default version1. Not security-relevant. |
| `application-context-name` | `[1]` | **Critical.** OID `2.16.756.5.8.1.x` — determines whether ciphered APDUs are permitted at all. |
| `called-AP-title` | `[2]` | Optional. |
| `calling-AP-title` | `[6]` | **Carries the client System Title** for HLS mech 6/7 and for ciphering. |
| `calling-AE-qualifier` | `[7]` | **Carries the client's signature certificate** (`Cert-Sign-Client`) for HLS mech 7. |
| `sender-acse-requirements` | `[10]` | `BIT STRING { authentication (0) }`. Bit set ⇒ authentication functional unit selected. |
| `mechanism-name` | `[11]` | **Critical.** OID `2.16.756.5.8.2.x` — selects the authentication mechanism. |
| `calling-authentication-value` | `[12]` | **Critical.** LLS password, or the HLS `CtoS` challenge. |
| `user-information` | `[30]` | Carries the xDLMS `InitiateRequest`, which carries the **dedicated key** if used. |

### 4.4.1 The application context name — the ciphering gate

**[SPEC]** [GB] Table 74:

```
COSEM_Application_Context_Name ::=
  { joint-iso-ccitt(2) country(16) country-name(756)
    identified-organisation(5) DLMS-UA(8) application-context(1)
    context_id(x) }
```

| context_id | Name | Unciphered APDUs | Ciphered APDUs |
|-----------|------|------------------|----------------|
| 1 | `Logical_Name_Referencing_No_Ciphering` | Yes | **No** |
| 2 | `Short_Name_Referencing_No_Ciphering` | Yes | **No** |
| 3 | `Logical_Name_Referencing_With_Ciphering` | Yes | **Yes** |
| 4 | `Short_Name_Referencing_With_Ciphering` | Yes | **Yes** |

**[SPEC]** [GB] 9.2.7.2.3 states the rule precisely:

> *"Ciphered xDLMS APDUs can be used in a ciphered application context only.
> On the other hand, in a ciphered application context, both ciphered and
> unciphered APDUs may be used."*

**[IMPL] Two consequences for your firmware:**

1. If `context_id` is 1 or 2 and a ciphered APDU arrives, **reject it**. This
   is a mandatory check, and it is easy to forget because the ciphered APDU
   parses fine.
2. If `context_id` is 3 or 4, unciphered APDUs are still *syntactically*
   permitted — so the gate that actually forces protection is the **security
   policy**, not the context name. A meter configured with context 3 and
   `security_policy = 0` accepts plaintext GETs all day.

**[INFER]** That combination — ciphered context, zero policy — is, in my
judgement, the most common real-world misconfiguration in DLMS deployments. It
looks secure in a configuration screen ("ciphering: enabled") and is not.

Encoded on the wire, context 3 appears as:

```
A1 09 06 07 60 85 74 05 08 01 03
│  │  │  │  └──────────────────┴─ OID value 2.16.756.5.8.1.3
│  │  │  └─ OID length = 7
│  │  └─ BER tag: OBJECT IDENTIFIER
│  └─ length = 9
└─ context tag [1]
```

Note `60` = the first two arcs 2·40 + 16 = 96 = `0x60`, then `85 74` = 756
encoded in base-128, then `05 08 01 03`.

### 4.4.2 The mechanism name

**[SPEC]** [GB] Table 75. Take the numbering from the table itself — it is
very commonly quoted shifted by one:

```
COSEM_Authentication_Mechanism_Name ::=
  { joint-iso-ccitt(2) country(16) country-name(756)
    identified-organization(5) DLMS-UA(8)
    authentication_mechanism_name(2) mechanism_id(x) }
```

| mechanism_id | Name | Notes |
|--------------|------|-------|
| 0 | lowest level security | No authentication |
| 1 | low level security (LLS) | Password |
| 2 | high level security | **[SPEC]** *"the method of processing the challenge is secret"* — manufacturer-specific |
| 3 | HLS using MD5 | **[SPEC]** *"not recommended for new implementations"* |
| 4 | HLS using SHA-1 | **[SPEC]** *"not recommended for new implementations"* |
| 5 | HLS using GMAC | |
| 6 | HLS using SHA-256 | |
| 7 | HLS using ECDSA | |

On the wire, mechanism 5:

```
8B 07 60 85 74 05 08 02 05
│  │  └──────────────────┴─ OID 2.16.756.5.8.2.5
│  └─ length = 7
└─ context tag [11], primitive
```

**[SPEC]** And a coupling rule from [GB] 9.4.2.2.3: *"When the
Authentication_Mechanism_Name is present in the COSEM-OPEN service, the
authentication functional unit of the A-ASSOCIATE service shall be selected."*
That is, `sender-acse-requirements` bit 0 must be set. A mechanism-name
without the ACSE requirements bit is malformed.

### 4.4.3 The dedicated key rides in the InitiateRequest

**[SPEC]** [GB] 9.2.5.1 — this is a subtle and important detail:

> *"Dedicated keys are generated by the DLMS/COSEM client and transported to
> the server in the dedicated-key field of the xDLMS InitiateRequest APDU,
> carried by the user-information field of the AARQ APDU. When the dedicated
> key is present, the xDLMS InitiateRequest APDU shall be authenticated and
> encrypted using the AES-GCM-128 / 256 algorithm, the global unicast
> encryption key and — if in use — the authentication key."*
>
> *"NOTE The AARQ and the AARE APDUs themselves are not protected."*

Read that NOTE carefully, because it defines the security boundary during
association setup:

```
   AARQ  (tag 0x60)                          ← NOT protected
   ├── application-context-name               ← visible
   ├── mechanism-name                         ← visible
   ├── calling-AP-title (System Title)        ← visible
   ├── calling-authentication-value (CtoS)    ← visible
   └── user-information [30]
       └── glo-initiateRequest (tag 0x21)     ← PROTECTED with GUEK
           └── SC ‖ IC ‖ ciphertext ‖ tag
               └── InitiateRequest
                   └── dedicated-key          ← confidential
```

So the dedicated key is protected by the *global* key inside an otherwise
plaintext AARQ. And **[SPEC]** *"When the dedicated key is used, the key-set
bit of the security control byte … is not relevant and shall be set to zero."*

**[IMPL]** This creates a genuine ordering constraint in firmware: you must be
able to decrypt an embedded `glo-initiateRequest` *before* the association is
established, using the global key associated with the proposed association.
Implementations that only wire up the crypto path after association
establishment fail here. Design the security context to be resolvable from
(server SAP, client SAP) at AARQ-parse time.

---

## 4.5 The AARE and the negotiated result

The AARE (`[APPLICATION 1]`, tag `0x61`) mirrors the AARQ, with:

| Field | Purpose |
|-------|---------|
| `responding-AP-title` | **Server System Title** (needed for HLS mech 6/7, and for the client to build the RX IV) |
| `responding-AE-qualifier` | **Server signature certificate** (`Cert-Sign-Server`) for HLS mech 7 |
| `responding-authentication-value` | The **StoC** challenge |
| `result` | accepted / rejected(permanent) / rejected(transient) |
| `result-source-diagnostic` | Result source (ACSE service-user vs service-provider) + diagnostic |

**The HLS-specific result value.** For HLS, the server returns `result =
accepted` together with a diagnostic indicating authentication is still
required. **[SPEC]** [GB] 9.2.2.2.2.4:

> *"After Pass 2 — provided that the proposed application context and xDLMS
> context are acceptable — the AA is formally established, but the access of
> the client is restricted to the method reply_to_HLS_authentication of the
> current 'Association SN / LN' object."*

**[IMPL]** This is a distinct firmware state, and it must be enforced. Model
it explicitly:

```c
typedef enum {
    AA_IDLE = 0,
    AA_PENDING,           /* AARQ received, being validated              */
    AA_HLS_PASS2_SENT,    /* AARE sent with StoC; ONLY                   */
                          /* reply_to_HLS_authentication is permitted    */
    AA_ESTABLISHED,       /* passes 3 and 4 complete                     */
    AA_RELEASING
} aa_state_t;
```

A server that reaches `AA_HLS_PASS2_SENT` and then accepts a GET request has a
**complete authentication bypass**. The client never proved anything — it only
sent a random challenge. This is a real and recurring implementation bug
[INFER], and it is the first thing I would test in a security review: send an
AARQ with HLS, then immediately send a GET without doing pass 3, and see what
comes back.

---

## 4.6 Conceptual packet flow, all mechanisms

```
 CLIENT                                                       METER
   │                                                             │
   │  ══════════ NO SECURITY, mechanism_id(0) ═══════════        │
   │                                                             │
   │──── AARQ  [ctx-name, mech(0)] ────────────────────────────► │
   │◄─── AARE  [ctx-name, result=accepted] ───────────────────── │
   │                                            ASSOCIATION UP   │
   │                                                             │
   │  ══════════ LLS, mechanism_id(1) ═══════════════════        │
   │                                                             │
   │──── AARQ  [mech(1), calling-auth-value = PASSWORD] ───────► │
   │                                          check password     │
   │◄─── AARE  [result = accepted | rejected] ───────────────────│
   │                                            ASSOCIATION UP   │
   │                                     (one-way only)          │
   │                                                             │
   │  ══════════ HLS, mechanism_id(2..7) ════════════════        │
   │                                                             │
   │  Pass 1                                                     │
   │──── AARQ  [mech(5), calling-auth-value = CtoS] ───────────► │
   │           [+ calling-AP-title = Sys-T_C   (mech 6,7)]       │
   │           [+ calling-AE-qualifier = Cert  (mech 7)]         │
   │                                                             │
   │  Pass 2                                    generate StoC    │
   │◄─── AARE  [result=accepted, responding-auth-value = StoC] ──│
   │           [+ responding-AP-title = Sys-T_S (mech 6,7)]      │
   │           [+ responding-AE-qualifier = Cert (mech 7)]       │
   │                                                             │
   │        ┌──────────────────────────────────────────┐         │
   │        │ AA formally established, but the ONLY    │         │
   │        │ permitted service is                     │         │
   │        │ reply_to_HLS_authentication              │         │
   │        └──────────────────────────────────────────┘         │
   │                                                             │
   │  [SPEC] If StoC == CtoS, the client SHALL reject and abort  │
   │                                                             │
   │  Pass 3                                                     │
   │──── ACTION.request ──────────────────────────────────────►  │
   │      Association LN, method 1 = reply_to_HLS_authentication │
   │      parameter = f(StoC)                                    │
   │                                    verify f(StoC)           │
   │                                    → client authenticated   │
   │  Pass 4                                                     │
   │◄─── ACTION.response  [ success, data = f(CtoS) ] ───────────│
   │                                                             │
   │  verify f(CtoS) → server authenticated                      │
   │                                                             │
   │              ═══ ASSOCIATION FULLY ESTABLISHED ═══          │
   │                    (mutual authentication)                  │
   │                                                             │
   │  ══════════ PHASE 2: protected message exchange ════        │
   │                                                             │
   │──── glo-get-request  (0xC8) ──────────────────────────────► │
   │◄─── glo-get-response (0xCC) ────────────────────────────────│
   │                                                             │
   │  ══════════ PHASE 3: release ═══════════════════════        │
   │                                                             │
   │──── RLRQ ─────────────────────────────────────────────────► │
   │◄─── RLRE ───────────────────────────────────────────────────│
```

**[SPEC]** The `StoC != CtoS` check is mandatory, from [GB] 9.2.2.2.2.4:

> *"If StoC is the same as CtoS, the client shall reject it and shall abort the
> AA establishment process."*

**Why [THEORY]:** if the server simply echoes the client's challenge, then in
mechanisms where `f` is symmetric in form, `f(StoC)` and `f(CtoS)` become the
same value. The client computes it in Pass 3 and hands it to the "server",
which can then replay it back in Pass 4 without knowing the secret at all. A
fake server that echoes the challenge authenticates itself using the real
client's own work. One comparison prevents it — and it is frequently omitted
in client implementations [INFER].

---

# CHAPTER 5 — LOW LEVEL SECURITY (LLS)

## 5.1 What LLS is

**[SPEC]** [GB] 9.2.2.2.2.3:

> *"In this case, the server requires that the client authenticates itself by
> supplying a password that is known by the server. The password is held by
> the current 'Association SN / LN' object modelling the AA to be established.
> The 'Association SN / LN' objects provide means to change the secret."*

The complete protocol:

```
 CLIENT                                                    METER
   │                                                         │
   │  ① COSEM-OPEN.request, carrying the password            │
   │──── AARQ ─────────────────────────────────────────────► │
   │      mechanism-name = 2.16.756.5.8.2.1                  │
   │      calling-authentication-value = "12345678"          │
   │                                                         │
   │                                    ② compare against    │
   │                                       stored secret     │
   │                                                         │
   │  ③ COSEM-OPEN.response                                  │
   │◄─── AARE ───────────────────────────────────────────────│
   │      result = accepted  →  AA established               │
   │      result = rejected  →  AA refused                   │
   │                                                         │
```

**[SPEC]** [GB] classifies this precisely, in 9.2.2.2.2.1 NOTE 1:

> *"In ITU-T X.811 this is known as unilateral authentication, class 0
> mechanism."*

"Class 0" is not a compliment. It is the weakest category in the X.811
taxonomy.

---

## 5.2 Byte-level AARQ with LLS

**«EDUCATIONAL / FICTIONAL EXAMPLE»** — the values below are constructed for
teaching. They are not from [GB].

Association: client SAP 16 (management), LLS, password `"ABCDEFGH"`,
unciphered LN referencing.

```
60 1D                                    AARQ, length 0x1D = 29
│  └─ length
└─ [APPLICATION 0] = 0x60

   A1 09                                 [1] application-context-name, len 9
      06 07 60 85 74 05 08 01 01
      │  │  └───────────────────┴─ OID 2.16.756.5.8.1.1
      │  └─ OID length 7            = LN referencing, NO ciphering
      └─ OBJECT IDENTIFIER

   8A 02 07 80                           [10] sender-acse-requirements
   │  │  │  └─ 0x80 = bit 0 set = authentication functional unit
   │  │  └─ 0x07 = 7 unused bits in the final octet
   │  └─ length 2
   └─ context tag [10], primitive, BIT STRING

   8B 07 60 85 74 05 08 02 01            [11] mechanism-name
      │  └───────────────────┴─ OID 2.16.756.5.8.2.1
      └─ length 7                 = mechanism_id(1) = LLS

   AC 0A                                 [12] calling-authentication-value
      80 08 41 42 43 44 45 46 47 48
      │  │  └──────────────────────┴─ "ABCDEFGH" in ASCII
      │  └─ length 8
      └─ [0] CHOICE: charstring
```

### The critical observation

```
   ... 41 42 43 44 45 46 47 48 ...
        A  B  C  D  E  F  G  H
```

**The password is on the wire in cleartext.** Not hashed, not salted, not
challenged. Any passive listener with a serial sniffer or a logic analyser on
the optical port reads it directly.

**[SPEC]** And there is no defence available inside LLS itself, because of
[GB] 9.2.5.1's NOTE: *"The AARQ and the AARE APDUs themselves are not
protected."* You cannot encrypt the AARQ. There is no mechanism to do so.

---

## 5.3 Why LLS is weak — a precise enumeration

| Weakness | Consequence |
|----------|-------------|
| **Cleartext transmission** | One passive capture yields the credential permanently. |
| **One-way only** | The meter never proves itself. A rogue device that answers `AARE result=accepted` is indistinguishable from a real meter. |
| **No freshness** | The same bytes work every time. A replayed AARQ establishes a new association. |
| **No binding to the session** | Nothing links the password to the messages that follow. |
| **Typically short and low-entropy [VENDOR]** | Field practice tends toward 8 ASCII digits — around 26 bits of entropy. Offline guessing is trivial once captured; online guessing is limited only by the meter's lockout policy, if it has one. |
| **Often shared across a fleet [VENDOR]** | Recovering one meter's password may unlock thousands. |

---

## 5.4 The relationship between LLS and message encryption

This is where engineers reason incorrectly, so let me be exact.

**Claim frequently heard:** *"LLS is fine because we encrypt everything
anyway."*

**[SPEC] Why that is wrong in part:** the AARQ carrying the password is *not*
encrypted — it cannot be. Message security begins with the first ciphered
xDLMS APDU, which is *after* the AARQ. So enabling message security does not
protect the LLS password on the wire. The credential is exposed regardless.

**Where the claim has partial merit [INFER]:** message security does limit
what the stolen password buys. An attacker with the password but without the
GUEK/GAK can send an AARQ and get an AARE, but cannot construct a valid
ciphered GET — so under a security policy that mandates authenticated
encryption, the association is useless to them. The password alone is not
sufficient for access.

**The correct conclusion:** LLS + mandatory authenticated encryption is
*survivable*, because the real access control has migrated to key possession.
But then the password is doing almost no work, and you would be better served
by HLS-GMAC, which reuses the keys you already have and adds mutual
authentication for essentially no cost.

**[IMPL] Recommendation.** Use LLS only for a genuinely public, read-only
association exposing non-sensitive data, and treat the password as a nuisance
filter rather than a security control. For anything that touches billing data,
configuration, or the disconnect relay: HLS mechanism 5 minimum.

---

## 5.5 Typical legacy implementation and its failure modes [VENDOR]

**[VENDOR]** Patterns commonly observed in the field. None of these is DLMS
behaviour; all are implementation choices:

- Password stored in plaintext in EEPROM at a fixed, well-known offset.
- Password comparison implemented with `memcmp()` — **[INFER]** timing-variable,
  and on a slow serial link with averaging, potentially observable.
- No failed-attempt counter and no lockout, allowing unbounded online guessing.
- The same password across every meter in a deployment.
- `change_LLS_secret` never exercised after commissioning.

**[IMPL] Firmware fixes, in priority order:**

1. Constant-time comparison. Accumulate the XOR difference across all bytes
   and test once at the end; never return early on the first mismatch.
2. Failed-attempt counter, persisted across reset, with a backoff.
3. Per-device passwords derived from a master secret plus the serial number,
   so that compromise does not scale.
4. Store a salted hash of the password rather than the password, if the
   protocol flow permits it. **[SPEC] Note the constraint:** LLS compares a
   received plaintext password, so hashed-at-rest storage *is* possible — but
   **[SPEC]** the "Association" object also offers `change_LLS_secret`, and
   whether that method requires reading back the current secret is
   implementation-dependent.
   > **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — check Blue
   > Book DLMS UA 1000-1 Ed. 12 clause 4.4.3/4.4.4 for the exact semantics of
   > the `secret` attribute and `change_LLS_secret` / `change_HLS_secret`
   > methods.

---

# CHAPTER 6 — HIGH LEVEL SECURITY (HLS)

## 6.1 The idea: prove knowledge without revealing it

The problem LLS cannot solve: how do you prove you know a secret to someone
who is listening, without the listener learning the secret?

**[THEORY] The answer is challenge–response.** The verifier sends a fresh
random value. The prover applies a keyed one-way function to it and returns
the result. The listener sees a random challenge and a response that is
useless for any *other* challenge — and cannot invert the function to recover
the key.

**[SPEC]** DLMS makes this mutual. [GB] 9.2.2.2.2.4:

> *"In this case, both the client and the server have to successfully
> authenticate themselves to establish an AA. HLS authentication is a
> four-pass process."*
>
> *"NOTE 2 In ITU-T X.811 this is known as mutual authentication using
> challenge mechanisms."*

---

## 6.2 The four passes, precisely

**[SPEC]** [GB] 9.2.2.2.2.4, quoted in full because the details matter:

```
┌────────────────────────────────────────────────────────────────────┐
│ PASS 1  (C → S, carried by AARQ)                                   │
│   "The client transmits a 'challenge' CtoS and — depending on the  │
│    authentication mechanism — additional information to the server" │
├────────────────────────────────────────────────────────────────────┤
│ PASS 2  (S → C, carried by AARE)                                   │
│   "The server transmits a 'challenge' StoC and — depending on the  │
│    authentication mechanism — additional information to the client" │
│                                                                    │
│   "If StoC is the same as CtoS, the client shall reject it and     │
│    shall abort the AA establishment process."                      │
├────────────────────────────────────────────────────────────────────┤
│ PASS 3  (C → S, carried by reply_to_HLS_authentication .request)   │
│   "The client processes StoC and the additional information        │
│    according to the rules of the HLS authentication mechanism      │
│    valid for the given AA and sends the result to the server. The  │
│    server checks if f(StoC) is the result of correct processing    │
│    and — if so — it accepts the authentication of the client"      │
├────────────────────────────────────────────────────────────────────┤
│ PASS 4  (S → C, carried by reply_to_HLS_authentication .response)  │
│   "The server processes then CtoS and the additional information   │
│    … and sends the result to the client. The client checks if      │
│    f(CtoS) is the result of correct processing and — if so — it    │
│    accepts the authentication of the server."                      │
└────────────────────────────────────────────────────────────────────┘
```

**[SPEC]** Which service carries which pass:

> *"Pass 1 and Pass 2 are supported by the COSEM-OPEN service. … Pass 3 and
> Pass 4 are supported by the method reply_to_HLS_authentication of the
> 'Association SN / LN' object(s). If both passes 3 and 4 are successfully
> executed, then the AA is established. Otherwise, either the client or the
> server aborts the AA."*

So passes 3 and 4 are **an ordinary ACTION service invocation and its
response** — which means, importantly, that they can themselves be
cryptographically protected. [GB] Figure 64: *"The messages may be
cryptographically protected."*

---

## 6.3 Why four passes and not two

A two-pass design (challenge, response) authenticates the client to the server
only. That is unilateral, and it leaves a real attack open:

```
   Real client ────► ROGUE METER
                      · answers AARE
                      · says "accepted"
                      · records everything the client sends
```

Under two-pass, the client has no way to detect that the device it is
configuring is not the real meter. With a disconnect-capable client, a rogue
device could harvest command sequences and credentials.

Four passes forces the server to prove key knowledge against a challenge the
*client* chose. The rogue meter cannot produce `f(CtoS)` and is detected at
pass 4.

**[INFER] Note the asymmetry that makes it work.** The two computations are
deliberately *not* the same function of the same inputs:

| | Pass 3 (client proves) | Pass 4 (server proves) |
|--|------------------------|------------------------|
| mech 3 | `MD5(StoC ‖ HLS Secret)` | `MD5(CtoS ‖ HLS Secret)` |
| mech 5 | `GMAC(SC ‖ AK ‖ StoC)` | `GMAC(SC ‖ AK ‖ CtoS)` |
| mech 6 | `SHA-256(Secret ‖ Sys-T_C ‖ Sys-T_S ‖ StoC ‖ CtoS)` | `SHA-256(Secret ‖ Sys-T_S ‖ Sys-T_C ‖ CtoS ‖ StoC)` |
| mech 7 | `ECDSA(Sys-T_C ‖ Sys-T_S ‖ StoC ‖ CtoS)` | `ECDSA(Sys-T_S ‖ Sys-T_C ‖ CtoS ‖ StoC)` |

Each side transforms the *other* side's challenge. And in mechanisms 6 and 7,
the system titles are also swapped, so even the input strings differ
structurally. Neither party's response can be replayed as the other's.

---

## 6.4 All six HLS mechanisms — the comparison table

**[SPEC]** Built from [GB] Table 42 and Table 75. **Two things are commonly
got wrong here: the mechanism numbering, and mechanism 6's formula.**

| Mechanism | Primitive | Key / Secret | Pass 3 input `f(StoC)` | Output | Mutual? | Security | DLMS usage |
|-----------|-----------|--------------|------------------------|--------|---------|----------|------------|
| **id(2)** HLS manufacturer-specific | Undisclosed | Manufacturer-defined | Manufacturer-defined | Manufacturer-defined | Yes | **[SPEC]** *"the method of processing the challenge is secret"* | **[VENDOR]** Legacy; security by obscurity. Avoid. |
| **id(3)** HLS MD5 | MD5 hash | HLS secret | `MD5(StoC ‖ HLS Secret)` | 16 octets | Yes | **Broken.** MD5 collisions are practical. | **[SPEC]** *"not recommended for new implementations"* |
| **id(4)** HLS SHA-1 | SHA-1 hash | HLS secret | `SHA-1(StoC ‖ HLS Secret)` | 20 octets | Yes | **Deprecated.** SHA-1 collisions demonstrated. | **[SPEC]** *"not recommended for new implementations"* |
| **id(5)** HLS GMAC | AES-GCM in GMAC mode | **Authentication Key (AK)** + encryption key EK | `GMAC(SC ‖ AK ‖ StoC)`, IV = Sys-T ‖ IC | `SC ‖ IC ‖ T` = 17 octets (suite 0) | Yes | **Strong.** AES-based, replay-bound via IC. | The practical symmetric choice. |
| **id(6)** HLS SHA-256 | SHA-256 hash | HLS secret | `SHA-256(HLS_Secret ‖ Sys-T_C ‖ Sys-T_S ‖ StoC ‖ CtoS)` | 32 octets | Yes | **Strong** hash; but a plain hash, not a MAC construction. | Where a password-based secret is preferred over AES keys. |
| **id(7)** HLS ECDSA | ECDSA signature | **Private signature key**; verified via certificate | `ECDSA(Sys-T_C ‖ Sys-T_S ‖ StoC ‖ CtoS)` | 2·⌈log₂n/8⌉ octets = 64 (P-256) / 96 (P-384) | Yes | **Strongest.** Public-key; non-repudiable; no shared secret. | Suites 1 and 2, PKI deployments. |

### Reading the table — the four things that actually differ

**1. What secret is used.** Mechanisms 3, 4, 6 use an *HLS secret* (a
password-like shared value). Mechanism 5 uses the *Authentication Key* — the
same AK used for message protection. Mechanism 7 uses a *private key* that is
never shared at all.

**[INFER]** This is the deepest distinction. Mechanism 5 has no separate
credential to provision, rotate, or leak — it reuses key material you already
manage. Mechanism 7 has no shared secret whatsoever, so compromising the
server tells you nothing about the client.

**2. Whether the system titles are bound in.** Only mechanisms 6 and 7 include
`Sys-T_C` and `Sys-T_S` in the hashed/signed input. **[THEORY]** That binds
the authentication to *these two specific devices*. Mechanisms 3–5 do not do
this at the formula level — though mechanism 5 binds the system title
implicitly through the IV.

**3. Whether replay is bound to a counter.** Only mechanism 5 carries an
invocation counter in its response (`f = SC ‖ IC ‖ T`). Mechanisms 3, 4, 6, 7
rely purely on challenge freshness.

**4. Whether it survives server compromise.** For mechanisms 3–6, the server
stores the same secret the client uses — extract it from one meter and you can
impersonate the client to every meter sharing it. For mechanism 7, the server
stores only the client's *public* key and certificate; extraction gives an
attacker nothing usable.

### Challenge length requirements [SPEC]

From [GB] Table 42:

| Mechanisms | CtoS / StoC length |
|------------|--------------------|
| 3, 4, 5, 6 | Random string, **8 to 64 octets** |
| 7 | Random string, **32 to 64 octets** |

**[INFER]** The longer minimum for mechanism 7 is not accidental: the
challenge feeds a signature over a 256- or 384-bit curve, and an 8-octet
challenge would provide only 64 bits of freshness against a signature scheme
offering 128+ bits of security.

**[IMPL]** At 8 octets you have 64 bits of challenge. That is adequate against
replay but is the floor. Use 16 octets minimum where the peer permits it — the
cost is 8 bytes on the wire, once per association.

---

## 6.5 What "additional information" means per mechanism

**[SPEC]** [GB] Table 42's Pass 1 and Pass 2 columns, plus the note following:

| Mechanism | Pass 1 also carries | Pass 2 also carries |
|-----------|--------------------|--------------------|
| 3, 4, 5 | *(nothing extra)* | *(nothing extra)* |
| 6 | `System-Title-C` in `calling-AP-title` | `System-Title-S` in `responding-AP-title` |
| 7 | `System-Title-C` in `calling-AP-title`, `Cert-Sign-Client` in `calling-AE-qualifier` | `System-Title-S` in `responding-AP-title`, `Cert-Sign-Server` in `responding-AE-qualifier` |

**[SPEC]** And the conditionality, [GB] Table 42 NOTE and following text:

> *"NOTE The system titles and the Certificates have to be sent only if not
> already known by the other party."*
>
> *"The System_Title and Cert-Sign may be already known; in this case they do
> not have to be transported. If these elements are not available, the result
> of the processing of the challenge fails and the AA shall not be
> established."*

**[IMPL] The failure mode this creates.** A meter that has previously learned
the client's system title (say, during S-FSK registration) may legitimately
receive an AARQ *without* `calling-AP-title`. A meter that has *not* learned it
receives the same AARQ and must fail. Two identical-looking AARQs, two
different outcomes, depending on server-side state.

When debugging "HLS mechanism 6 works on the bench and fails in the field",
this is the first thing to check: whether the field meter has the client
system title provisioned. **[SPEC]** [GB] 4.3.4 lists the three ways a system
title can arrive:

1. During the media-specific registration process (e.g. S-FSK CIASE).
2. During AA establishment in the AARQ/AARE.
3. By writing `client_system_title` / reading `server_system_title` on the
   "Security setup" object.

And a consistency rule: **[SPEC]** *"If the system titles sent / received
during AA establishment are not the same as the ones exchanged during the
registration process, the AA shall be rejected."*

---

## 6.6 The HLS secret and how it is changed

**[SPEC]** [GB] 9.2.2.2.2.4:

> *"In some HLS authentication mechanisms, the processing of the challenges
> involves the use of an HLS secret. The 'Association SN / LN' interface class
> provides a method to change the HLS 'secret': change_HLS_secret."*

And a warning that is really a distributed-systems problem in disguise:

> **[SPEC]** *"REMARK After the client has issued the change_HLS_secret () —
> or change_LLS_secret () — method, it expects a response from the server
> acknowledging that the secret has been changed. It is possible that the
> server transmits the acknowledgement, but due to communication problems, the
> acknowledgement is not received at the client side. Therefore, the client
> does not know if the secret has been changed or not. For simplicity reasons,
> the server does not offer any special support for this case; i.e. it is left
> to the client to cope with this situation."*

**[INFER] This is the classic lost-acknowledgement problem, and the
specification explicitly declines to solve it.** The consequence: a meter can
end up with a secret the head-end does not know, and the head-end cannot
determine which of two values is live.

**[IMPL] Client-side handling.** Since the server offers no help, the client
must:

1. Retain both old and new secrets after issuing `change_HLS_secret`, marked
   *pending*.
2. On the next association attempt, try the new secret first; on
   authentication failure, retry with the old.
3. Only discard the old secret after a successful authentication with the new
   one.
4. Alarm if both fail — that indicates a third state and needs a field visit.

**[IMPL] Server-side hardening (optional but wise).** Nothing prevents a
server from committing the secret change *atomically with* the response
transmission, and from keeping a short-lived grace window in which the previous
secret is still accepted. **[VENDOR]** Whether a given meter does this is a
vendor choice, not specified behaviour — so a client must not rely on it.

---

## 6.7 HLS failure handling

**[SPEC]** [GB] 9.2.2.2.2.4: *"If both passes 3 and 4 are successfully
executed, then the AA is established. Otherwise, either the client or the
server aborts the AA."*

**[IMPL]** A correct server state machine:

```
   AA_HLS_PASS2_SENT
        │
        ├── receives reply_to_HLS_authentication with valid f(StoC)
        │      └──► compute f(CtoS), send in ACTION response
        │             └──► AA_ESTABLISHED
        │
        ├── receives reply_to_HLS_authentication with INVALID f(StoC)
        │      └──► respond with failure
        │             └──► ABORT the AA  ← do NOT stay in PASS2_SENT
        │                   increment failure counter
        │
        ├── receives ANY OTHER service
        │      └──► reject  ← the authentication-bypass guard
        │
        └── timeout expires
               └──► ABORT the AA
```

Three requirements that are easy to omit:

**Abort on failure, do not retry in place.** If a failed pass 3 leaves the
association in `PASS2_SENT`, an attacker gets unlimited guesses against a
single StoC. Each attempt must force a fresh association and a fresh challenge.

**A timeout is mandatory [IMPL].** Without one, an attacker opens associations
and never completes them, exhausting the server's association slots — a
trivial denial of service. The specification does not mandate a timeout value;
**[VENDOR]** typical values are in the tens of seconds.

**Fresh randomness per attempt.** StoC must be regenerated for every AARQ. A
server that caches a challenge across attempts has reintroduced replay.

---

## 6.8 Chapter 6 summary

1. HLS is four passes: CtoS in the AARQ, StoC in the AARE, `f(StoC)` and
   `f(CtoS)` via `reply_to_HLS_authentication`.
2. Passes 1–2 use COSEM-OPEN; passes 3–4 use an ACTION on the Association
   object, method 1.
3. Between pass 2 and pass 4 the AA exists but **only**
   `reply_to_HLS_authentication` is permitted.
4. `StoC == CtoS` must be rejected by the client.
5. Six mechanisms exist; ids 3 and 4 are deprecated by the specification
   itself; id 2 is manufacturer-secret.
6. Mechanism 5 (GMAC) reuses the AK you already have and binds the invocation
   counter into the response.
7. Mechanism 7 (ECDSA) is the only one with no shared secret and therefore the
   only one that survives full server compromise.
8. `change_HLS_secret` has an unsolved lost-acknowledgement problem that the
   client must handle.

---

**Next: Volume 2 — AES, AES-GCM, GMAC in extreme depth, the Security Control
byte bit by bit, IV and Invocation Counter, System Title, the three security
suites, ciphered APDU wire format, and every official Green Book test vector
verified byte for byte.**

*End of Volume 1.*

---

← **Previous:** [Volume 0 — Index and Source Policy](00-INDEX.md)  ·  **Next:** [Volume 2 — The Symmetric Core and the Wire Format](VOL-2-Symmetric-Core-and-Wire-Format.md) →

[Back to the index](00-INDEX.md)
