# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 4 — General Ciphering, Multi-Layer Protection, and Packet Analysis**
*Chapters 20–24*

> Prerequisites: Volumes 0–3. Volume 2 Chapter 13 (wire format) especially.

---

# CHAPTER 20 — THE GENERAL-CIPHERING APDU IN DEPTH

## 20.1 Why general-ciphering exists

Service-specific `glo-`/`ded-` ciphering assumes the two parties already share
everything: the keys, each other's System Titles, and the association context.
That assumption fails in three situations:

1. **A third party** wants end-to-end security with the meter, but holds none
   of the global keys.
2. **A key must be established as part of the exchange** — wrapped or agreed —
   rather than assumed present.
3. **The message needs provenance metadata** — who originated it, who must
   remove the protection, when, and under what transaction.

`general-ciphering` carries all of that inline.

**[SPEC]** [GB] 9.2.7.2.4.8:

> *"The general-ciphering APDU can be used between a client and a server or
> between a third party and the server. **These APDUs carry also the necessary
> information on the key to be used.**"*

---

## 20.2 The structure

**[SPEC]** [GB] clause 9.5:

```
   General-Ciphering ::= SEQUENCE
   {
       transaction-id           OCTET STRING,
       originator-system-title  OCTET STRING,
       recipient-system-title   OCTET STRING,
       date-time                OCTET STRING,
       other-information        OCTET STRING,
       key-info                 Key-Info OPTIONAL,
       ciphered-content         OCTET STRING
   }
```

Tag **`0xDD`** ([221]).

```
 ┌──────┬──────────┬────────────┬────────────┬──────┬───────┬──────┬──────────┐
 │ 0xDD │transact- │ originator-│ recipient- │date- │other- │ key- │ ciphered-│
 │      │ ion-id   │ system-    │ system-    │time  │inform-│ info │ content  │
 │      │          │ title      │ title      │      │ation  │      │          │
 └──────┴──────────┴────────────┴────────────┴──────┴───────┴──────┴──────────┘
```

**[SPEC]** [GB] Figure 84: *"All fields are A-XDR encoded OCTET STRINGs. **The
length and the value of each field is included in the AAD.**"*

That sentence is the single most common source of general-ciphering interop
failure. The AAD includes each field's **length octet(s) as well as its
value** — including the length octets of *empty* fields. An empty `date-time`
contributes one octet (`00`) to the AAD, not zero octets.

---

## 20.3 Field-by-field

**[SPEC]** [GB] Table 39 and 9.2.7.2.4.8:

| Field | Present in glo/ded? | Present in general? | Purpose |
|-------|--------------------|---------------------|---------|
| `system-title` | `–` service-specific, `+` general-glo/ded | `–` | Originator identity (glo/ded form) |
| `transaction-id` | `–` | **`+`** | Correlates request/response; supplies `Nonce_U` for C(0e,2s) |
| `originator-system-title` | `–` | **`+`** | **[SPEC]** *"identifying the party that applied the protection"* |
| `recipient-system-title` | `–` | **`+`** | **[SPEC]** *"the party that shall check / remove the protection"* |
| `date-time` | `–` | **`+`** | Freshness / audit |
| `other-information` | `–` | **`+`** | Extension point |
| `key-info` | `–` | **`+`** | How the encryption key is identified or established |
| `security control byte` | `+` | `+` | **[SPEC]** *"Provides information on the protection applied, the key-set and the security suite used"* |
| `invocation counter` | `+` | `+` | The IV's invocation field |
| unprotected / encrypted APDU | `+` | `+` | The payload |
| `authentication tag` | `+` | `+` | **[SPEC]** *"Calculated by the AES-GCM algorithm"* |

**[SPEC]** Footnote 1) to Table 39: *"In the case of the general-ciphering APDU,
the key-set bit of the security control byte is not relevant and shall be set
to zero."*

---

## 20.4 The AAD construction

**[SPEC]** [GB] Table 38, the `general-ciphering` column:

```
 ── Authentication only (E=0, A=1) ──────────────────────────────────
   P = ∅
   A = SC ‖ AK
       ‖ transaction-id           (length ‖ value)
       ‖ originator-system-title  (length ‖ value)
       ‖ recipient-system-title   (length ‖ value)
       ‖ date-time                (length ‖ value)
       ‖ other-information        (length ‖ value)
       ‖ (C) I                    ← the compressed/plain APDU

 ── Encryption only (E=1, A=0) ──────────────────────────────────────
   P = (C) I
   A = – (null)

 ── Authenticated encryption (E=1, A=1) ★ ───────────────────────────
   P = (C) I
   A = SC ‖ AK
       ‖ transaction-id           (length ‖ value)
       ‖ originator-system-title  (length ‖ value)
       ‖ recipient-system-title   (length ‖ value)
       ‖ date-time                (length ‖ value)
       ‖ other-information        (length ‖ value)
```

**Note what is *not* in the AAD: `key-info`.** The five metadata fields are
authenticated; the key information is not. **[INFER]** That is defensible — the
`key-ciphered-data` for C(1e,1s) is itself ECDSA-signed, and a wrapped key
carries its own RFC 3394 integrity check — but it means an attacker who alters
`key-info` produces a decryption failure rather than a tag failure. Your error
reporting should distinguish the two.

**[IMPL]** Because the five metadata fields *are* in the AAD, an attacker
cannot rewrite the originator or recipient System Title without breaking the
tag. That is what makes the broker model in Chapter 22 safe.

---

## 20.5 The key-info field

**[SPEC]** [GB] clause 9.5:

```
   Key-Info ::= CHOICE
   {
       identified-key  [0] Identified-Key,
       wrapped-key     [1] Wrapped-Key,
       agreed-key      [2] Agreed-Key
   }
```

**[SPEC]** [GB] Table 21, in full:

| Choice | Member | M/S | Meaning |
|--------|--------|-----|---------|
| **`identified-key`** | | S | *"The EK is identified"* |
| | `key-id` | M | |
| | ↳ `global-unicast-encryption-key` | S | GUEK |
| | ↳ `global-broadcast-encryption-key` | S | GBEK |
| **`wrapped-key`** | | S | *"The EK is transported using key wrap"* |
| | `kek-id` | M | |
| | ↳ `master-key` | M | *"Identifies the key used for wrapping the key-ciphered-data. **0 = Master Key (KEK)**"* |
| | `key-ciphered-data` | M | *"Randomly generated key wrapped with KEK"* |
| **`agreed-key`** | | S | *"The key is agreed by the parties using either the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme; or the Static Unified Model C(0e, 2s, ECC CDH) scheme"* |
| | `key-parameters` | M | *"Identifier of the key agreement scheme: **0x01: C(1e, 1s ECC CDH)**, **0x02: C(0e,2s ECC CDH)**. All other reserved."* |
| | `key-ciphered-data` | M | See below |

**[SPEC]** The `key-ciphered-data` semantics for `agreed-key`:

> *"In the case of the C(1e, 1s, ECC CDH) scheme: **the public key Q_e,U of the
> ephemeral key agreement key pair of party U, signed with the private digital
> signature key of party U.**"*
>
> *"In the case of the C(0e, 2s, ECC CDH) scheme: **an octet-string of length
> zero.** In this case party U has to provide a nonce, Nonce_U."*

**[SPEC]** And the scoping note that explains the whole design:

> *"NOTE Using key identification restricts exchanging protected xDLMS APDUs /
> COSEM data between a client and a server because the GUEK and the GBEK shall
> not be disclosed to any party other than the client and the server."*

```
   ┌───────────────────────────────────────────────────────────────┐
   │  WHO CAN USE WHICH key-info CHOICE                            │
   ├───────────────────────────────────────────────────────────────┤
   │  identified-key   →  client ↔ server ONLY                     │
   │                      (a third party has no GUEK/GBEK)         │
   │                                                               │
   │  wrapped-key      →  client ↔ server ONLY                     │
   │                      (a third party has no KEK)               │
   │                                                               │
   │  agreed-key       →  client ↔ server  OR  third party ↔ server│
   │                      (needs only certificates — no shared     │
   │                       symmetric secret)                       │
   └───────────────────────────────────────────────────────────────┘
```

**[INFER]** This is why key agreement, not key wrap, is the enabler for
third-party end-to-end security. A third party can be onboarded with nothing but
a certificate issued by a CA the meter trusts.

---

## 20.6 The official general-ciphering example — decoded

**[SPEC]** [GB] Table 41: *"an example where the ACCESS.request and
ACCESS.response APDUs … are protected using authenticated encryption. The
general-ciphering APDU specified in 9.2.7.2.4.8 is used. **The encryption key
is agreed on using the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) key agreement
scheme.** The authentication key is the same as in Table 40."*

### 20.6.1 The assembled bytes, field by field

```
DD                          general-ciphering, tag [221]
│
├─ 08                       transaction-id: length 8
│  0102030405060708         transaction-id: value
│
├─ 08                       originator-system-title: length 8
│  4D4D4D0000BC614E         originator-system-title: value
│
├─ 08                       recipient-system-title: length 8
│  4D4D4D0000000001         recipient-system-title: value
│
├─ 00                       date-time: length 0  (absent, but the
│                           LENGTH OCTET still enters the AAD)
│
├─ 00                       other-information: length 0
│
├─ 01                       key-info: OPTIONAL present
│  02                       CHOICE = agreed-key [2]
│  01                       key-parameters: length 1
│  01                       key-parameters: value = C(1e, 1s ECC CDH)
│  81 80                    key-ciphered-data: length 0x80 = 128
│  C323C2BD45711DE4688637D9…  ← 128 octets
│     ┌──────────────────────────────────────────────────────────┐
│     │ 64 octets: Q_e,U  =  x-coordinate (32) ‖ y-coordinate(32)│
│     │ 64 octets: ECDSA signature over it  =  R (32) ‖ S (32)   │
│     │            computed with party U's private signature key │
│     └──────────────────────────────────────────────────────────┘
│
└─ 81 EB                    ciphered-content: length 0xEB = 235
   30                       SC = authenticated encryption, suite 0,
   │                             unicast, no compression
   00000000                 IC = 0
   3F14FC102AE08241BC24EF…  ciphertext (223 octets)
   …                        authentication tag (12 octets)
```

**[SPEC]** The Green Book annotates the ciphered-content as
*"SC ‖ IC ‖ ciphertext ‖ auth. Tag"* and the whole example as
*"ACCESS.request with authenticated encryption"*.

### 20.6.2 What to learn from this example

**The 128-octet `key-ciphered-data` decomposes exactly as Chapter 18 predicted.**
64 octets of P-256 public key (`FE2OS(x) ‖ FE2OS(y)`) plus 64 octets of plain-
format ECDSA signature (`R ‖ S`, 32 each). Confirming Volume 3 §17.4.3: this is
**not** DER — a DER signature would be 70–72 octets and the field would not be
a round 128.

**The invocation counter is 0.** The encryption key was *just agreed*, so
**[SPEC]** *"when the key is established the corresponding ICs are reset to 0"*
— [GB] 9.2.3.3.7.3. Seeing `IC = 00000000` alongside an `agreed-key` in a
capture is exactly right, and seeing a *non-zero* IC there would be a bug.

**Both empty fields still cost one octet each.** `date-time` and
`other-information` are `00`. Those two octets are in the AAD. Omit them and
your tag will not match.

**Length encoding is A-XDR.** `0x80` needs `81 80` (the `81` says "one length
octet follows"); `0xEB` needs `81 EB`. Values ≤ 0x7F are a single octet. Getting
this wrong shifts everything downstream.

**The originator here is `4D4D4D0000BC614E`** — the same value the Green Book
uses for the *server* in Table 43. So in this example the **server** is party U
(the originator), sending an ACCESS.request-shaped protected message. That is
consistent with **[SPEC]** [GB] 9.2.3.4.6.3: *"The party sending the message
(the originator) plays the role of party U."* Party U is a role, not a fixed
entity — do not hard-code "client = U".

---

## 20.7 Firmware: parsing general-ciphering

```c
typedef struct {
    const uint8_t *transaction_id;      size_t transaction_id_len;
    const uint8_t *originator_st;       size_t originator_st_len;
    const uint8_t *recipient_st;        size_t recipient_st_len;
    const uint8_t *date_time;           size_t date_time_len;
    const uint8_t *other_info;          size_t other_info_len;
    bool           key_info_present;
    uint8_t        key_info_choice;     /* 0=identified 1=wrapped 2=agreed */
    const uint8_t *key_data;            size_t key_data_len;
    uint8_t        key_parameters;      /* 0x01 or 0x02 for agreed-key    */
    const uint8_t *ciphered_content;    size_t ciphered_content_len;

    /* The AAD spans from the transaction-id LENGTH octet to the end of
       other-information. Capture it as a slice — do not rebuild it.    */
    const uint8_t *aad_meta;            size_t aad_meta_len;
} general_ciphering_t;
```

**[IMPL] Capture the AAD as a contiguous slice of the received buffer** rather
than reconstructing it field by field. The received bytes are, by definition,
exactly what the sender hashed. Rebuilding them re-introduces every
length-encoding and empty-field bug this chapter warns about. The AAD is then:

```
   A = SC ‖ AK ‖ aad_meta[0 .. aad_meta_len)
```

for authenticated encryption, and additionally `‖ (C)I` for authentication-only.

**[IMPL] Validation before crypto:**

```c
/* 1. recipient-system-title must be US. Otherwise this message is not
      for us to unprotect. [GB] 9.2.7.3                              */
if (memcmp(gc.recipient_st, ctx->our_system_title, 8) != 0)
    return ERR_NOT_ADDRESSED_TO_US;

/* 2. Key_Set bit MUST be zero in general-ciphering. [GB] Table 39 n.1 */
if (sc.broadcast) return ERR_MALFORMED;

/* 3. key-info choice must be one we can honour with this peer.        */
if (gc.key_info_choice == KEY_IDENTIFIED && peer_is_third_party)
    return ERR_KEY_INFO_NOT_PERMITTED;   /* [GB] Table 21 NOTE        */

/* 4. For agreed-key C(1e,1s): VERIFY THE SIGNATURE on Q_e,U before
      using it. Otherwise you have an unauthenticated Diffie-Hellman
      and a textbook MITM.                                            */
if (gc.key_info_choice == KEY_AGREED && gc.key_parameters == 0x01) {
    if (ecdsa_verify(peer_signature_pubkey,
                     gc.key_data, 64,          /* Q_e,U               */
                     gc.key_data + 64, 64)     /* R‖S                 */
        != OK)
        return ERR_EPHEMERAL_KEY_NOT_AUTHENTIC;
}
```

Check 4 is the one that must never be skipped. An unverified ephemeral public
key is an open invitation to substitute your own and read everything.

---

# CHAPTER 21 — GENERAL-SIGNING AND DIGITAL SIGNATURE

## 21.1 Structure

**[SPEC]** [GB] Figure 85 and clause 9.5:

```
   General-Signing ::= SEQUENCE
   {
       transaction-id           OCTET STRING,
       originator-system-title  OCTET STRING,
       recipient-system-title   OCTET STRING,
       date-time                OCTET STRING,
       other-information        OCTET STRING,
       content                  OCTET STRING,
       signature                OCTET STRING
   }
```

Tag **`0xDF`** ([223]).

```
 ┌──────┬──────────┬───────────┬───────────┬──────┬───────┬─────────┬─────────┐
 │ 0xDF │transact- │originator-│recipient- │date- │other- │ content │signature│
 │      │ion-id    │system-    │system-    │time  │inform-│         │         │
 │      │          │title      │title      │      │ation  │         │         │
 └──────┴──────────┴───────────┴───────────┴──────┴───────┴─────────┴─────────┘
   ◄──────────── all of this contributes to the signature ─────────►
```

**[SPEC]** [GB] Figure 85: *"All fields are A-XDR encoded OCTET STRINGs. **The
length and the value of each field contribute to the signature.**"*

Same rule as general-ciphering's AAD: lengths count.

**[SPEC]** [GB] 9.2.7.2.5: *"The algorithm is the elliptic curve digital
signature algorithm (ECDSA) as specified in 9.2.3.4.5."* — so P-256/SHA-256 for
suite 1, P-384/SHA-384 for suite 2, and the signature is plain `R‖S` of 64 or 96
octets.

**[SPEC]** [GB] Table 36: `general-signing` uses an **asymmetric key**, provides
**digital signature**, and **compression: No**.

---

## 21.2 What `content` holds

The `content` field is an OCTET STRING carrying whatever is being signed. Two
useful cases:

```
 ── Sign only ────────────────────────────────────────────────────────
   0xDF … content = [ plain xDLMS APDU ] … signature
   → authenticity + non-repudiation, NO confidentiality

 ── Sign then encrypt ────────────────────────────────────────────────
   [SPEC] "If both ciphering and digital signature is applied by the
    same party for the same party, then normally the digital signature
    is applied first." — [GB] 9.2.7.3

   0xDD general-ciphering
     └─ ciphered-content
          └─ (encrypted) 0xDF general-signing
                            └─ content = plain xDLMS APDU
                            └─ signature
```

**[INFER] Why sign-then-encrypt rather than encrypt-then-sign?** Signing first
means the signature covers the *plaintext*, which is what you actually want to
attest to. It also hides the identity of the signer from a passive observer,
because the signature and the originator fields of the inner APDU are inside
the ciphertext. Encrypt-then-sign would leave the signature — and therefore the
signer — visible.

---

## 21.3 When to use general-signing

| Requirement | Symmetric (GMAC) sufficient? | Needs ECDSA? |
|-------------|------------------------------|--------------|
| Detect tampering in transit | ✅ | |
| Confirm the peer holds the shared key | ✅ | |
| Prove to a **third party** who originated a message | ❌ | ✅ |
| Billing evidence admissible against the utility | ❌ | ✅ |
| Firmware image authenticity | ❌ | ✅ |
| Authenticate a party you share no secret with | ❌ | ✅ |

**[INFER] The billing case is the practically important one.** With a GMAC tag,
the utility and the meter share the key — so the utility could have fabricated
any reading, and a customer disputing a bill has a real argument. With an ECDSA
signature made by a private key that never left the meter, the reading is
attributable to the meter alone. Regulators in several jurisdictions are moving
toward requiring exactly this, and it is the strongest reason to plan for suite
1 even if you deploy suite 0 today.

---

# CHAPTER 22 — MULTI-LAYER PROTECTION AND THE THIRD-PARTY MODEL

## 22.1 The concept

**[SPEC]** [GB] 9.2.7.3:

> *"Cryptographic protection can be applied by multiple parties. Generally the
> parties are: a server; a client; a third party."*
>
> *"Each party can apply one or multiple layers of protection:*
> - *to apply encryption, authentication or authenticated encryption, the
>   **general-ciphering** APDU is used. **Authenticated encryption is considered
>   to be a single layer of protection**;*
> - *to apply digital signature, the **general-signing** APDU is used."*
>
> *"Both APDUs include the Originator_System_Title and the
> Recipient_System_Title, identifying the party that applied the protection and
> the party that shall check / remove the protection."*

---

## 22.2 The end-to-end model

**[SPEC]** [GB] 9.2.2.5:

> *"To ensure end-to-end message security, third parties have to be able to
> exchange protected xDLMS service requests with DLMS/COSEM servers. In this
> case, **the client acts as a broker**, meaning that a third party is a user of
> one of the AAs between a client and a server the third party wants to reach."*

```
 ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
 │ THIRD PARTY  │        │    CLIENT    │        │    SERVER    │
 │              │        │  (broker)    │        │   (meter)    │
 └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
        │                       │                       │
        │  TP applies its own   │                       │
        │  protection to the    │                       │
        │  xDLMS APDU           │                       │
        │                       │                       │
        │── protected TP-client │                       │
        │   message ───────────►│                       │
        │                       │ client ENCAPSULATES   │
        │                       │ it in its own         │
        │                       │ general-ciphering     │
        │                       │ APDU (its own layer)  │
        │                       │                       │
        │                       │── client-server ─────►│
        │                       │   general protected   │
        │                       │   APDU                │
        │                       │                       │ server removes
        │                       │                       │ the client's
        │                       │                       │ layer, then
        │                       │                       │ the TP's layer
        │                       │                       │
        │                       │◄── server-client ─────│
        │                       │    protected response │
        │                       │                       │
        │◄── protected client-  │                       │
        │    TP message ────────│                       │
        │                       │                       │
```

**[SPEC]** Responsibilities, [GB] 9.2.2.5:

**The third party:**
> *"is DLMS/COSEM aware i.e. it can generate and process messages encapsulating
> xDLMS APDUs carrying COSEM object related service requests and responses; it
> is able to apply its own protection to the xDLMS APDU carrying the request;
> it is able to verify protection applied by the server and / or the client on
> the response."*

**The client (broker):**
> *"acts as a broker between the third party and the server; makes an
> appropriate AA available for use by the third party, based on information
> included in the TP – client message; **verifies that the TP has the right to
> use that AA**; it may verify the protection applied by the third party;
> encapsulates the third party – client message into a general protected xDLMS
> APDU; it may verify the protection applied by the server on the APDU
> encapsulating the … response; it may apply its own protection to the
> protected xDLMS APDUs sent to the TP."*
>
> *"NOTE 2 The way to verify this is outside the Scope of this Technical
> Report."*

**The server:**
> *"shall (pre-)establish an AA with the client used by the third party; it may
> check the identity of the third party using the AA; it shall provide access
> to COSEM object attributes and methods as determined by the security policy
> and access rights **once the protection(s) applied by the client and/or the
> third party have been successfully verified**; it shall prepare the response …
> and apply the protection determined by the protection applied on the incoming
> request, the access rights and the security policy."*

---

## 22.3 The protection mirroring rules

**[SPEC]** [GB] 9.2.7.3 — three rules that govern what protection appears on
the response:

> **Rule 1** — *"If a kind of protection has been applied on the request by a
> party, then the same kind of protection will be applied for the same party in
> the response."*
>
> **Rule 2** — *"However if a kind of protection which was applied on the
> request is not required on the response, than no protection will be applied
> on the response for that party."*
>
> **Rule 3** — *"If a protection is required on the response that was not
> applied on the request, then the server cannot determine from the request
> which party has the response to be protected for. Therefore **it shall apply
> the protection for all parties**."*

**[SPEC]** The Green Book's own worked examples:

> *"**Example 1** If the request was digitally signed by the third party and
> authenticated by the client, and the required protection on the response is
> authentication and digital signature, then the response will be authenticated
> for the client and digitally signed for the third party."*
>
> *"**Example 2** If the request was digitally signed by the third party and
> authenticated by the client, and the required protection on the response is
> authentication only, then the response will be authenticated for the client
> and **no protection will be applied to the third party**. (The TP will receive
> a general-ciphering APDU without any protection applied.)"*

Tabulated:

| Request protection | Required response protection | Response actually built |
|-------------------|------------------------------|------------------------|
| TP: signed<br>Client: authenticated | authentication + signature | Client layer: authenticated<br>TP layer: signed |
| TP: signed<br>Client: authenticated | authentication only | Client layer: authenticated<br>TP layer: **general-ciphering with SC = 0x00, no protection** |
| TP: nothing<br>Client: authenticated | authentication + encryption | **Applied for all parties** (Rule 3) |

**[IMPL]** Example 2 explains why `SC = 0x00` — "no protection" — is a legal
value inside `general-ciphering` (Volume 2 §9.2.3). It is the encoding for *"a
layer exists for this party, but nothing is applied to it."* Your parser must
accept it in `general-ciphering` and reject it everywhere else.

**[SPEC]** *"See also Annex D"* — for further multi-layer scenarios.

---

## 22.4 A worked multi-layer message

**«EDUCATIONAL / FICTIONAL EXAMPLE»** — structure is per [SPEC]; values are
illustrative.

Third party `TTT0000000000001` reads a register from meter `MMM0000000000042`
through client `CCC0000000000009`. TP signs; client authenticates.

```
 LAYER 3 — what the client transmits to the server
 ┌────────────────────────────────────────────────────────────────┐
 │ DD  general-ciphering                                          │
 │   transaction-id          = 0102030405060708                   │
 │   originator-system-title = CCC0000000000009   ← the CLIENT    │
 │   recipient-system-title  = MMM0000000000042   ← the SERVER    │
 │   date-time               = (empty)                            │
 │   other-information       = (empty)                            │
 │   key-info                = identified-key: GUEK               │
 │   ciphered-content:                                            │
 │     SC = 10   (authentication only, suite 0, unicast)          │
 │     IC = 000012A7                                              │
 │     ┌────────────────────────────────────────────────────────┐ │
 │     │ LAYER 2 — the TP's signed message, carried as the       │ │
 │     │           client's "information"                        │ │
 │     │ DF  general-signing                                     │ │
 │     │   transaction-id          = 0102030405060708            │ │
 │     │   originator-system-title = TTT0000000000001  ← the TP  │ │
 │     │   recipient-system-title  = MMM0000000000042            │ │
 │     │   date-time               = (empty)                     │ │
 │     │   other-information       = (empty)                     │ │
 │     │   content:                                              │ │
 │     │     ┌─────────────────────────────────────────────────┐ │ │
 │     │     │ LAYER 1 — the actual service                    │ │ │
 │     │     │ C0 01 C1 00 03 01 00 01 08 00 FF 02 00          │ │ │
 │     │     │ get-request, Register class 3, attribute 2      │ │ │
 │     │     └─────────────────────────────────────────────────┘ │ │
 │     │   signature = R‖S, 64 octets, TP's private ECDSA key    │ │
 │     └────────────────────────────────────────────────────────┘ │
 │     T = 12-octet GMAC tag over SC ‖ GAK ‖ metadata ‖ layer 2   │
 └────────────────────────────────────────────────────────────────┘
```

**Server-side processing order:**

```
   ① Parse the outer general-ciphering (0xDD).
   ② recipient-system-title == MMM0000000000042 → yes, it is for us.
   ③ key-info = identified-key GUEK → select the GUEK.
   ④ Build IV = originator-system-title ‖ IC
              = CCC0000000000009 ‖ 000012A7
      ★ the ORIGINATOR of THIS layer — the client, not the TP.
   ⑤ Rebuild AAD = SC ‖ GAK ‖ (metadata slice) ‖ layer-2 bytes.
   ⑥ Verify tag. Fail → discard everything. Client layer removed.
   ⑦ Parse the inner general-signing (0xDF).
   ⑧ recipient-system-title == us → yes.
   ⑨ Look up TP's C(DataSign) certificate by originator-system-title
      TTT0000000000001, via SubjectAltName→hwSerialNum. [Vol 3 §19.4.2]
   ⑩ Verify the ECDSA signature over the full field sequence
      (lengths AND values). Fail → discard. TP layer removed.
   ⑪ NOW parse the layer-1 get-request.
   ⑫ Check access rights for THIS association AND, per [GB] 9.2.2.5,
      optionally the TP's identity.
   ⑬ Execute; build the response with mirrored protection (§22.3).
```

**[IMPL] Step ④ is the one to get right.** In a multi-layer message each layer
has its **own** originator, and each layer's IV uses **that layer's**
originator. A single global "peer system title" variable in your context is
wrong here.

---

## 22.5 COSEM data security

**[SPEC]** [GB] 9.2.2.6:

> *"COSEM data i.e. values of COSEM object attributes, method invocation
> parameters and return parameters can be also cryptographically protected.
> When this is required, the attributes and methods concerned are **accessed
> indirectly, via 'Data protection' objects**, applies and verifies / removes
> protection on COSEM data."*
>
> *"NOTE COSEM data may be still accessed directly, subject to security policy
> and access rights of the objects concerned."*

**[SPEC]** [GB] 9.2.7.5:

> *"The cryptographic algorithms applied to xDLMS APDUs can be also applied to
> COSEM data, i.e. attribute values and method invocation / return parameters.
> This is achieved by accessing attributes and/or methods of other COSEM
> objects indirectly through instances of the 'Data protection' interface
> class."*
>
> *"The list of data to be protected, the required protection and the
> protection parameters are determined by the 'Data protection' objects."*
>
> *"'Data protection' objects allow applying or removing protection when
> reading or writing a list of attributes, or when invoking methods of COSEM
> objects. Protection to be applied / removed may include **any combination of
> authentication, encryption and digital signature**."*
>
> *"The APDUs carrying the service invocations to access the attributes and
> methods of 'Data protection' objects are protected as required by the
> prevailing security policy and the access rights of the 'Data protection'
> object."*

### The distinction that matters

```
   ── MESSAGE SECURITY ──────────────────────────────────────────────
   Protects the APDU in transit. Removed by the recipient.
   The data lands in the meter's application as plaintext.

     TP ──[protected]──► Client ──[protected]──► Meter
                                                   └─► plaintext data

   ── COSEM DATA SECURITY ───────────────────────────────────────────
   Protects the DATA ITSELF, independently of transport.
   Protection survives the removal of the message layers.

     TP ──────────────────────────────────────────► Meter
        the DATA is protected end-to-end; the meter's application
        stores or produces it in protected form, and only the
        intended party can remove that protection
```

**[INFER] Why this exists.** Consider a load-profile export where the meter
signs the readings. The signature must survive the client stripping the
transport layer, being stored in a database for a year, and being presented to
a regulator. Message security cannot do that — it is removed on arrival. Data
security can.

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — the "Data
> protection" interface class (attributes, methods, protection-parameter
> structures) is specified in **Blue Book DLMS UA 1000-1 Ed. 12:2014 clause
> 4.4.9**, which was not supplied. [GB] tells us it exists and what it does,
> not its encoding.

---

# CHAPTER 23 — PACKET-BY-PACKET ANALYSIS

**«EDUCATIONAL / FICTIONAL PACKET CAPTURE»**
Every value in this chapter is constructed for teaching except where explicitly
marked **[GB Table 40]** or **[GB Table 43]**, which are official. Do not use
the fictional values as test vectors.

## 23.1 Scenario

```
   Client (HES)     System Title  4D4D4D0000000001   [GB Table 43]
   Server (meter)   System Title  4D4D4D0000BC614E   [GB Table 43]
   Suite 0, HLS mechanism 5 (GMAC), LN referencing with ciphering
   EK = 000102030405060708090A0B0C0D0E0F              [GB Table 40/43]
   AK = D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF              [GB Table 40/43]
   Security policy: authenticated + encrypted, both directions
```

---

## 23.2 Packet 1 — AARQ

```
60 36
│  └─ length 0x36 = 54
└─ AARQ, [APPLICATION 0]

   A1 09 06 07 60 85 74 05 08 01 03
   └─ application-context-name
      = 2.16.756.5.8.1.3
      = Logical_Name_Referencing_With_Ciphering   [GB Table 74]
      ★ context_id 3 ⇒ ciphered APDUs are PERMITTED

   A6 0A 04 08 4D 4D 4D 00 00 00 00 01
   │  │  │  │  └────────────────────┴─ client System Title
   │  │  │  └─ length 8
   │  │  └─ OCTET STRING
   │  └─ length 10
   └─ [6] calling-AP-title
      ★ carries the CLIENT SYSTEM TITLE — needed for the IV

   8A 02 07 80
   └─ [10] sender-acse-requirements
      = BIT STRING { authentication (0) }
      ★ MANDATORY when mechanism-name is present  [GB 9.4.2.2.3]

   8B 07 60 85 74 05 08 02 05
   └─ [11] mechanism-name = 2.16.756.5.8.2.5
      = COSEM_High_Level_Security_Mechanism_Name_Using_GMAC
      ★ mechanism_id(5). GMAC is commonly mis-quoted as
        "mechanism 4". It is 5.                  [GB Table 75]

   AC 0A 80 08 4B 35 36 69 56 61 67 59
   │  │  │  │  └────────────────────┴─ CtoS = "K56iVagY"  [GB Table 43]
   │  │  │  └─ length 8
   │  │  └─ [0] CHOICE: charstring
   │  └─ length 10
   └─ [12] calling-authentication-value
      ★ the CLIENT-TO-SERVER CHALLENGE, in the clear —
        and that is fine: it is a random nonce, not a secret

   BE 10 04 0E 01 00 00 00 06 5F 1F 04 00 00 18 1F FF FF
   └─ [30] user-information
      └─ xDLMS InitiateRequest (unciphered here — no dedicated key)
         01 00 00 00   dedicated-key absent, response-allowed TRUE,
                       proposed-quality-of-service absent
         06            dlms-version-number = 6
         5F 1F 04 …    proposed-conformance + max PDU sizes
```

**What the meter does:**

1. Match `(client SAP, server SAP)` to a pre-configured association.
2. Check `application-context-name` is one it supports.
3. Check `mechanism-name` matches the association's configured mechanism.
   Mismatch → reject. **This is the downgrade defence at association level.**
4. Store `CtoS` and the client System Title.
5. Generate a fresh random `StoC`.
6. Enter `AA_HLS_PASS2_SENT` — **only** `reply_to_HLS_authentication` permitted.

**What is visible to an attacker:** everything. Application context,
mechanism, both System Titles, the challenge. None of it is secret. The
challenge is a nonce, not a credential.

---

## 23.3 Packet 2 — AARE

```
61 3A
└─ AARE, [APPLICATION 1], length 0x3A = 58

   A1 09 06 07 60 85 74 05 08 01 03
   └─ application-context-name, echoed = context_id(3)

   A2 03 02 01 00
   └─ [2] result = accepted (0)
      ★ Note: ACCEPTED, even though authentication is incomplete.
        [GB 9.2.2.2.2.4]: "the AA is formally established, but the
        access of the client is restricted to the method
        reply_to_HLS_authentication"

   A3 05 A1 03 02 01 0E
   └─ [3] result-source-diagnostic
      = ACSE service-user, diagnostic 14
      = authentication-required
      ★ THIS is the signal that HLS passes 3–4 must follow

   A4 0A 04 08 4D 4D 4D 00 00 BC 61 4E
   └─ [4] responding-AP-title = SERVER System Title
      ★ the client needs this to build its RX IV

   88 02 07 80
   └─ [8] responder-acse-requirements = authentication

   89 07 60 85 74 05 08 02 05
   └─ [9] mechanism-name = 2.16.756.5.8.2.5 (GMAC), confirmed

   AA 0A 80 08 50 36 77 52 4A 32 31 46
   └─ [10] responding-authentication-value
      = StoC = "P6wRJ21F"                        [GB Table 43]

   BE 10 04 0E 08 00 06 5F 1F 04 00 00 18 1D FF FF …
   └─ [30] user-information → xDLMS InitiateResponse
      (negotiated conformance, negotiated max PDU size)
```

**Client-side check, mandatory:**

```c
/* [GB] 9.2.2.2.2.4: "If StoC is the same as CtoS, the client shall
   reject it and shall abort the AA establishment process."          */
if (stoc_len == ctos_len && memcmp(stoc, ctos, stoc_len) == 0)
    return abort_association(ERR_CHALLENGE_ECHO);
```

Here `"P6wRJ21F" != "K56iVagY"`, so we proceed.

---

## 23.4 Packet 3 — HLS pass 3

The client invokes `reply_to_HLS_authentication` (method 1 of the Association
LN object, OBIS `0.0.40.0.0.255`), with the GMAC result as parameter. Because
the security policy requires protection, the ACTION request is itself
ciphered.

**Computing the parameter** — this is [GB] Table 43, verified in Volume 0 §0.4:

```
   IV  = 4D4D4D0000000001 ‖ 00000001      client Sys-T ‖ client IC
   A   = SC ‖ AK ‖ StoC
       = 10 D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF 503677524A323146
   P   = ∅                                 ← GMAC: nothing encrypted
   T   = 1A52FE7DD3E72748973C1E28          ✅ [GB Table 43]

   f(StoC) = SC ‖ IC ‖ T
           = 10 00000001 1A52FE7DD3E72748973C1E28
           = 10000000011A52FE7DD3E72748973C1E28   (17 octets)
```

**The inner ACTION request:**

```
C3 01 C1
│  │  └─ invoke-id-and-priority
│  └─ action-request-normal
└─ action-request

   00 0F 00 00 28 00 00 FF 01
   │  │  └───────────────┴─ OBIS 0.0.40.0.0.255 = Association LN
   │  └─ class_id 0x000F = 15
   └─ (class id high byte)
   … 01                     method_id 1 = reply_to_HLS_authentication

   01 11 10 00 00 00 01 1A 52 FE 7D D3 E7 27 48 97 3C 1E 28
   │  │  └─────────────────────────────────────────────┴─ f(StoC)
   │  └─ octet-string length 0x11 = 17
   └─ method invocation parameter present
```

**Wrapped in a glo-action-request:** SC = `0x30`, IC = `00000002` (the counter
has advanced past the one used inside the GMAC computation).

```
CB 2C 30 00000002 <ciphertext, 26 octets> <tag, 12 octets>
│  │  │  │
│  │  │  └─ invocation counter
│  │  └─ SC: suite 0, A=1, E=1, unicast, no compression
│  └─ length 0x2C = 44 = 1 + 4 + 26 + 12
└─ glo-action-request [203]
```

> **[INFER]** Note the two different invocation counters. The IC *inside*
> `f(StoC)` (`00000001`) is the one used to build the GMAC IV. The IC in the
> **security header** of the enclosing `glo-action-request` (`00000002`) is the
> one protecting this APDU. They are drawn from the same counter sequence but
> they are different invocations. Confusing them is a real bug — and in a
> capture they will differ by exactly one, which makes it look "obviously
> wrong" to someone who has not thought it through.

**What the meter does:**

```
   ① Parse tag 0xCB → glo-action-request.
   ② SC = 0x30 → suite 0, authenticated encryption, unicast.
      Check it meets the security policy. ✓
   ③ IC = 0x00000002. Check ≥ ic_rx_floor. ✓
   ④ IV = CLIENT Sys-T ‖ 00000002 = 4D4D4D000000000100000002
   ⑤ AAD = SC ‖ AK = 30 D0D1…DEDF
   ⑥ AES-GCM decrypt + verify. Fail → discard, no state change.
   ⑦ ic_rx_floor = 0x00000003.
   ⑧ Parse the ACTION. Check state == AA_HLS_PASS2_SENT and that the
      target is Association LN method 1.  ★ THE BYPASS GUARD
   ⑨ Extract f(StoC) = 10 00000001 1A52…1E28.
      Split: SC' = 10, IC' = 00000001, T' = 1A52…1E28.
   ⑩ Rebuild IV' = CLIENT Sys-T ‖ IC' = 4D4D4D000000000100000001
   ⑪ Rebuild AAD' = SC' ‖ AK ‖ StoC   — using the meter's OWN
      stored StoC, never a value from the wire.
   ⑫ GMAC and compare with T' in constant time. Match → the client
      is authenticated.
```

---

## 23.5 Packet 4 — HLS pass 4

```
   IV  = 4D4D4D0000BC614E ‖ 01234567      server Sys-T ‖ server IC
   A   = SC ‖ AK ‖ CtoS
       = 10 D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF 4B35366956616759
   P   = ∅
   T   = FE1466AFB3DBCD4F9389E2B7          ✅ [GB Table 43]

   f(CtoS) = 10 01234567 FE1466AFB3DBCD4F9389E2B7   (17 octets)
```

Inner action-response:

```
C7 01 C1 00 01 00 01 11 10 01 23 45 67 FE 14 66 AF B3 DB CD 4F 93 89 E2 B7
│  │  │  │  │  │  │  │  └─────────────────────────────────────────────┴─ f(CtoS)
│  │  │  │  │  │  │  └─ octet-string length 17
│  │  │  │  │  │  └─ get-data-result: data
│  │  │  │  │  └─ return parameters present
│  │  │  │  └─ result = success (0)
│  │  │  └─ (method descriptor echo omitted for brevity)
│  │  └─ invoke-id-and-priority
│  └─ action-response-normal
└─ action-response
```

Wrapped as `glo-action-response` (`0xCF`), SC = `0x30`, IC = the server's next
transmit counter.

**Client verifies** using the **server's** System Title and the client's own
stored `CtoS`. Match → mutual authentication complete.

---

## 23.6 Packet 5 — Ciphered GET request

**This is [GB] Table 40 exactly** — official, verified in Volume 0 §0.4.

```
C8 1E 30 01234567 411312FF935A47566827C467BC 7D825C3BE4A77C3FCC056B6B
│  │  │  │        │                          │
│  │  │  │        │                          └─ auth tag, 12 octets
│  │  │  │        └─ ciphertext, 13 octets
│  │  │  └─ IC = 0x01234567
│  │  └─ SC = 0x30
│  └─ length 0x1E = 30
└─ glo-get-request [200] = 0xC8
```

Decrypting yields:

```
C0 01 00 00 08 00 00 01 00 00 FF 02 00
│  │  │  │  └─────────────────┴─ OBIS 0.0.1.0.0.255 = Clock
│  │  │  └─ class_id 0x0008 = 8 (Clock)
│  │  └─ invoke-id-and-priority
│  └─ get-request-normal
└─ get-request [192]
                                 … 02  attribute_id = 2 (time)
                                 … 00  no access selection
```

**[SPEC]** [GB]'s own annotation: *"(Get-request, attribute 2 of the Clock
object)"*.

---

## 23.7 Packet 6 — Ciphered GET response

**«FICTIONAL»** — structure per [SPEC]; the ciphertext and tag are invented.

```
CC 2A 30 89ABCDEF <ciphertext 24 octets> <tag 12 octets>
│  │  │  │
│  │  │  └─ SERVER's invocation counter
│  │  └─ SC = 0x30
│  └─ length 0x2A = 42 = 1 + 4 + 24 + 12
└─ glo-get-response [204] = 0xCC
```

Plaintext:

```
C4 01 C1 00 09 0C 07 E8 09 02 03 0E 1E 0A 00 FF C4 00
│  │  │  │  │  │  └───────────────────────────┴─ date-time
│  │  │  │  │  └─ octet-string, length 12
│  │  │  │  └─ data
│  │  │  └─ result = success
│  │  └─ invoke-id-and-priority
│  └─ get-response-normal
└─ get-response [196]
```

Client processing: build `IV = server Sys-T ‖ 89ABCDEF`, `AAD = SC ‖ AK`,
decrypt, verify, advance the RX floor, parse.

---

## 23.8 Packets 7 and 8 — SET and ACTION

**«FICTIONAL»**

```
   glo-set-request  (0xC9)   SC=0x30  IC=01234568
     inner: C1 01 C1 00 01 00 00 60 01 00 FF 02 00 <data>
            └─ set-request, class 1 Data, OBIS 0.0.96.1.0.255

   glo-action-request (0xCB) SC=0x30  IC=01234569
     inner: C3 01 C1 00 46 00 00 60 03 0A FF 01 …
            └─ action-request, class 70 Disconnect control,
               method 1 = remote_disconnect
```

**[IMPL] The ACTION on Disconnect Control is where all three security concepts
converge, and it is worth walking explicitly:**

```
   ① Message security  — tag verifies ⇒ the sender holds EK and AK
   ② Replay protection — IC > floor  ⇒ not a recorded command
   ③ Authentication    — HLS passed  ⇒ this AA belongs to a proven peer
   ④ ACCESS RIGHTS     — is method 1 of class 70 permitted on THIS
                         association?
                         ✗ → reject, even though ①②③ all passed
```

Step ④ has no cryptography in it. **[INFER]** In practice the disconnect method
should be reachable only from a dedicated high-security association, distinct
from the meter-reading association, with a different mechanism and different
keys. A design where the meter-reading credentials can also open the relay is a
design fault, not a cryptographic one — and no amount of AES fixes it.

---

## 23.9 The complete session summary

| # | Direction | APDU | Tag | SC | IC | Key | Protection |
|---|-----------|------|-----|----|----|-----|-----------|
| 1 | C→S | AARQ | `0x60` | — | — | — | **None** ([GB] 9.2.5.1 NOTE) |
| 2 | S→C | AARE | `0x61` | — | — | — | **None** |
| 3 | C→S | glo-action-request | `0xCB` | `0x30` | `00000002` | GUEK+GAK | Auth. encryption |
| 4 | S→C | glo-action-response | `0xCF` | `0x30` | server IC | GUEK+GAK | Auth. encryption |
| 5 | C→S | glo-get-request | `0xC8` | `0x30` | `01234567` | GUEK+GAK | Auth. encryption |
| 6 | S→C | glo-get-response | `0xCC` | `0x30` | `89ABCDEF` | GUEK+GAK | Auth. encryption |
| 7 | C→S | glo-set-request | `0xC9` | `0x30` | `01234568` | GUEK+GAK | Auth. encryption |
| 8 | C→S | glo-action-request | `0xCB` | `0x30` | `01234569` | GUEK+GAK | Auth. encryption |
| 9 | C→S | RLRQ | `0x62` | — | — | — | Optional |
| 10 | S→C | RLRE | `0x63` | — | — | — | Optional |

**Observation worth internalising:** packets 1 and 2 are *entirely
unprotected*. Everything that establishes the association — the context, the
mechanism, both System Titles, both challenges — is in the clear. The security
begins at packet 3. That is by design, and it is why the AARQ/AARE cannot carry
anything confidential except the dedicated key, which is separately wrapped in
a `glo-initiateRequest`.

---

# CHAPTER 24 — PACKET ANALYSIS TECHNIQUE AND VENDOR DIFFERENCES

## 24.1 What you can learn from an encrypted capture

You will often be handed a capture and no keys. Here is what is still
extractable.

```
   HDLC frame
   ┌──────┬──────┬──────┬─────┬─────┬──────────────┬─────┬──────┐
   │ 7E   │ fmt  │ dest │ src │ ctl │  information │ FCS │ 7E   │
   └──────┴──────┴──────┴─────┴─────┴──────┬───────┴─────┴──────┘
    ↑ visible: addressing, frame type,     │
      sequence numbers, segmentation       │
                                            ▼
                                  ┌──────────────────┐
                                  │ LLC  E6 E6 00    │  ← visible
                                  └────────┬─────────┘
                                            ▼
                          ┌─────────────────────────────────┐
                          │ xDLMS APDU                      │
                          │  tag  ← VISIBLE: service class! │
                          │  len  ← VISIBLE: size           │
                          │  SC   ← VISIBLE: suite, E, A,   │
                          │           key set, compression  │
                          │  IC   ← VISIBLE: message index  │
                          │  ciphertext ← opaque, but its   │
                          │               LENGTH is visible │
                          │  tag  ← opaque                  │
                          └─────────────────────────────────┘
```

| Observable | Inference |
|------------|-----------|
| APDU tag `0xC8`/`0xCC` | Routine meter reading |
| APDU tag `0xC9`/`0xCD` | **Configuration change** |
| APDU tag `0xCB`/`0xCF` | **Method invocation — possibly the relay** |
| APDU tag `0xDB`/`0xDD` | General ciphering — likely third-party or key establishment |
| APDU tag `0xDF` | Digital signature in use ⇒ suite 1 or 2 |
| SC low nibble | Which security suite is deployed |
| SC bit 6 | Broadcast traffic present |
| SC bits 5,4 = `00` | **No protection at all** — a finding |
| SC bits 5,4 = `10` | Encryption only — **malleable, a finding** |
| IC jumps to a low value | **Meter reset, or counter rollback — a serious finding** |
| IC identical on two frames | **Nonce reuse — a critical finding** |
| Ciphertext length | Single register vs load-profile block |
| Long gap then a burst | Polling schedule |

**[IMPL] The two findings you can make from a capture with no keys at all:**

1. **Duplicate `(System Title, IC)` pairs.** Grep the capture for repeated
   invocation counters under the same originator. Any repeat is nonce reuse and
   is a critical vulnerability. This is a five-line script and it is the single
   highest-value check you can run.
2. **SC values weaker than the stated policy.** If the specification says
   authenticated encryption and you see `0x10` or `0x20`, the policy is not
   enforced.

---

## 24.2 Wireshark technique

**[VENDOR]** Wireshark has a DLMS/COSEM dissector. Practical notes:

| Task | Approach |
|------|----------|
| **Decode as** | For raw serial captures, use "Decode As" → DLMS, or import via `text2pcap` with a synthetic link layer |
| **Supplying keys** | Where the dissector supports it, provide the block cipher key and authentication key. **[INFER]** Support varies by version; confirm against your build rather than assuming |
| **Filtering** | Filter on the APDU tag to isolate service classes; filter on the invocation counter field to spot resets |
| **Segmented APDUs** | HDLC segmentation and `general-block-transfer` (`0xE0`) split one APDU across frames. Reassemble **before** attempting decryption — a partial ciphertext will never verify |
| **Time alignment** | Correlate the invocation counter against the frame timestamp to build a picture of message rate and reset events |

**[IMPL] When the dissector cannot decrypt but you have the keys**, do it by
hand — the calculation is small. Extract SC, IC, ciphertext, and tag; build
`IV = originator Sys-T ‖ IC` and `AAD = SC ‖ AK`; run AES-GCM. A twenty-line
Python script using the `cryptography` library does this, and the
`dlms_test_vectors.py` delivered with Volume 0 is a working starting point.

---

## 24.3 The systematic debugging chain

The prompt asked for this as a checklist. Use it in order; each step either
resolves or narrows.

```
   ① CAPTURE
      Is the capture complete? Segmentation reassembled?
      Both directions present?
                          │
   ② APDU IDENTIFICATION  ▼
      Read the tag. Is it a ciphered variant? Which family?
      Does the length field match the actual byte count?
                          │
   ③ SECURITY CONTROL     ▼
      Decode all 8 bits. Suite? E? A? Key_Set? Compression?
      Does it meet the configured policy AND access rights?
                          │
   ④ SUITE                ▼
      Does the SC suite match the negotiated security context?
      A mismatch is a downgrade attempt or a misconfiguration.
                          │
   ⑤ SYSTEM TITLE         ▼
      Which party ORIGINATED this APDU?
      Is the System Title present in the APDU, or must it come
      from association context? Do you have the right one?
                          │
   ⑥ INVOCATION COUNTER   ▼
      Is it ≥ the receiver's floor?
      Has it ever repeated? Did it reset?
                          │
   ⑦ KEY SELECTION        ▼
      Key_Set bit → GUEK or GBEK?
      Dedicated key in play?  key-info override?
                          │
   ⑧ IV CONSTRUCTION      ▼
      IV = originator Sys-T (8) ‖ IC (4), big-endian. 12 octets.
                          │
   ⑨ AAD CONSTRUCTION     ▼
      auth-only:   SC ‖ AK ‖ APDU
      auth+encr:   SC ‖ AK
      general-*:   plus the metadata fields WITH their lengths
                          │
   ⑩ CIPHERTEXT           ▼
      Length must equal the plaintext length. Off-by-one here
      usually means the tag was included in the ciphertext slice.
                          │
   ⑪ AUTHENTICATION TAG   ▼
      Exactly 12 octets. Taken from the MSB end.
                          │
   ⑫ CRYPTO CALCULATION   ▼
      Run it yourself, offline, with known keys.
                          │
   ⑬ EXPECTED vs ACTUAL   ▼
      Compare tag and ciphertext byte by byte.
                          │
   ⑭ ROOT CAUSE           ▼
```

**[INFER] Where the failure usually is.** In my experience, if steps ①–⑦ are
clean and the tag still fails, it is almost always ⑧ or ⑨ — a wrong System
Title in the IV, a wrong endianness on the IC, or an AAD missing the
authentication key or a length octet. Those four account for the large majority
of "the bytes look fine but nothing verifies" cases.

---

## 24.4 Vendor implementation differences

**[VENDOR]** DLMS/COSEM leaves a great deal to companion specifications and to
manufacturers. The following vary and are **not** part of DLMS. Never assume
observed behaviour is standard.

| Area | What varies |
|------|-------------|
| **Key provisioning** | Factory injection method; whether the KEK is per-device or per-batch; whether keys are derivable from the serial number |
| **Association layout** | How many associations; which client SAPs; what each is allowed to do |
| **Supported HLS mechanisms** | Many meters support only mechanism 1 and 5; some only vendor mechanism 2 |
| **Security policy defaults** | Whether ciphering is enforced out of the box or must be activated |
| **Invocation counter exposure** | Which object exposes it, if any; whether it is readable without ciphering |
| **Counter reset behaviour** | What happens on NVM corruption; whether the meter fails closed |
| **Failed-authentication handling** | Lockout, backoff, event logging — all vendor choices |
| **Object model extensions** | Manufacturer-specific objects in the 0.0.128–254 OBIS range |
| **Provisioning protocol** | Some vendors use a proprietary out-of-band tool entirely outside DLMS |
| **Firmware update** | Image Transfer usage, signature scheme, rollback policy |

**[IMPL] How to separate standard from vendor:**

```
   1. If it is in [GB] clause 9.2 or the Blue Book IC definitions
      → STANDARD.
   2. If it is in your national companion specification (IDIS, DSMR,
      IS 15959, G3, …) → PROFILE, mandatory for that market only.
   3. If it is only in the vendor's manual → VENDOR.
   4. If it is only in a field engineer's head → assume it is wrong
      until you see it in one of the above.
```

**[INFER] A practical review question that catches this:** ask "which clause
says so?" Anyone who cannot answer for a claimed protocol behaviour is
describing a vendor implementation.

---

## 24.5 Volume 4 summary

1. **[SPEC]** `general-ciphering` (`0xDD`) carries transaction-id, both System
   Titles, date-time, other-information, `key-info`, and ciphered-content.
2. **[SPEC]** *"The length and the value of each field is included in the
   AAD"* — including the length octets of empty fields.
3. **[SPEC]** `key-info` is `identified-key`, `wrapped-key`, or `agreed-key`.
   Only `agreed-key` works with a third party.
4. **[SPEC]** For C(1e,1s), `key-ciphered-data` is the ephemeral public key
   **signed** with the originator's ECDSA key. Verify that signature.
5. **[SPEC]** `general-signing` (`0xDF`) signs all fields including lengths,
   with plain `R‖S` ECDSA. Sign first, then encrypt.
6. **[SPEC]** Multi-layer protection mirrors the request's protection per
   party; where the request had none and the response requires some, the server
   applies it for **all** parties.
7. In multi-layer messages, **each layer's IV uses that layer's originator.**
8. **[SPEC]** COSEM data security via "Data protection" objects protects the
   data itself, surviving removal of the message layers.
9. Even fully encrypted, a capture leaks the **service class** via the APDU
   tag, plus the suite, protection level, message rate, and counter resets.
10. The two highest-value key-free capture checks: repeated `(System Title,
    IC)` pairs, and SC values weaker than the stated policy.

---

**Next: Volume 5 — firmware module architecture, memory budgets for all three
suites, secure key storage from flash to secure element, the key provisioning
lifecycle, key rotation, and random number generation on a microcontroller.**

*End of Volume 4.*

---

← **Previous:** [Volume 3 — Keys, PKI and Key Agreement](VOL-3-Keys-PKI-and-Key-Agreement.md)  ·  **Next:** [Volume 5 — Embedded Firmware Implementation](VOL-5-Embedded-Firmware-Implementation.md) →

[Back to the index](00-INDEX.md)
