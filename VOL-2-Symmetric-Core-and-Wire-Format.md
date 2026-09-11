# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 2 — The Symmetric Core and the Wire Format**
*Chapters 7–13*

> Prerequisites: Volume 0 (claim labels and verified test vectors, which
> concern this volume directly) and Volume 1.

This is the volume that matters most. Every claim about byte layout below is
checked against the Green Book's own official test vectors, and every
numerical value shown was recomputed independently and matches.

---

# CHAPTER 7 — AES FUNDAMENTALS

## 7.1 What AES is, exactly

**[SPEC]** [GB] 9.2.3.3.3:

> *"For the purposes of DLMS/COSEM, the Advanced Encryption Standard (AES) as
> specified in FIPS PUB 197:2001 shall be used. AES operates on blocks
> (chunks) of data during an encryption or decryption operation. For this
> reason, AES is referred to as a block cipher algorithm."*
>
> *"AES encrypts and decrypts data in 128-bit blocks, using 128, 192 or 256
> bit keys. All three key sizes are adequate."*

The essential facts, and only these:

| Property | Value | Consequence for you |
|----------|-------|---------------------|
| **Block size** | **Always 128 bits (16 octets)** — regardless of key size | Your buffers align to 16. GCM's counter blocks, GHASH blocks, and key-wrap semiblocks all derive from this. |
| **Key sizes** | 128 / 192 / 256 bits | **[SPEC]** DLMS uses **128** (suites 0, 1) and **256** (suite 2). 192 is never used. |
| **Rounds** | 10 (AES-128), 12 (AES-192), 14 (AES-256) | AES-256 is ~40% more work per block, not 2×. |
| **Structure** | Substitution–permutation network | Not a Feistel network. Encryption and decryption use *different* code paths. |

**The block size / key size distinction is worth dwelling on** because it is
a common confusion: AES-256 does **not** encrypt 256-bit blocks. It encrypts
128-bit blocks using a 256-bit key. Suite 2 does not change any block
alignment anywhere in DLMS — only key lengths.

---

## 7.2 What happens inside, at the depth you need

One AES encryption transforms a 16-byte block using the key, through a fixed
number of rounds. The block is held as a 4×4 byte matrix called the **state**,
filled column-wise:

```
   input bytes:  b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 b10 b11 b12 b13 b14 b15

   state:        ┌─────┬─────┬─────┬─────┐
                 │ b0  │ b4  │ b8  │ b12 │
                 ├─────┼─────┼─────┼─────┤
                 │ b1  │ b5  │ b9  │ b13 │
                 ├─────┼─────┼─────┼─────┤
                 │ b2  │ b6  │ b10 │ b14 │
                 ├─────┼─────┼─────┼─────┤
                 │ b3  │ b7  │ b11 │ b15 │
                 └─────┴─────┴─────┴─────┘
```

Each round applies four transformations:

```
  ┌──────────────┬──────────────────────────────────────────────────┐
  │ SubBytes     │ Substitution. Each byte replaced via the S-box.  │
  │              │ Non-linear — this is what resists algebraic      │
  │              │ attack.                                          │
  ├──────────────┼──────────────────────────────────────────────────┤
  │ ShiftRows    │ Permutation. Row r rotated left by r bytes.      │
  │              │ Diffuses across columns.                         │
  ├──────────────┼──────────────────────────────────────────────────┤
  │ MixColumns   │ Each column multiplied by a fixed matrix in      │
  │              │ GF(2⁸). Diffuses within columns.                 │
  │              │ (Omitted in the final round.)                    │
  ├──────────────┼──────────────────────────────────────────────────┤
  │ AddRoundKey  │ XOR with the round key from the key schedule.    │
  │              │ The ONLY place the key enters.                   │
  └──────────────┴──────────────────────────────────────────────────┘
```

**[THEORY]** *Substitution* provides confusion — the relationship between key
and ciphertext is complex. *Permutation* and MixColumns provide diffusion — one
input bit affects every output bit after two rounds. Confusion and diffusion
together are what a block cipher is.

**Why you need this much and no more:** AES-GCM never calls AES decryption.
Not once. Understanding that requires knowing that AES is a keyed permutation
of 128-bit blocks; it does not require knowing the S-box.

---

## 7.3 The critical property that makes modes necessary

**[SPEC]** [GB] 9.2.3.3.4, quoting NIST SP 800-21:

> *"With a symmetric key block cipher algorithm, the same plaintext block will
> always encrypt to the same ciphertext block when the same symmetric key is
> used. If the multiple blocks in a typical message (data stream) are
> encrypted separately, an adversary could easily substitute individual
> blocks, possibly without detection. Furthermore, certain kinds of data
> patterns in the plaintext, such as repeated blocks, would be apparent in the
> ciphertext."*

That is the ECB failure. Two identical GET requests would produce byte-identical
ciphertext, leaking the fact that they are the same request.

**[SPEC]** The fix, same clause:

> *"Cryptographic modes of operation have been defined to address this problem
> by combining the basic cryptographic algorithm with variable initialization
> values (commonly known as initialization vectors) and feedback rules."*

And DLMS's specific selection:

> **[SPEC]** *"NIST SP 800-38D specifies the Galois/Counter Mode (GCM), an
> algorithm for authenticated encryption with associated data, and its
> specialization, GMAC, for generating a message authentication code (MAC) on
> data that is not encrypted."* — [GB] 9.2.3.3.4

---

## 7.4 Firmware notes on AES [IMPL]

| Concern | Guidance |
|---------|----------|
| **Hardware acceleration** | Most modern metering MCUs have an AES peripheral. Check whether it supports GCM natively or only ECB/CBC. If ECB only, you get the block cipher accelerated and must implement GHASH in software — that is the usual case and it is fine. |
| **Key schedule caching** | Expanding a 128-bit key into 11 round keys costs ~176 bytes RAM and non-trivial cycles. Expand once per key, not once per block. Hardware AES units usually do this internally. |
| **Software S-box and cache timing** | On a Cortex-M there is no data cache, so classic cache-timing attacks on table-based AES do not apply. **[INFER]** On a Cortex-A (e.g. a concentrator) they do — use the crypto extensions or a bitsliced implementation. |
| **Decryption path** | **You almost certainly do not need it.** GCM uses only the forward direction. AES key unwrap does need the inverse cipher. If you implement only suite 0 with no key wrap, you can omit AES decryption entirely and save flash. |

---

# CHAPTER 8 — AES-GCM IN EXTREME DEPTH

## 8.1 What GCM is

**[SPEC]** [GB] 9.2.3.3.7.1, from NIST SP 800-38D:

> *"Galois/Counter Mode (GCM) is an algorithm for authenticated encryption
> with associated data. GCM is constructed from an approved symmetric key
> block cipher with a block size of 128 bits, such as the Advanced Encryption
> Standard (AES) algorithm … Thus, GCM is a mode of operation of the AES
> algorithm."*
>
> *"GCM provides assurance of the confidentiality of data using a variation of
> the Counter mode of operation for encryption."*
>
> *"GCM provides assurance of the authenticity of the confidential data … using
> a universal hash function that is defined over a binary Galois (i.e. finite)
> field (GHASH). GCM can also provide authentication assurance for additional
> data (of practically unlimited length per invocation) that is not
> encrypted."*
>
> *"If the GCM input is restricted to data that is not to be encrypted, the
> resulting specialization of GCM, called GMAC, is simply an authentication
> mode on the input data."*

Four sentences, four facts:

1. GCM = authenticated encryption with associated data (AEAD).
2. Confidentiality comes from **CTR mode**.
3. Authenticity comes from **GHASH**, a hash over a finite field.
4. **GMAC is GCM with nothing to encrypt.** Not a different algorithm — a
   restriction of the same one.

That fourth point is the source of endless confusion, so let me state it as a
rule: **GMAC is GCM where the plaintext is empty and everything is associated
data.** Quality Rule 5 in your prompt says never confuse AES-GCM with GMAC;
the precise relationship is that GMAC ⊂ GCM.

---

## 8.2 The two functions

**[SPEC]** [GB] 9.2.3.3.7.2, based on NIST SP 800-38D 5.2:

> *"The two functions that comprise GCM are called authenticated encryption and
> authenticated decryption. … The authenticated encryption function encrypts
> the confidential data and computes an authentication tag on both the
> confidential data and any additional, non-confidential data. The
> authenticated decryption function decrypts the confidential data, contingent
> on the verification of the tag."*

```
   AUTHENTICATED ENCRYPTION              AUTHENTICATED DECRYPTION

        P          A                          C     T     A
        │          │                          │     │     │
        ▼          ▼                          ▼     ▼     ▼
   ┌─────────────────────┐              ┌─────────────────────┐
   │  AES Galois/Counter │              │  AES Galois/Counter │
EK─┤  mode authenticated ├─          EK─┤  mode authenticated ├─
   │     encryption      │              │     decryption      │
IV─┤                     │           IV─┤                     │
   └──────┬───────┬──────┘              └──────────┬──────────┘
          │       │                                │
          ▼       ▼                        ┌───────┴───────┐
          C       T                        ▼               ▼
                                           P             FAIL
```

**[SPEC]** *"The output P indicates that T is the correct authentication tag
for IV, A, and C; otherwise, the output is FAIL."*

**[IMPL] The single most important consequence for firmware:** decryption is
*contingent on* tag verification. The correct API returns either plaintext or
FAIL, never both. If your `gcm_decrypt()` hands back plaintext alongside a
separate boolean the caller might forget to check, you have built a footgun.
See §8.7.

---

## 8.3 The five inputs and two outputs

```
                  ┌───────────────────────────────┐
     EK  ────────►│                               │
     (block       │                               │
      cipher key) │                               │
                  │                               │
     IV  ────────►│         AES-GCM               │──────► C (ciphertext)
     (12 octets   │      authenticated            │        len(C) = len(P)
      in DLMS)    │        encryption             │
                  │                               │──────► T (tag)
     P   ────────►│                               │        96 bits in DLMS
     (plaintext,  │                               │
      encrypted)  │                               │
                  │                               │
     A   ────────►│                               │
     (AAD,        └───────────────────────────────┘
      authenticated but NOT encrypted)
```

| Input | Encrypted? | Authenticated? | Transmitted? |
|-------|------------|----------------|--------------|
| **EK** | — | — | **Never** |
| **IV** | No | Implicitly (bound into the computation) | Partly — the IC is transmitted; the System Title may be |
| **P** | **Yes** → becomes C | Yes | As ciphertext |
| **A** | **No** | **Yes** | **Depends** — see below |

**The A row is where DLMS gets interesting.** In most AEAD protocols the
associated data is a header that travels on the wire. In DLMS, **the
authentication key is placed in A** — and the AK is a secret that is never
transmitted. That is unusual, deliberate, and explained in §9.3.

---

## 8.4 Inside GCM — the actual mechanics

Now the internals, with real numbers from [GB] Table 40. Every value below was
computed independently and reproduces the Green Book's published output.

### Step 1 — Derive the hash subkey H

```
   H = AES-Encrypt(EK, 0¹²⁸)
```

Encrypt an all-zero block with the key. That is the entire derivation.

With [GB] Table 40's `EK = 000102030405060708090A0B0C0D0E0F`:

```
   H = C6A13B37878F5B826F4F8162A1C8D879
```

**[THEORY] Why H must never leak.** GHASH is a polynomial evaluation at the
point H. If an attacker learns H, they can solve for the tag of any message
without the key — total forgery. H is derived from the key, so it is as
sensitive as the key. **[IMPL]** In firmware: clear the H table from RAM after
use, and never expose it through a debug interface. If you precompute GHASH
multiplication tables (the usual 4-bit or 8-bit optimisation), those tables are
equally sensitive and considerably larger.

### Step 2 — Build the pre-counter block J0

**[THEORY]** When `len(IV) == 96 bits` — which **[SPEC]** is always true in
DLMS — J0 is simply:

```
   J0 = IV ‖ 0³¹ ‖ 1        i.e. the 12-octet IV followed by 00 00 00 01
```

With Table 40's IV:

```
   IV = 4D4D4D0000BC614E 01234567
        └── System Title ┘ └─ IC ─┘

   J0 = 4D4D4D0000BC614E 01234567 00000001
```

**[THEORY] Why the 96-bit case is special and why it matters.** For any other
IV length, J0 must be computed by GHASHing the IV — extra work, extra code, and
a real risk of collision between different-length IVs. By fixing `len(IV) = 96`,
DLMS gets the fast path, the simple path, and eliminates a class of bug.
**[IMPL]** If your GCM implementation supports arbitrary IV lengths, you can
delete that path for DLMS — but do not delete the *length check*.

### Step 3 — Generate the keystream (CTR encryption)

The counter starts at J0 and is incremented for each plaintext block. The
32-bit rightmost field increments; the leading 96 bits stay fixed.

```
   CB₁ = inc32(J0) = 4D4D4D0000BC614E 01234567 00000002
   CB₂ = inc32(CB₁)= 4D4D4D0000BC614E 01234567 00000003
   ...

   keystream_i = AES-Encrypt(EK, CB_i)
   C_i         = P_i XOR keystream_i
```

**Note J0 itself is not used for the keystream — it is reserved for the tag.**
The keystream starts at `inc32(J0)`.

Working it through with Table 40's data:

```
   CB₁         = 4D4D4D0000BC614E0123456700000002
   AES(EK,CB₁) = 811212FF9B5A475768273B65BC1E9EF8    ← keystream block 1

   P (the APDU)= C0010000080000010000FF0200         (13 octets)
   keystream   = 811212FF9B5A475768273B65 BC         (first 13 octets)
   XOR         = ─────────────────────────────
   C           = 411312FF935A47566827C467BC          ✅ matches [GB] Table 40
```

**Three properties fall directly out of this:**

1. **`len(C) == len(P)`.** No padding, no expansion. A 13-octet APDU produces
   13 octets of ciphertext. Your buffers do not grow.
2. **AES decryption is never called.** Decryption regenerates the *same*
   keystream and XORs again. `(P ⊕ ks) ⊕ ks = P`. Encryption and decryption
   are literally the same code path.
3. **The final block is truncated, not padded.** Only the needed keystream
   bytes are used.

**[THEORY] And now the nonce-reuse catastrophe becomes mechanical rather than
abstract.** The keystream depends on `(EK, IV)` and nothing else — not on the
plaintext, not on the AAD. Two messages under the same `(EK, IV)` get the
*identical* keystream. Their ciphertexts XORed together yield the two
plaintexts XORed together, with the key entirely absent from the result. See
Chapter 10.

### Step 4 — GHASH over AAD and ciphertext

```
   S = GHASH_H( A ‖ pad(A) ‖ C ‖ pad(C) ‖ [len(A)]₆₄ ‖ [len(C)]₆₄ )
```

GHASH processes 128-bit blocks. Each block is XORed into an accumulator and
the accumulator is multiplied by H in GF(2¹²⁸):

```
   X₀ = 0
   X_i = (X_{i-1} XOR block_i) · H     in GF(2¹²⁸), reduction poly
                                        x¹²⁸ + x⁷ + x² + x + 1
   S  = X_n
```

Three details that cause interoperability bugs [IMPL]:

- **A and C are each zero-padded to a 16-octet boundary**, independently. Do
  not concatenate first and pad once.
- **The final block encodes the bit-lengths**, not byte-lengths: 64 bits for
  `len(A)` then 64 bits for `len(C)`, both big-endian.
- **GF(2¹²⁸) multiplication is bit-reflected** relative to the naive
  convention. Getting the bit order wrong produces a tag that is wrong but
  *plausible* — the classic hard-to-find GCM bug. If your GHASH is wrong, the
  Table 40 vector catches it instantly.

### Step 5 — Produce the tag

```
   T = MSB_t( GCTR(EK, J0, S) )  =  MSB_t( S XOR AES-Encrypt(EK, J0) )
```

Here is where J0 is used: it encrypts to a mask that is XORed onto the GHASH
result, and the result is truncated to `t` bits.

With Table 40's material:

```
   AES(EK, J0) = D1D9A5C91B418C59777E5EC57C1DC609    ← the tag mask
   S           = (GHASH output)
   T           = MSB₉₆( S XOR D1D9A5C9... )
```

**[SPEC]** [GB] 9.2.3.3.7.6:

> *"The bit length of the authentication tag, denoted t, is a security
> parameter. In security suites 0, 1 and 2 its value shall be 96 bits."*

**96 bits = 12 octets, in all three suites.** Not 128. This trips people up
constantly, because most GCM libraries default to a 16-octet tag.

**[THEORY] Why the mask matters.** Without `AES(EK, J0)`, the tag would be a
raw GHASH output — and GHASH is a *linear* function of its input. An attacker
who saw a few tags could solve for H by linear algebra. The AES-based mask
destroys that linearity.

**[IMPL] Truncation direction.** Take the **most significant** 96 bits — the
*first* 12 octets of the 16-octet tag. Taking the last 12 is a real bug I have
seen; it produces consistent-but-wrong tags that only fail against a real peer.

---

## 8.5 The complete data flow, one picture

```
     EK ──────────────────────────────────────────────────────────┐
      │                                                            │
      ├──► AES(EK, 0¹²⁸) ──► H (hash subkey)                      │
      │                       │                                    │
 IV ──┼──► J0 = IV‖0³¹‖1 ─────┼──────────────► AES(EK,J0) ──┐     │
 (12) │      │                │                              │     │
      │      ▼                │                              │     │
      │   inc32 ──► CB₁,CB₂...│                              │     │
      │      │                │                              │     │
      │      ▼                │                              │     │
      └──► AES(EK,CBᵢ) ──► keystream                         │     │
                  │                                           │     │
   P ────────────►XOR────────► C ────┐                        │     │
                                     │                        │     │
   A ───────────────────────────────►│                        │     │
                                     ▼                        ▼     │
                    GHASH_H( A‖pad ‖ C‖pad ‖ len(A)‖len(C) )  │     │
                                     │                        │     │
                                     └────────► XOR ◄─────────┘     │
                                                 │                  │
                                                 ▼                  │
                                          MSB₉₆( · ) = T ───────────┘
```

---

## 8.6 GMAC — the authentication-only specialisation

Set `P = ∅`. Then:

- No keystream is consumed for encryption. `C = ∅`.
- GHASH runs over `A ‖ pad(A) ‖ [len(A)]₆₄ ‖ [0]₆₄`.
- The tag is produced exactly as before.

```
     GCM  with P ≠ ∅   →  outputs C and T
     GCM  with P = ∅   →  outputs only T          ← this is GMAC
```

**[SPEC]** [GB] 9.2.3.3.5: *"For the purposes of DLMS/COSEM, the GMAC
algorithm as specified in 9.2.3.3.7.2 shall be used."*

**This is precisely where implementations go wrong.** It
places the challenge in `P`. The Green Book places it in `A`. Chapter 9 proves
it against the official vector.

**[IMPL]** You do not need a separate GMAC implementation. Call your GCM
encrypt with a zero-length plaintext. If your API cannot accept an empty
plaintext, fix the API — do not write a second code path.

---

## 8.7 Tag verification — the rule that must never be broken

**[SPEC]** [GB] 9.2.2.5:

> *"A request or response received shall be processed only if the protection on
> the message carrying the request or response could be successfully verified
> and removed."*

**[IMPL]** Three requirements:

**1. Constant-time comparison.** Never `memcmp`. A comparison that returns
early on the first differing byte leaks, through timing, how many leading bytes
were correct — turning a 2⁹⁶ forgery search into a 12 × 256 search.

```c
/* Constant-time tag comparison. Returns 0 if equal. */
static int ct_memcmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= (uint8_t)(a[i] ^ b[i]);
    return (int)diff;          /* single branch, after the whole loop */
}
```

**2. Never release unverified plaintext.** Decrypt into a scratch buffer; only
after the tag verifies do you hand it to the APDU parser. Releasing unverified
plaintext turns your parser into a decryption oracle: an attacker submits
modified ciphertexts and learns about the plaintext from how your parser
misbehaves.

```c
/* WRONG — parser sees attacker-controlled garbage */
gcm_decrypt(ctx, ct, len, pt);
parse_apdu(pt, len);                 /* ← already too late */
if (!tag_ok) return ERR;

/* RIGHT */
if (gcm_decrypt_verify(ctx, ct, len, tag, pt) != OK) {
    secure_zero(pt, len);
    return ERR_TAG_MISMATCH;         /* nothing downstream ever sees it */
}
parse_apdu(pt, len);
```

**3. Wipe on failure.** Zero the scratch buffer, so a later bug cannot expose
partially-decrypted attacker-chosen data.

---

# CHAPTER 9 — DLMS-SPECIFIC AES-GCM AND THE SECURITY CONTROL BYTE

## 9.1 The security header

**[SPEC]** [GB] 9.2.7.2.4.2:

> *"The security header SH includes the security control byte concatenated
> with the invocation counter: SH = SC ‖ IC."*

```
   ┌────────┬──────────────────────────┐
   │   SC   │           IC             │
   │ 1 octet│        4 octets          │      SH = 5 octets
   └────────┴──────────────────────────┘
```

Five octets, at the head of every ciphered APDU's protected content. If you can
parse those five octets you can determine everything about how the rest is
protected.

---

## 9.2 The Security Control byte — bit by bit

### 9.2.1 The authoritative layout

**[SPEC]** [GB] Table 37 and 9.2.7.2.4.2:

> - *Bit 3…0: Security_Suite_Id, see 9.2.3.7;*
> - *Bit 4: "A" subfield: indicates that authentication is applied;*
> - *Bit 5: "E" subfield: indicates that encryption is applied;*
> - *Bit 6: Key_Set subfield: 0 = Unicast, 1 = Broadcast;*
> - *Bit 7: Indicates the use of compression.*

```
    MSB                                                       LSB
   ┌───────┬─────────┬───────┬───────┬───────────────────────────┐
   │ bit 7 │  bit 6  │ bit 5 │ bit 4 │      bits 3 · 2 · 1 · 0   │
   ├───────┼─────────┼───────┼───────┼───────────────────────────┤
   │ Compr │ Key_Set │   E   │   A   │    Security_Suite_Id      │
   └───────┴─────────┴───────┴───────┴───────────────────────────┘
       │        │        │       │                 │
       │        │        │       │                 └─ 0000 = Suite 0
       │        │        │       │                    0001 = Suite 1
       │        │        │       │                    0010 = Suite 2
       │        │        │       │                    others reserved
       │        │        │       └─ 1 = authentication applied (tag present)
       │        │        └────────── 1 = encryption applied
       │        └─────────────────── 0 = unicast key (GUEK)
       │                             1 = broadcast key (GBEK)
       └──────────────────────────── 1 = V.44 compression applied
```

> ⚠️ **Read the bit layout from [GB] Table 37, not from memory.** The suite
> ID is the low nibble; compression is bit 7.
> The guide places the suite ID in bits 7–6 and compression in bit 2. It is
> wrong, and it produces incorrect decodes for every value involving broadcast,
> compression, or suites 1/2.

**[SPEC]** One constraint on Key_Set, [GB] Table 37 note:

> *"The Key_Set bit is not relevant and shall be set to 0 when the
> service-specific dedicated ciphering, the general-ded-ciphering or the
> general-ciphering APDUs are used."*

**[INFER] Why:** dedicated ciphering by definition uses the dedicated key, and
`general-ciphering` carries its key selection explicitly in the `key-info`
field. In both cases a unicast/broadcast bit would be ambiguous, so it is
forced to zero.

### 9.2.2 Decoding every value the prompt asked for

Bit-by-bit, as required by the byte-level engineering rule.

---

**`0x10`**

```
   0x10 = 0001 0000
          │││└┴┴┴┴──── bits 3..0 = 0000 → Security Suite 0
          ││└───────── bit 4  A  = 1    → AUTHENTICATION applied
          │└────────── bit 5  E  = 0    → no encryption
          └─────────── bit 6 Key = 0    → unicast key (GUEK)
        bit 7 Compr    = 0              → no compression
```

| Field | Value |
|-------|-------|
| Suite | 0 — AES-GCM-128 |
| Protection | **Authentication only** |
| Key used | Global **Unicast** Encryption Key (as GCM block cipher key) + GAK in the AAD |
| Plaintext `P` | **∅** (empty) |
| AAD `A` | `SC ‖ AK ‖ Information` |
| APDU content | `SC ‖ IC ‖ unprotected-APDU ‖ T` |
| On the wire | **The APDU is readable.** Only integrity is protected. |

This is the value used by **HLS mechanism 5** — see [GB] Table 43.

---

**`0x20`**

```
   0x20 = 0010 0000
          │││└┴┴┴┴──── Suite 0
          ││└───────── A = 0  → no authentication
          │└────────── E = 1  → ENCRYPTION applied
          └─────────── Key_Set = 0 → unicast
```

| Field | Value |
|-------|-------|
| Protection | **Encryption only** |
| Plaintext `P` | the APDU |
| AAD `A` | **null** — [GB] Table 38 |
| APDU content | `SC ‖ IC ‖ ciphertext` — **no tag** |
| Security | ⚠️ **Malleable.** No integrity. See Volume 1 §3.2 Case B. |

**[IMPL] Do not deploy this.** It exists for specification completeness.

---

**`0x30`**

```
   0x30 = 0011 0000
          │││└┴┴┴┴──── Suite 0
          ││└───────── A = 1  → authentication
          │└────────── E = 1  → encryption
          └─────────── Key_Set = 0 → unicast
```

| Field | Value |
|-------|-------|
| Protection | **Authenticated encryption** ★ |
| Plaintext `P` | the APDU |
| AAD `A` | `SC ‖ AK` |
| APDU content | `SC ‖ IC ‖ ciphertext ‖ T` |

**This is the correct default for production.** Note that the AAD here is *not*
`SC ‖ AK ‖ APDU` — the APDU is in `P`, and GCM already authenticates the
ciphertext internally. Putting it in `A` as well would be redundant work.

---

**`0x50`**

```
   0x50 = 0101 0000
          │││└┴┴┴┴──── bits 3..0 = 0000 → Suite 0
          ││└───────── A = 1  → authentication
          │└────────── E = 0  → no encryption
          └─────────── bit 6 Key_Set = 1 → BROADCAST key (GBEK)
```

| Field | Value |
|-------|-------|
| Suite | **0** (not 1 — read the low nibble, not the top two bits) |
| Protection | Authentication only |
| Key used | Global **Broadcast** Encryption Key (GBEK) |

**[INFER] Where you meet this:** a head-end sending one authenticated
`event-notification` or `DataNotification` to a whole population of meters
under a shared broadcast key. Authentication-only is a sensible choice for
broadcast — the content is not usually secret, but its origin must be
verifiable.

---

**`0x70`**

```
   0x70 = 0111 0000
          │││└┴┴┴┴──── Suite 0
          ││└───────── A = 1  → authentication
          │└────────── E = 1  → encryption
          └─────────── Key_Set = 1 → BROADCAST key
```

Authenticated encryption using the **broadcast** key, suite 0.

**[INFER] A security caution about broadcast confidentiality:** the GBEK is by
construction shared across every meter in the group. "Encrypted" here means
"unreadable by outsiders", not "unreadable by other meters". Any compromised
meter in the group can decrypt every broadcast. Do not send anything
device-specific or sensitive under a broadcast key.

---

**`0xB0`**

```
   0xB0 = 1011 0000
          │││└┴┴┴┴──── Suite 0
          ││└───────── A = 1  → authentication
          │└────────── E = 1  → encryption
          └─────────── Key_Set = 0 → unicast
        bit 7 = 1                   → COMPRESSION applied
```

| Field | Value |
|-------|-------|
| Protection | Compression + authenticated encryption, unicast, Suite 0 |
| Order | **[SPEC]** Compress **first**, then encrypt — [GB] Figures 83, 84 |

**[SPEC]** The compression algorithm, [GB] 9.2.3.6:

> *"The compression algorithm shall be as specified in ITU-T V.44: 2000."*

selected for *"low processing load; low memory requirements; low latency"*.

**[SPEC]** Note also that compression is only available on the **general**
ciphering APDUs. [GB] Table 36's Compression column shows `–` for
service-specific glo/ded-ciphering and `Yes` for general-glo / general-ded /
general-ciphering. So `0xB0` cannot legitimately appear inside a `glo-get-request`.

**[THEORY] A security caution.** Compressing before encrypting leaks
information through ciphertext length — the CRIME/BREACH class of attack. If
an attacker can influence part of the plaintext and observe the compressed
length, they can learn about the rest. **[INFER]** In DLMS the attacker's
ability to inject chosen plaintext into a meter's response is limited, so the
practical risk is low — but if you do not need the bandwidth saving, leave
compression off.

---

### 9.2.3 Additional values you will meet

| SC | Binary | Suite | Compr | Key | E | A | Meaning |
|----|--------|-------|-------|-----|---|---|---------|
| `0x00` | `0000 0000` | 0 | – | uni | 0 | 0 | No protection. Legal only in `general-ciphering` ([GB] Figure 84). |
| `0x10` | `0001 0000` | 0 | – | uni | 0 | 1 | Authentication only |
| `0x20` | `0010 0000` | 0 | – | uni | 1 | 0 | Encryption only |
| `0x30` | `0011 0000` | 0 | – | uni | 1 | 1 | **Authenticated encryption ★** |
| `0x31` | `0011 0001` | **1** | – | uni | 1 | 1 | Authenticated encryption, **Suite 1** |
| `0x32` | `0011 0010` | **2** | – | uni | 1 | 1 | Authenticated encryption, **Suite 2** (AES-256) |
| `0x50` | `0101 0000` | 0 | – | **bcast** | 0 | 1 | Authentication only, broadcast |
| `0x70` | `0111 0000` | 0 | – | **bcast** | 1 | 1 | Auth. encryption, broadcast |
| `0x90` | `1001 0000` | 0 | **yes** | uni | 0 | 1 | Compression + authentication |
| `0xA0` | `1010 0000` | 0 | **yes** | uni | 1 | 0 | Compression + encryption |
| `0xB0` | `1011 0000` | 0 | **yes** | uni | 1 | 1 | Compression + auth. encryption |
| `0xF2` | `1111 0010` | **2** | yes | bcast | 1 | 1 | Everything on, Suite 2 |

**[IMPL] Decoder, complete:**

```c
typedef struct {
    uint8_t suite;        /* bits 3..0 */
    bool    authenticated;/* bit 4     */
    bool    encrypted;    /* bit 5     */
    bool    broadcast;    /* bit 6     */
    bool    compressed;   /* bit 7     */
} sec_control_t;

static inline void sc_decode(uint8_t sc, sec_control_t *out)
{
    out->suite         =  sc        & 0x0Fu;
    out->authenticated = (sc >> 4)  & 0x01u;
    out->encrypted     = (sc >> 5)  & 0x01u;
    out->broadcast     = (sc >> 6)  & 0x01u;
    out->compressed    = (sc >> 7)  & 0x01u;
}

static inline uint8_t sc_encode(const sec_control_t *in)
{
    return (uint8_t)( (in->suite & 0x0Fu)
                    | (in->authenticated ? 0x10u : 0u)
                    | (in->encrypted     ? 0x20u : 0u)
                    | (in->broadcast     ? 0x40u : 0u)
                    | (in->compressed    ? 0x80u : 0u) );
}
```

**[IMPL] Validation you must perform on a received SC:**

```c
/* 1. Suite must be one you support. [GB] Table 19: all others reserved. */
if (sc.suite > 2u || sc.suite != ctx->suite)   return ERR_WRONG_SUITE;

/* 2. Suite must match the negotiated security context — an attacker
      must not be able to downgrade you to a weaker suite per-APDU.   */

/* 3. Protection must MEET OR EXCEED policy AND access rights.
      [GB] 9.2.7.2.2: more is allowed, less is rejected.              */
if ((applied & required) != required)          return ERR_INSUFFICIENT;

/* 4. Key_Set must be 0 for ded / general-ded / general ciphering.    */
if (apdu_uses_dedicated_or_general && sc.broadcast) return ERR_MALFORMED;

/* 5. Compression must be 0 for service-specific ciphering APDUs.     */
if (apdu_is_service_specific && sc.compressed)     return ERR_MALFORMED;

/* 6. E==0 && A==0 is only legal inside general-ciphering.            */
if (!sc.encrypted && !sc.authenticated && !apdu_is_general)
                                                    return ERR_MALFORMED;
```

Check 2 is the **downgrade defence** and it is frequently missing. Without it,
an attacker who can modify the SC byte in flight could try to negotiate a
weaker suite. (In practice the tag verification would then fail — but only if
you are checking a tag at all. Check 3 covers that; check 2 is defence in
depth.)

---

## 9.3 Plaintext and AAD — the definitive table

**[SPEC]** [GB] Table 38. `SC` is the security control byte, `AK` the
authentication key, and `I` the information being protected (the xDLMS APDU or
COSEM data). `(C)` denotes optionally-compressed.

| E | A | Protection | `P` (plaintext) | `A` (AAD) — service-specific / general-glo / general-ded | `A` (AAD) — general-ciphering |
|---|---|------------|-----------------|---------------------------------|-------------------------------|
| 0 | 0 | None | – | – | – |
| 0 | 1 | **Authenticated only** | – | `SC ‖ AK ‖ (C)I` | `SC ‖ AK ‖ transaction-id ‖ originator-system-title ‖ recipient-system-title ‖ date-time ‖ other-information ‖ (C)I` |
| 1 | 0 | **Encrypted only** | `(C)I` | – (null) | – (null) |
| 1 | 1 | **Authenticated encryption** | `(C)I` | `SC ‖ AK` | `SC ‖ AK ‖ transaction-id ‖ originator-system-title ‖ recipient-system-title ‖ date-time ‖ other-information` |

**[SPEC]** Footnote to Table 38: *"The fields transaction-id … other-information
are A.XDR encoded OCTET STRINGs. The length and the value of each field is
included in the AAD."* — i.e. for `general-ciphering`, the AAD includes each
field's **length octet as well as its value**. Omitting the lengths is a common
and hard-to-diagnose interop failure.

### Reading the table — three things to internalise

**1. The Authentication Key lives in the AAD, not in the key slot.**

This is the DLMS design decision that surprises people coming from TLS. The
GCM block cipher key is the **encryption key** (GUEK/GBEK/dedicated). The
**authentication key (GAK)** is prepended to the associated data.

**[SPEC]** [GB] 9.2.3.3.7.5:

> *"In DLMS/COSEM, for additional security, an authentication key denoted AK is
> also specified. When present, it shall be part of the Additional
> Authenticated Data, AAD."*

**[INFER] Why this design?** It means an attacker who somehow obtains the
encryption key alone still cannot forge a valid tag, because the tag depends on
a second secret they do not have. It gives two-key security from a single GCM
invocation, at zero extra cryptographic cost. It is not a standard AEAD
construction — it is a DLMS-specific hardening — but it is sound: the AAD is
input to GHASH, so the tag genuinely depends on every bit of the AK.

The corollary matters just as much: **the AK is never transmitted.** It appears
in the AAD, which is *authenticated but not sent*. The receiver already has
the AK from its own security context and reconstructs the same AAD locally.
Anyone who does not have the AK cannot even *check* a tag, let alone forge one.

Quality Rule 10 in your prompt — never assume a key is transmitted simply
because a derived value exists — has its clearest illustration right here.

**2. When encrypting, the APDU is not repeated in the AAD.**

For `E=1, A=1` the AAD is just `SC ‖ AK` — 17 octets in suite 0. The APDU
itself is in `P`, and GCM's GHASH covers the ciphertext automatically. Adding
the plaintext to the AAD as well would double the GHASH work for no benefit.

**3. When authenticating only, the APDU *is* the AAD.**

For `E=0, A=1` there is nothing to encrypt, so the APDU goes into `A`. This is
GMAC. **This is the single most commonly mis-implemented point in DLMS HLS.**

---

## 9.4 The HLS-GMAC deep dive, proven against the official vector

The prompt asked for this to be one of the deepest sections. Here is the
complete construction, with every value verified.

### 9.4.1 The formula

**[SPEC]** [GB] Table 42, mechanism_id(5):

```
   Pass 3 (client → server):   f(StoC) = SC ‖ IC ‖ GMAC( SC ‖ AK ‖ StoC )
   Pass 4 (server → client):   f(CtoS) = SC ‖ IC ‖ GMAC( SC ‖ AK ‖ CtoS )
```

### 9.4.2 The official security material

**[SPEC]** [GB] Table 43:

| Item | Client | Server |
|------|--------|--------|
| Security suite | GCM-AES-128 | GCM-AES-128 |
| System Title | `4D4D4D0000000001` | `4D4D4D0000BC614E` |
| Invocation Counter | `00000001` | `01234567` |
| Initialization Vector | `4D4D4D000000000100000001` | `4D4D4D0000BC614E01234567` |
| Block cipher key EK | `000102030405060708090A0B0C0D0E0F` | *(same)* |
| Authentication Key AK | `D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF` | *(same)* |
| Security Control SC | `10` | `10` |

Challenges:

```
   CtoS = 4B35366956616759     ASCII "K56iVagY"     (8 octets)
   StoC = 503677524A323146     ASCII "P6wRJ21F"     (8 octets)
```

Note `SC = 0x10` — authentication only, suite 0, unicast, no compression.
Nothing is encrypted during HLS.

### 9.4.3 Pass 3 — the client proves itself

```
 ┌─ STEP 1 ── Build the IV from the CLIENT's own identity ─────────────┐
 │                                                                     │
 │   IV = Sys-T_client  ‖  IC_client                                   │
 │      = 4D4D4D0000000001  ‖  00000001                                │
 │      = 4D4D4D000000000100000001                    (12 octets)      │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─ STEP 2 ── Build the AAD ───────────────────────────────────────────┐
 │                                                                     │
 │   A = SC ‖ AK ‖ StoC                                                │
 │                                                                     │
 │       10                                    ← SC          (1 octet) │
 │       D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF      ← AK         (16 octets)│
 │       503677524A323146                      ← StoC        (8 octets)│
 │                                                                     │
 │   A = 10 D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF 503677524A323146          │
 │                                                          (25 octets)│
 └─────────────────────────────────────────────────────────────────────┘

 ┌─ STEP 3 ── Plaintext is EMPTY ──────────────────────────────────────┐
 │                                                                     │
 │   P = ∅          ← this is what makes it GMAC and not GCM           │
 │   C = ∅          ← nothing encrypted, nothing to transmit as C      │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─ STEP 4 ── Run AES-GCM ─────────────────────────────────────────────┐
 │                                                                     │
 │   T = MSB₉₆( GCM(EK, IV, A, ∅) )                                    │
 │     = 1A52FE7DD3E72748973C1E28                          (12 octets) │
 │                                                                     │
 │   ✅ VERIFIED — matches [GB] Table 43 exactly                       │
 └─────────────────────────────────────────────────────────────────────┘

 ┌─ STEP 5 ── Assemble f(StoC) ────────────────────────────────────────┐
 │                                                                     │
 │   f(StoC) = SC ‖ IC ‖ T                                             │
 │           = 10 00000001 1A52FE7DD3E72748973C1E28                    │
 │           = 10000000011A52FE7DD3E72748973C1E28          (17 octets) │
 │                                                                     │
 │   ✅ VERIFIED — matches [GB] Table 43 exactly                       │
 └─────────────────────────────────────────────────────────────────────┘
```

This 17-octet value is the parameter of the ACTION request invoking
`reply_to_HLS_authentication`.

### 9.4.4 What the server does on receipt

```
   1. Parse f(StoC):  SC = 10  |  IC = 00000001  |  T = 1A52...1E28

   2. Look up the CLIENT's System Title from the security context
      (learned from calling-AP-title, or previously provisioned).
      → 4D4D4D0000000001

   3. Rebuild the IV:  Sys-T_client ‖ IC_received
      → 4D4D4D000000000100000001

      ★ Note: the server uses the CLIENT's system title, not its own.
        The IV is always built from the ORIGINATOR's identity.

   4. Rebuild the AAD:  SC ‖ AK ‖ StoC
      using the StoC the SERVER itself generated and remembers.

      ★ This is the crux. The server does not trust any challenge sent
        back to it — it uses its own stored copy. An attacker who
        substitutes a different StoC gets a tag mismatch.

   5. Compute T' = GMAC(...) and compare against T in constant time.

   6. T' == T  →  the client holds EK and AK  →  authenticated.
```

### 9.4.5 Pass 4 — the server proves itself

Now everything flips to the server's identity:

```
   IV = Sys-T_server ‖ IC_server
      = 4D4D4D0000BC614E ‖ 01234567
      = 4D4D4D0000BC614E01234567

   A  = SC ‖ AK ‖ CtoS
      = 10 D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF 4B35366956616759

   P  = ∅

   T  = FE1466AFB3DBCD4F9389E2B7            ✅ matches [GB] Table 43

   f(CtoS) = SC ‖ IC ‖ T
           = 1001234567FE1466AFB3DBCD4F9389E2B7        (17 octets)

                                            ✅ matches [GB] Table 43
```

### 9.4.6 The complete exchange, one diagram

```
  CLIENT                                                      SERVER
  Sys-T = 4D4D4D0000000001                   Sys-T = 4D4D4D0000BC614E
  IC    = 00000001                           IC    = 01234567
  EK    = 000102...0E0F    ◄─── shared ───►  EK    = 000102...0E0F
  AK    = D0D1...DEDF      ◄─── shared ───►  AK    = D0D1...DEDF
     │                                                          │
     │  PASS 1  ── AARQ, calling-authentication-value ─────────► │
     │            CtoS = 4B35366956616759                        │
     │                                                           │
     │  PASS 2  ◄─ AARE, responding-authentication-value ─────── │
     │            StoC = 503677524A323146                        │
     │                                                           │
     │  client checks StoC != CtoS  ✓                            │
     │                                                           │
     │  computes:                                                │
     │    IV = 4D4D4D000000000100000001                          │
     │    A  = 10 ‖ D0D1..DEDF ‖ 503677524A323146                │
     │    T  = 1A52FE7DD3E72748973C1E28                          │
     │                                                           │
     │  PASS 3  ── ACTION reply_to_HLS_authentication ──────────►│
     │            10000000011A52FE7DD3E72748973C1E28             │
     │                                     server rebuilds with  │
     │                                     CLIENT Sys-T + rx IC  │
     │                                     and its OWN StoC  ✓   │
     │                                                           │
     │                                     computes:             │
     │                                       IV = 4D4D..01234567 │
     │                                       A  = 10‖AK‖CtoS     │
     │                                       T  = FE1466AF...E2B7│
     │                                                           │
     │  PASS 4  ◄─ ACTION response, success ────────────────────│
     │            1001234567FE1466AFB3DBCD4F9389E2B7             │
     │                                                           │
     │  client rebuilds with SERVER Sys-T + rx IC                │
     │  and its OWN CtoS  ✓                                      │
     │                                                           │
     │         ═══ MUTUAL AUTHENTICATION COMPLETE ═══            │
```

### 9.4.7 What happens when each element is wrong

| Wrong element | Symptom | Root cause | Diagnosis |
|---------------|---------|------------|-----------|
| Wrong AK | Tag mismatch on pass 3 | Key provisioning mismatch | Both sides compute over different AAD. Compare AK provisioning records. |
| Wrong EK | Tag mismatch on pass 3 | Key provisioning mismatch | EK is the block cipher key; a wrong EK gives a wrong H and a wrong mask. |
| Used server Sys-T in client's IV | Tag mismatch | Classic bug: using the *peer's* identity instead of your own for outgoing | The IV always uses the **originator's** system title. |
| IC not incremented | Peer rejects with counter error | Missing counter update | Replay protection triggers before the tag is even checked. |
| Challenge put in `P` instead of `A` | Tag mismatch, and an unexpected ciphertext field appears | The classic HLS-GMAC mistake | Your f() will be 17 + 8 = 25 octets instead of 17. |
| Tag truncated to 16 octets | Length mismatch, peer rejects | Library default | DLMS tag is **12** octets in all suites. |
| Tag truncated from the wrong end | Tag mismatch | Took LSB instead of MSB | Take the **first** 12 octets. |
| SC byte in AAD differs from SC on the wire | Tag mismatch | Built AAD with a hardcoded SC | The SC in the AAD must be the *actual* SC transmitted. |

**[INFER]** In my experience the first, third, and last rows account for the
majority of real HLS-GMAC failures. All three are invisible in a capture — the
bytes look perfectly well-formed — which is why the test-vector self-check in
Volume 0 §0.4 is worth building into your firmware as a power-on test.

---

# CHAPTER 10 — THE INITIALIZATION VECTOR AND THE INVOCATION COUNTER

This is the chapter where firmware engineers destroy otherwise correct
implementations. Read it twice.

## 10.1 The specification

**[SPEC]** [GB] 9.2.3.3.7.3:

> *"In DLMS/COSEM, for the construction of the initialization vector IV
> deterministic construction as specified in NIST SP 800-38D 8.2.1 shall be
> used: the IV is the concatenation of two fields, called the fixed field and
> the invocation field. The fixed field shall identify the physical device, or,
> more generally, the (security) context for the instance of the authenticated
> encryption function. The invocation field shall identify the sets of inputs
> to the authenticated encryption function in that particular device."*
>
> *"**For any given key, no two distinct physical devices shall share the same
> fixed field, and no two distinct sets of inputs to any single device shall
> share the same invocation field.**"*
>
> *"The length of the IV shall be 96 bits (12 octets): len(IV) = 96. Within
> this:*
> - *the leading (i.e. the leftmost) 64 bits (8 octets) shall hold the fixed
>   field. It shall contain the system title, see 4.3.4;*
> - *the trailing (i.e. the rightmost) 32 bits shall hold the invocation field.
>   The invocation field shall be an integer counter."*

```
   ┌──────────────────────────────────┬────────────────────┐
   │      FIXED FIELD  (64 bits)      │ INVOCATION (32 bit)│
   │        = System Title            │  = Invocation Ctr  │
   ├──────────────────────────────────┼────────────────────┤
   │   4D 4D 4D 00 00 BC 61 4E        │   01 23 45 67      │
   └──────────────────────────────────┴────────────────────┘
    ◄────────── uniqueness across ─────►◄─ uniqueness within ─►
                  DEVICES                      one device
```

The bolded sentence is the whole security requirement, split into two halves:

- **Across devices**: the System Title guarantees no two meters collide.
- **Within a device**: the Invocation Counter guarantees no two messages
  collide.

Break either half and GCM breaks completely.

---

## 10.2 The counter rules, exactly as specified

**[SPEC]** [GB] 9.2.3.3.7.3:

> *"For each encryption key EK (i.e. block cipher key) an invocation counter
> (IC) is maintained **separately for the authenticated encryption and the
> authenticated decryption function**. The following rules apply:*
>
> - *when the key is established the corresponding ICs are reset to 0;*
> - *when the authenticated encryption function is used, the corresponding IC
>   is used then it is incremented by 1. However, when the maximum value of the
>   IC has been reached, any following invocation of the authenticated
>   encryption function shall return an error and the IC shall not be
>   incremented;*
> - *when the authenticated decryption function is used, the value of the IC is
>   verified. Verification of the IC fails — and with this, the authenticated
>   decryption function fails — if the value being verified is smaller than the
>   lowest acceptable value. If the verification is successful the lowest
>   acceptable value is set to the value of the IC verified plus 1. If the value
>   being verified is equal to the maximum value, the authenticated decryption
>   function shall return an error."*
>
> *"NOTE The maximal number of invocations is 2³²-1."*

Formalised:

```
   ─── TRANSMIT PATH ───────────────────────────────────────────────
   if (ic_tx == 0xFFFFFFFF)  return ERROR;     /* exhausted, no wrap */
   iv = sys_title_self ‖ ic_tx;
   gcm_encrypt(...);
   ic_tx = ic_tx + 1;                          /* USE then INCREMENT */

   ─── RECEIVE PATH ────────────────────────────────────────────────
   if (ic_rx == 0xFFFFFFFF)   return ERROR;    /* exhausted           */
   if (ic_rx <  ic_rx_floor)  return ERROR;    /* REPLAY DETECTED     */
   iv = sys_title_peer ‖ ic_rx;
   if (gcm_decrypt_verify(...) != OK) return ERROR;
   ic_rx_floor = ic_rx + 1;                    /* advance ONLY on     */
                                               /* successful verify   */
```

### Four details that are easy to get wrong

**1. Use-then-increment, not increment-then-use.** The first message after key
establishment carries IC = 0? **[SPEC]** The specification says the IC is reset
to 0 on key establishment and *"the corresponding IC is used then it is
incremented"* — so yes, the first transmitted IC is 0.

**[VENDOR]** In practice, many implementations start at 1. Since the receiver
only requires monotonic increase from its floor of 0, both interoperate. Do not
assume either.

**2. `<` not `<=`.** Verification fails if the received value is *smaller than*
the floor. Equal to the floor is **acceptable** — because the floor is set to
*last_good + 1*, so "equal to floor" means "exactly the next expected value".
Using `<=` would reject every valid message.

**3. Gaps are permitted.** If the floor is 100 and IC = 250 arrives, that is
valid; the floor becomes 251. This tolerates lost messages on lossy links —
essential for PLC and RF mesh. It also means an attacker who can inject one
message with IC = 0xFFFFFFFE can **permanently disable** the association by
exhausting the counter space. **[IMPL]** Consider a sanity window: reject
values more than N ahead of the floor. **[SPEC]** Note this is *not* specified
behaviour and could break interoperability on very lossy links — [GB]
9.2.2.5's NOTE 1 explicitly leaves room for it: *"Project specific companion
specifications may specify additional criteria for accepting and processing
messages."*

**4. Advance the floor only after the tag verifies.** If you advance on a
message whose tag then fails, an attacker who injects garbage with a high IC
desynchronises you from the legitimate peer. Order: check IC → decrypt →
verify tag → *then* advance.

---

## 10.3 The catastrophe: nonce reuse

**[THEORY]** Recall from §8.4 that the keystream depends only on `(EK, IV)`.

```
   Message 1:   C₁ = P₁ XOR keystream(EK, IV)
   Message 2:   C₂ = P₂ XOR keystream(EK, IV)      ← same IV!

   Attacker computes:
       C₁ XOR C₂ = (P₁ XOR ks) XOR (P₂ XOR ks)
                 = P₁ XOR P₂                        ← key eliminated
```

The attacker now holds the XOR of two plaintexts. Against DLMS APDUs this is
close to a full break, because APDUs are highly structured and predictable:

```
   P₁ = C0 01 00 00 08 00 00 01 00 00 FF 02 00   (GET Clock time)
                └──────────────────────┴─ known OBIS code
   P₂ = C0 01 00 01 01 00 63 01 00 FF 02 00 ...  (GET energy register)

   Knowing P₁ entirely → P₂ = (P₁ XOR P₂) XOR P₁  → fully recovered
```

**And it is worse than confidentiality loss.** In GCM specifically, IV reuse
under a fixed key allows an attacker with two ciphertext/tag pairs to solve for
the **authentication subkey H** — because the two tags give two equations in
the same unknown over GF(2¹²⁸). Once H is known, the attacker can forge valid
tags for arbitrary messages. That is a complete break of authenticity as well.

The academic name is the "forbidden attack". It is not theoretical; it has been
demonstrated against real TLS deployments.

**Summary of consequences:**

| Broken property | How |
|-----------------|-----|
| Confidentiality | XOR of plaintexts recovered; structured data yields both |
| Integrity | H recovered → arbitrary tag forgery |
| Authenticity | Same as above — attacker can produce APDUs that verify |
| Replay protection | Meaningless once forgery is possible |

**Everything the security architecture provides is lost.** This is why the
counter is not a housekeeping detail.

---

## 10.4 Correct and dangerous firmware patterns

### 10.4.1 The dangerous pattern

```c
/* ══════ DANGEROUS — DO NOT DO THIS ══════ */
void security_init(void)
{
    ctx.ic_tx = 0;              /* ← counter reset on every boot */
    ctx.ic_rx_floor = 0;
}
```

**Why it is fatal.** Every power cycle restarts the IV sequence from the
beginning. Meter reboots — brownout, watchdog, maintenance, tamper switch — and
now IV `Sys-T ‖ 00000000` is used for a *second, different* message. Two
plaintexts under one keystream. And meters reboot; that is not an edge case.

The failure is silent. Communications work perfectly. Nothing logs an error.
The meter simply leaks its keystream to anyone recording the link.

**[INFER]** In my judgement this is the single most common serious defect in
field DLMS implementations, precisely because nothing tests for it. Interop
test suites verify that messages decrypt; they do not verify that IVs never
repeat across a power cycle.

### 10.4.2 The correct pattern

```c
/* ══════ CORRECT ══════ */
void security_init(void)
{
    if (nvm_load_ic(&ctx.ic_tx, &ctx.ic_rx_floor) != OK) {
        /* NVM unreadable: fail closed. Do NOT invent a counter. */
        ctx.state = SEC_FAULT_NO_COUNTER;
        log_critical("IC restore failed — ciphering disabled");
        return;
    }

    /* Jump forward past any invocations that may have been used but
       not persisted before the last power loss. See §10.5.          */
    ctx.ic_tx += IC_SAFETY_MARGIN;
    nvm_store_ic_tx(ctx.ic_tx);

    ctx.state = SEC_READY;
}
```

**[IMPL] The rule: on any doubt, go forward, never back.** Skipping counter
values costs nothing — they are merely nonces, and gaps are explicitly
permitted by the receiver rules. Reusing one is catastrophic. The asymmetry is
total, so the design should be too.

---

## 10.5 Counter persistence — the real engineering problem

You must persist a 32-bit counter that increments on **every transmitted
message**, in NVM with finite endurance, under unannounced power loss.

### 10.5.1 The naive approach and why it fails

```c
/* Write the counter to EEPROM on every message */
ic_tx++;
eeprom_write_u32(IC_ADDR, ic_tx);   /* ← wears out; not atomic */
```

Two independent failures:

**Endurance.** A meter read every 15 minutes, 4 messages per read, is ~140,000
writes/year. Internal MCU flash typically endures 10,000–100,000 cycles. The
cell dies within a year, and when it does the counter starts returning garbage
or the old value — reintroducing reuse.

**Atomicity.** Lose power mid-write and the cell holds a partially programmed
value. On restart you may read a *lower* number than you had. Now you reuse
IVs.

### 10.5.2 Pattern A — Reservation blocks (recommended)

Persist a *ceiling*, not the current value. Reserve a block of counter values
in one NVM write, then consume them from RAM.

```c
#define IC_BLOCK  1000u          /* values reserved per NVM write */

static uint32_t ic_tx;           /* current, in RAM     */
static uint32_t ic_ceiling;      /* persisted high-water */

int ic_init(void)
{
    if (nvm_read_ceiling(&ic_ceiling) != OK)
        return ERR_FAIL_CLOSED;

    /* Anything below the persisted ceiling MAY have been used. Start
       at the ceiling — never below it.                              */
    ic_tx = ic_ceiling;

    ic_ceiling += IC_BLOCK;
    if (ic_ceiling < ic_tx) return ERR_IC_EXHAUSTED;   /* overflow */
    return nvm_write_ceiling(ic_ceiling);
}

int ic_next(uint32_t *out)
{
    if (ic_tx == 0xFFFFFFFFu) return ERR_IC_EXHAUSTED;

    if (ic_tx >= ic_ceiling) {              /* block consumed */
        uint32_t next = ic_ceiling + IC_BLOCK;
        if (next < ic_ceiling) return ERR_IC_EXHAUSTED;
        if (nvm_write_ceiling(next) != OK) return ERR_NVM;
        ic_ceiling = next;
    }
    *out = ic_tx++;
    return OK;
}
```

**Properties:**

| | |
|--|--|
| NVM writes | 1 per 1000 messages — endurance problem solved |
| Power loss | Loses at most `IC_BLOCK` counter values. **Never reuses one.** |
| Counter space cost | 1000 wasted per unclean shutdown. Out of 2³² ≈ 4.29 billion, that is 4.29 million unclean shutdowns before exhaustion. |
| Complexity | Low |

**[IMPL] Tuning `IC_BLOCK`:** larger blocks mean fewer NVM writes but more
waste per reset. Compute it from your actual message rate and target NVM
lifetime:

```
   IC_BLOCK ≥ (messages_per_year × service_life_years) / nvm_endurance_cycles
```

For 140,000 msg/year, 15-year life, 10,000-cycle flash: `IC_BLOCK ≥ 210`. Round
up to 256 or 1000.

### 10.5.3 Pattern B — Ping-pong with sequence and CRC

For atomicity, keep two records and alternate. Always write the one that is not
currently valid, so a power loss mid-write leaves the other intact.

```c
typedef struct {
    uint32_t ceiling;
    uint32_t sequence;      /* increments each write; picks the newer */
    uint32_t crc;           /* over ceiling ‖ sequence                */
} ic_record_t;

/* Two records at separate NVM pages/sectors: SLOT_A, SLOT_B */

int ic_persist(uint32_t ceiling)
{
    ic_record_t a, b, new_rec;
    bool va = read_and_check(SLOT_A, &a);
    bool vb = read_and_check(SLOT_B, &b);

    uint32_t seq = 0;
    int      target = SLOT_A;

    if (va && vb)  { seq = seq_newer(a.sequence, b.sequence) + 1;
                     target = (a.sequence == seq - 1) ? SLOT_B : SLOT_A; }
    else if (va)   { seq = a.sequence + 1; target = SLOT_B; }
    else if (vb)   { seq = b.sequence + 1; target = SLOT_A; }
    /* else: both invalid — first write, or corruption. seq = 0. */

    new_rec.ceiling  = ceiling;
    new_rec.sequence = seq;
    new_rec.crc      = crc32(&new_rec, offsetof(ic_record_t, crc));

    return nvm_write(target, &new_rec, sizeof new_rec);
}
```

**On restore, take the highest valid ceiling of the two — never the newest
sequence alone.** If both records are valid but disagree, the higher ceiling is
the safe choice, because going forward is always safe.

```c
int ic_restore(uint32_t *ceiling)
{
    ic_record_t a, b;
    bool va = read_and_check(SLOT_A, &a);
    bool vb = read_and_check(SLOT_B, &b);

    if (va && vb) *ceiling = (a.ceiling > b.ceiling) ? a.ceiling : b.ceiling;
    else if (va)  *ceiling = a.ceiling;
    else if (vb)  *ceiling = b.ceiling;
    else          return ERR_FAIL_CLOSED;   /* both corrupt — do NOT
                                               invent a value        */
    return OK;
}
```

**[IMPL] Note `seq_newer()` must handle wraparound** — compare as a signed
difference (`(int32_t)(a - b) > 0`), not directly, or the comparison breaks
after 2³² writes. With reservation blocks that is far away, but it costs
nothing to be correct.

### 10.5.4 Pattern C — Dedicated external NVM

**[IMPL]** FRAM or MRAM (~10¹⁴ cycles, byte-writable, no erase) removes the
endurance problem entirely and lets you write on every message. If your BOM
permits it, this is the clean answer. Note that atomicity still needs
attention — a byte-write is atomic but a 4-byte write may not be, so keep the
CRC.

### 10.5.5 Fail-closed on unrecoverable counter loss

**[IMPL]** If NVM is unrecoverable, the correct behaviour is to **disable
ciphering and raise an alarm**, not to reset the counter to zero.

The reasoning: a meter that cannot communicate is a maintenance visit. A meter
that reuses IVs is a compromised key across the entire population sharing that
key. The first is expensive; the second is a security incident.

**[INFER]** The counter-argument you will hear in design review is "the meter
must never stop communicating". The answer is that key rotation is the recovery
path — install a fresh GUEK and the counter legitimately resets to 0
(**[SPEC]** *"when the key is established the corresponding ICs are reset to
0"*). That is the specification-sanctioned way out, and it is the only safe one.

---

## 10.6 Counter exhaustion

**[SPEC]** 2³²-1 invocations maximum, then the encryption function must return
an error and stop.

```
   4,294,967,295 messages, minus the block-reservation waste
```

At 140,000 messages/year that is roughly 30,000 years — not a concern in
normal operation. It becomes a concern when:

- Counter blocks are wastefully large and the meter resets often.
- **[INFER]** An attacker deliberately injects high-IC messages to force the
  RX floor upward. This is a genuine denial-of-service vector on the receive
  side, and it is why the sanity window in §10.2 detail 4 is worth having.

**Recovery is key rotation**, which resets both counters to 0.

---

## 10.7 Reading the counter remotely

**[VENDOR]** A client that has lost track of a meter's IC needs to resynchronise.
In practice this is done by reading an object exposing the invocation counter,
so the client can set its expectations before sending a ciphered APDU.

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — the supplied
> Green Book extract does not specify a COSEM object for exposing the
> invocation counter. Check Blue Book DLMS UA 1000-1 Ed. 12 (and any project
> companion specification, e.g. IDIS, DSMR, or the Indian IS 15959 companion)
> for the object and OBIS code used in your deployment.

**[IMPL]** Whatever the mechanism, note the security property required: reading
the counter must not itself require a valid counter, or you have a deadlock.
This usually means the counter object is readable under a lower-security
association.

---

# CHAPTER 11 — THE SYSTEM TITLE

## 11.1 Definition

**[SPEC]** [GB] 4.3.4:

> *"The system title Sys-T shall uniquely identify each DLMS/COSEM entity that
> may be server, a client or a third party that can access servers via clients.
> The system title:*
> - *shall be 8 octets long;*
> - *shall be unique.*
>
> *The leading (i.e., the 3 leftmost) octets should hold the three-letter
> manufacturer ID. This is the same as the leading three octets of the Logical
> Device Name … The remaining 5 octets shall ensure uniqueness."*

```
   ┌────────────────────┬──────────────────────────────────┐
   │  Manufacturer ID   │       Uniqueness field           │
   │     3 octets       │          5 octets                │
   ├────────────────────┼──────────────────────────────────┤
   │   4D    4D    4D   │   00    00    BC    61    4E     │
   │   'M'   'M'   'M'  │   ◄──── 0x0000BC614E ────►       │
   │                    │        = 12,345,678              │
   └────────────────────┴──────────────────────────────────┘
```

**[SPEC]** [GB] 4.3.4 NOTE:

> *"It can be derived for example from the last 12 digits of the manufacturing
> number, up to 999 999 999 999. This value converts to 0xE8D4A50FFF. Values
> above this, up to 0xFFFFFFFFFF (decimal 1 099 511 627 775) can also be used,
> but these values cannot be mapped to the last 12 digits of the manufacturing
> number."*

The manufacturer ID is **[SPEC]** *"Administered by the FLAG Association in
co-operation with the DLMS UA"* — it is a registered three-letter code, not
something a vendor invents.

**[SPEC]** And: *"Project specific companion specifications may specify a
different structure."* So a national companion standard may impose its own
layout on the last 5 octets. **[VENDOR]** Do not assume the manufacturing-number
mapping holds in every deployment.

---

## 11.2 Why it exists — the IV connection

The System Title looks like a device identifier, and it is. But its
*cryptographic* role is what makes it critical:

```
   System Title  ────────────────►  fixed field of the IV
                                            │
                                            ▼
                                    IV = Sys-T ‖ IC
                                            │
                                            ▼
                                    GCM keystream + tag
```

**[SPEC]** [GB] 9.2.3.3.7.3: *"For any given key, no two distinct physical
devices shall share the same fixed field."*

**Why this is the whole point.** Consider a fleet of meters sharing a broadcast
key GBEK. Each meter has its own counter starting at 0. If two meters shared a
System Title:

```
   Meter A:  IV = SYSTITLE_X ‖ 00000000   → keystream K
   Meter B:  IV = SYSTITLE_X ‖ 00000000   → keystream K    ← IDENTICAL
```

Both encrypt different data with the same keystream. Nonce reuse, across
devices, with no bug in either meter's counter handling. The System Title is
the *only* thing preventing this.

**[SPEC]** [GB] 9.2.3.3.7.3 quantifies the space:

> *"The bit length of the fixed field limits the number of distinct physical
> devices that can implement the authenticated encryption function for the
> given key to 2⁶⁴."*

2⁶⁴ devices per key. Not a constraint in practice — but only if the values are
actually unique.

**[INFER] The realistic failure mode is not exhaustion, it is manufacturing.**
A production line that programs a default System Title and relies on a later
step to overwrite it will, eventually, ship a batch that skipped the step.
Those meters are cryptographically indistinguishable. This is a
manufacturing-process security requirement, not a firmware one — see Volume 5.

---

## 11.3 Client and server System Titles

Both parties have one. Which is used depends on **direction**:

```
   ┌─────────────────────────────────────────────────────────────┐
   │  RULE: the IV always uses the ORIGINATOR's System Title.    │
   └─────────────────────────────────────────────────────────────┘

   Client → Server  (request)
       IV = Sys-T_client ‖ IC_client_tx

   Server → Client  (response)
       IV = Sys-T_server ‖ IC_server_tx
```

This is visible in [GB] Table 43: pass 3 (client-originated) uses
`4D4D4D0000000001` (client), pass 4 (server-originated) uses
`4D4D4D0000BC614E` (server).

**[IMPL] The bug this creates.** It is natural to write a single
`build_iv(ctx)` helper and forget that it must select a different system title
depending on whether you are sending or receiving. Make the direction explicit
in the signature:

```c
/* Force the caller to think about direction. */
typedef enum { DIR_OUTGOING, DIR_INCOMING } dir_t;

static void build_iv(const dlms_security_context_t *ctx,
                     dir_t dir, uint32_t ic, uint8_t iv[12])
{
    const uint8_t *st = (dir == DIR_OUTGOING) ? ctx->server_system_title  /* ours */
                                              : ctx->client_system_title; /* peer's */
    memcpy(iv, st, 8);
    iv[8]  = (uint8_t)(ic >> 24);
    iv[9]  = (uint8_t)(ic >> 16);
    iv[10] = (uint8_t)(ic >>  8);
    iv[11] = (uint8_t)(ic      );
}
```

Note the IC is **big-endian** in the IV. Getting endianness wrong here produces
a tag mismatch with a perfectly well-formed-looking capture — see the failure
table in §9.4.7.

---

## 11.4 How System Titles are exchanged

**[SPEC]** [GB] 4.3.4 lists three mechanisms:

```
   ① During media-specific registration
      e.g. S-FSK PLC: exchanged during registration via CIASE (see [GB] 10.4.5)

   ② During AA establishment
      calling-AP-title  [6]  in the AARQ  → client's System Title
      responding-AP-title[4] in the AARE  → server's System Title

   ③ Via the "Security setup" object
      write  client_system_title
      read   server_system_title
```

**[SPEC]** And the consistency rule:

> *"If the system titles sent / received during AA establishment are not the
> same as the ones exchanged during the registration process, the AA shall be
> rejected."*

**[SPEC]** Also: *"In the case of broadcast communication, only the client
sends the system title to the server."* Sensible — a broadcast has no single
server to answer.

**[SPEC]** And a prerequisite from [GB] 4.3.4:

> *"Before the cryptographic security algorithms can be used — this requires a
> ciphered application context — the peers have to exchange system titles."*

**[IMPL] The bootstrapping consequence.** You cannot decrypt a message from a
peer whose System Title you do not know, because you cannot build the IV. So
the exchange must complete before any ciphered APDU. For an
optical-port/handheld association this happens in the AARQ; for a PLC network
it may have happened during registration hours earlier. Your firmware must
handle both, and must have a defined behaviour for "ciphered APDU received from
an unknown System Title" — which is: **reject**.

---

## 11.5 What the System Title reveals — a privacy note

**[INFER]** The System Title is transmitted in cleartext (in the AARQ/AARE, and
in the `system-title` field of `general-glo-ciphering` APDUs). A passive
observer therefore learns:

- The manufacturer, from the FLAG code.
- Very likely the serial number, from the standard mapping.
- Enough to correlate all traffic to and from a specific physical meter, even
  though the payload is encrypted.

For most deployments this is acceptable — the meter's location is not secret.
On a shared RF medium serving many households it is a traffic-analysis exposure
worth noting in a threat model. It is not something the protocol lets you avoid.

---

# CHAPTER 12 — THE THREE SECURITY SUITES

## 12.1 What a security suite is

**[SPEC]** [GB] 9.2.3.7:

> *"A security suite determines the set of cryptographic algorithms available
> for the various cryptographic primitives and the key sizes."*
>
> *"The DLMS/COSEM security suites … are based on NSA Suite B and include
> cryptographic algorithms for authentication, encryption, key agreement,
> digital signature and hashing."*

The suite ID travels in **bits 3..0 of the Security Control byte**, so it is
visible on every single ciphered APDU.

---

## 12.2 The specification table

**[SPEC]** [GB] Table 19, reconstructed:

| Suite Id | Security suite name | Authenticated encryption | Digital signature | Key agreement | Hash | Key transport | Compression |
|----------|--------------------|--------------------------|-------------------|---------------|------|---------------|-------------|
| **0** | `AES-GCM-128` | AES-GCM-128 | – | – | – | AES-128 key wrap | – |
| **1** | `ECDH-ECDSA-AES-GCM-128-SHA-256` | AES-GCM-128 | ECDSA with P-256 | ECDH with P-256 | SHA-256 | AES-128 key wrap | V.44 |
| **2** | `ECDH-ECDSA-AES-GCM-256-SHA-384` | AES-GCM-256 | ECDSA with P-384 | ECDH with P-384 | SHA-384 | AES-256 key wrap | V.44 |
| 3–15 | — | — | — | — | — | — | — |

**[SPEC]** *"All other reserved."*

Note the em-dashes in the Suite 0 row. Suite 0 has **no** digital signature, **no**
key agreement, **no** hash, and **no** compression. It is AES-GCM-128 plus AES
key wrap, and nothing else.

**[SPEC]** The algorithm selections, from [GB] 9.2.3.7:

- *"authentication and encryption: the Advanced Encryption Standard (AES) shall
  be used as specified in FIPS PUB 197, with key sizes of 128 and 256 bits. AES
  shall be used with the Galois/Counter Mode (GCM) of operation specified in
  NIST SP 800-38D"*
- *"digital signature: the Elliptic Curve Digital Signature Algorithm (ECDSA)
  shall be used as specified FIPS PUB 186-4 and in NSA1, using the curves P-256
  or P-384"*
- *"key agreement: the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme; the
  One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme; and the Static Unified
  Model C(0e, 2s, ECC CDH) scheme shall be used using the elliptic curves P-256
  or P-384"*
- *"hashing: the Secure Hash Algorithms (SHA) SHA-256 and SHA-384 shall be used
  as specified in FIPS PUB 180-4:2012"*

---

## 12.3 Suite 0 — AES-GCM-128, in full

### 12.3.1 What "AES-GCM-128" actually names

Quality Rule 1 in your prompt forbids saying "this is just encryption", and
Chapter 18 of the prompt asks that this name be decomposed rather than
recited. So:

```
   AES  ── the block cipher: FIPS PUB 197, 128-bit blocks
    │
   GCM  ── the mode of operation: NIST SP 800-38D
    │       · CTR-mode encryption for confidentiality
    │       · GHASH over GF(2¹²⁸) for authenticity
    │       · combined into one pass = AEAD
    │
   128  ── the KEY length in bits (not the block length,
           which is 128 regardless)
```

And separately:

```
   AES-WRAP-128  ── RFC 3394 key wrapping
    │
   AES   ── same block cipher
   WRAP  ── a DIFFERENT algorithm from GCM. Six passes over the
    │       data, wrapping n 64-bit semiblocks into n+1, with a
    │       built-in integrity check value. NOT a mode of operation
    │       in the GCM sense — a purpose-built key-encryption
    │       construction.
   128   ── the KEK length in bits
```

**These are two distinct algorithms sharing one block cipher.** AES-GCM
protects messages; AES-WRAP protects keys. They are not interchangeable and
they use different keys (EK vs KEK).

**[SPEC]** [GB] 9.2.3.3.7.7 on key wrap:

> *"For wrapping key data DLMS/COSEM has selected the AES key wrap algorithm
> specified in RFC 3394. The algorithm is designed to wrap or encrypt key data.
> It operates on blocks of 64 bits. Before being wrapped, the key data is
> parsed into n blocks of 64 bits. The only restriction the key wrap algorithm
> places on n is that n has to be at least two."*
>
> *"The inputs to the key wrapping process are the Key Encrypting Key KEK and
> the plaintext to be wrapped. The plaintext consists of n 64-bit blocks …
> The output is the ciphertext, (n+1) 64 bit values."*

So a 128-bit key (n=2 semiblocks) wraps to **192 bits (24 octets)**. That extra
64-bit block is the integrity check. Budget for it in your buffers.

### 12.3.2 Suite 0 properties

| Property | Value |
|----------|-------|
| Encryption | AES-GCM, 128-bit key |
| Authentication | GMAC (GCM with empty plaintext), 96-bit tag |
| Encryption key EK | **[SPEC]** 128 bits — [GB] 9.2.3.3.7.4 |
| Authentication key AK | **[SPEC]** 128 bits — same rules as EK, [GB] 9.2.3.3.7.5 |
| KEK / master key | **[SPEC]** 128 bits — [GB] 9.2.3.3.7.7 |
| Tag length | **[SPEC]** 96 bits — [GB] 9.2.3.3.7.6 |
| IV length | **[SPEC]** 96 bits — [GB] 9.2.3.3.7.3 |
| Digital signature | **None** |
| Key agreement | **None** |
| Certificates | **None** |
| Compression | **None** |

### 12.3.3 Limitations of Suite 0 — stated honestly

**No key establishment.** Every key must arrive out of band or wrapped under a
pre-shared KEK. **[SPEC]** [GB] 9.2.5.4: *"this method can be used only between
parties sharing the master key, i.e. between a client and a server."* There is
no way for two parties who share nothing to bootstrap a key.

**No forward secrecy.** All keys are static. An attacker who records a year of
traffic and later extracts the GUEK decrypts the entire year retroactively.
This is the sharpest practical limitation of Suite 0.

**No non-repudiation.** Symmetric only. The utility and the meter share every
key, so neither can prove the other produced a message.

**Shared-secret blast radius.** Compromise of one meter's keys is bad;
compromise of a key shared across a fleet is a fleet-wide event.

### 12.3.4 Why Suite 0 nonetheless dominates deployment [INFER]

Because it is *enough* for the actual threat model of most deployments, and it
fits in an 8-bit-era BOM:

- The realistic adversary is a customer tampering with their own meter, or an
  opportunist on a shared bus — not a nation-state recording decades of traffic.
- AES-128 has a hardware accelerator on essentially every metering MCU.
- No certificates means no PKI, no CA, no expiry, no revocation, no
  clock-dependence — an enormous operational simplification.
- Flash and RAM cost is small enough to fit alongside metrology on a modest
  part.

**[INFER]** The correct engineering judgement is: Suite 0 is a reasonable
default for a constrained meter on a controlled network, and inadequate for a
meter that must interoperate across organisational boundaries or must support
non-repudiable billing evidence.

---

## 12.4 Suite 1 — adding public-key cryptography

**[SPEC]** Suite 1 = `ECDH-ECDSA-AES-GCM-128-SHA-256`. Decomposed:

```
   ECDH        ── Elliptic Curve Diffie-Hellman key agreement, P-256
   ECDSA       ── Elliptic Curve Digital Signature Algorithm, P-256
   AES-GCM-128 ── unchanged from Suite 0
   SHA-256     ── the hash for ECDSA and for the key derivation function
```

Plus **[SPEC]** AES-128 key wrap and V.44 compression.

### 12.4.1 Why Suite 1 is fundamentally different, not merely stronger

The bulk encryption is *identical* to Suite 0 — same AES-GCM-128, same 128-bit
keys, same 96-bit tags. Suite 1 is not "stronger encryption". It adds three
capabilities that Suite 0 structurally cannot provide:

**1. Key establishment without a pre-shared secret.** ECDH lets two parties who
have never met derive a shared key over a public channel. **[SPEC]** [GB]
9.2.3.4.6.1: *"Key agreement allows two entities to jointly compute a shared
secret and derive secret keying material from it."*

**2. Non-repudiation.** ECDSA signatures are made with a private key held by
exactly one party. **[SPEC]** [GB] 9.2.3.4.4 introduces digital signature
precisely for this property.

**3. Trust delegation via certificates.** A CA vouches for a public key. Meters
can authenticate parties they have never been provisioned with — the trust
comes from the CA, not from a shared secret table.

**[SPEC]** And a boundary worth restating, [GB] 9.2.3.4.1 NOTE 2:

> *"Asymmetric key algorithms are not used for encryption in DLMS/COSEM."*

ECDH agrees on a key; AES-GCM still does the encrypting. ECDSA signs; it never
encrypts. Quality Rule 9 in your prompt — never describe ECDSA as encryption —
is the specification's own position.

### 12.4.2 Ephemeral vs static keys and forward secrecy

**[SPEC]** [GB] offers three key-agreement schemes:

| Scheme | Party U contributes | Party V contributes | Forward secrecy |
|--------|--------------------|--------------------|-----------------|
| **C(2e, 0s)** | ephemeral pair | ephemeral pair | **Yes** — both keys are discarded |
| **C(1e, 1s)** | ephemeral pair | static pair | **Partial** |
| **C(0e, 2s)** | static pair + nonce | static pair | **No** |

**[SPEC]** [GB] 9.2.5.5 assigns them to purposes: C(2e,0s) is *"for use between
a DLMS/COSEM client and a server to agree on the master key, on global
encryption keys and/or on the authentication key"*; C(1e,1s) and C(0e,2s) are
*"for use by a DLMS/COSEM server and another party to agree on an ephemeral
encryption key to protect xDLMS APDUs or COSEM data"*.

Volume 3 develops these in full. The point here: **Suite 1 makes forward
secrecy achievable**, which Suite 0 cannot.

---

## 12.5 Suite 2 — AES-256 and P-384

**[SPEC]** Suite 2 = `ECDH-ECDSA-AES-GCM-256-SHA-384`.

Every parameter scales:

| Parameter | Suite 1 | Suite 2 |
|-----------|---------|---------|
| EK, AK, KEK | 128 bits | **[SPEC]** 256 bits |
| AES rounds | 10 | 14 |
| Curve | P-256 | **P-384** |
| Hash | SHA-256 | **SHA-384** |
| Key wrap | AES-128 | **AES-256** |
| ECDSA signature | 64 octets | **96 octets** |
| Public key (uncompressed x‖y) | 64 octets | **96 octets** |
| Tag | **96 bits** | **96 bits** — unchanged |
| IV | **96 bits** | **96 bits** — unchanged |
| System Title | **8 octets** | **8 octets** — unchanged |
| Invocation Counter | **4 octets** | **4 octets** — unchanged |

**Note carefully what does *not* change.** Tag, IV, System Title, and Invocation
Counter are identical in all three suites. Only key material and curve
parameters scale. That is a considerable convenience: your APDU parser and your
counter logic are suite-independent.

**[IMPL] Cost of Suite 2 on an MCU.** AES-256 is ~40% slower per block than
AES-128 (14 rounds vs 10). P-384 point multiplication is roughly **2.5–3×** the
cost of P-256, because the field is 1.5× wider and the scalar 1.5× longer, and
field multiplication cost grows quadratically. On a Cortex-M4 without a PKA,
budget hundreds of milliseconds per ECDSA operation on P-384. **[INFER]** If
Suite 2 is a requirement, a hardware public-key accelerator or a secure element
moves from "nice" to "necessary".

---

## 12.6 The complete comparison matrix

| Feature | **Suite 0** | **Suite 1** | **Suite 2** |
|---------|-------------|-------------|-------------|
| **Suite name** [SPEC] | AES-GCM-128 | ECDH-ECDSA-AES-GCM-128-SHA-256 | ECDH-ECDSA-AES-GCM-256-SHA-384 |
| **SC bits 3..0** | `0000` | `0001` | `0010` |
| **Encryption** | AES-GCM | AES-GCM | AES-GCM |
| **Key size (EK/AK/KEK)** | 128 bit | 128 bit | **256 bit** |
| **Authentication** | GMAC, 96-bit tag | GMAC, 96-bit tag | GMAC, 96-bit tag |
| **ECDSA** | ✗ | ✓ P-256 | ✓ P-384 |
| **ECDH** | ✗ | ✓ P-256 | ✓ P-384 |
| **Curve** | – | P-256 (secp256r1) | P-384 (secp384r1) |
| **Hash** | – | SHA-256 | SHA-384 |
| **Key wrap** | AES-128 (RFC 3394) | AES-128 | **AES-256** |
| **Certificates** | ✗ | ✓ X.509 v3 | ✓ X.509 v3 |
| **Compression** | ✗ | ✓ V.44 | ✓ V.44 |
| **Forward secrecy possible** | ✗ | ✓ via C(2e,0s) | ✓ via C(2e,0s) |
| **Non-repudiation** | ✗ | ✓ | ✓ |
| **RAM impact** [IMPL] | ~1–2 KB | ~4–8 KB | ~8–16 KB |
| **Flash impact** [IMPL] | ~4–8 KB | ~20–40 KB | ~25–50 KB |
| **CPU cost** [IMPL] | Low; hardware AES common | High for ECC ops; AES unchanged | Very high; P-384 ≈ 2.5–3× P-256 |
| **Implementation complexity** | Low | High — PKI, certificate parsing, validity, revocation | High, plus larger arithmetic |
| **Clock dependence** | None | **Yes** — certificate validity periods | **Yes** |
| **Typical deployment** [VENDOR] | The large majority of installed meters | Newer deployments needing third-party access or signed data | High-assurance / long-horizon regulatory requirements |
| **Key security consideration** | No forward secrecy; shared-key blast radius | Certificate lifecycle becomes an operational burden | Cost may force a secure element; verify the BOM early |

**[IMPL] The RAM/flash figures are order-of-magnitude estimates** for a
Cortex-M with software crypto, offered for early architectural budgeting. They
vary substantially with library choice, optimisation level, and whether a
hardware accelerator is present. Volume 5 develops proper budgets.

**[INFER] One consequence worth flagging early:** Suites 1 and 2 introduce a
dependency on the meter's real-time clock, because certificate validity periods
must be checked. A meter whose RTC has drifted or reset now cannot validate
certificates. This is an operational failure mode Suite 0 simply does not have,
and it should be in your threat model before you commit to a suite.

---

# CHAPTER 13 — THE CIPHERED APDU WIRE FORMAT

## 13.1 The four families

**[SPEC]** [GB] Table 36 defines the ciphered APDU types:

| APDU family | Parties | Ciphering type | Security services | Compression |
|-------------|---------|----------------|-------------------|-------------|
| Service-specific `glo-` / `ded-` | Client ↔ Server | Symmetric key | Authentication, encryption | **No** |
| `general-glo-ciphering` / `general-ded-ciphering` | Client ↔ Server | Symmetric key | Authentication, encryption | **Yes** |
| `general-ciphering` | Third party or Client ↔ Server | Symmetric key | Authentication, encryption | **Yes** |
| `general-signing` | — | **Asymmetric key** | **Digital signature** | **No** |

**[SPEC]** Key sourcing per family, also from Table 36:

- Service-specific and general-glo/ded: block cipher key is the **dedicated
  key** (transported by the AARQ) or the **global unicast/broadcast key**
  (established outside the exchange, identified by the SC byte).
- `general-ciphering`: block cipher key is a global key identified **as part of
  the exchange**, or established as part of the exchange (key wrap or key
  agreement) — the `key-info` field carries this.
- In all symmetric cases the **authentication key is global** and *"established
  outside the exchange"*.

---

## 13.2 Service-specific ciphering — structure

**[SPEC]** [GB] Figure 82. Three shapes, one per protection mode:

```
 ── Authentication only (SC bit 4 = 1) ────────────────────────────────
 ┌─────┬─────┬────┬───────────┬─────────────────────────┬────────────┐
 │ Tag │ Len │ SC │    IC     │   Unprotected APDU      │  Auth tag  │
 └─────┴─────┴────┴───────────┴─────────────────────────┴────────────┘
   1     1-3   1        4              n                      12
             └── security header ──┘
             ◄────────── OCTET STRING of length Len ──────────────►
   ⚠ The APDU is VISIBLE on the wire.

 ── Encryption only (SC bit 5 = 1) ────────────────────────────────────
 ┌─────┬─────┬────┬───────────┬─────────────────────────────────────┐
 │ Tag │ Len │ SC │    IC     │      Encrypted APDU (ciphertext)    │
 └─────┴─────┴────┴───────────┴─────────────────────────────────────┘
   1     1-3   1        4                     n
   ⚠ No tag. Malleable. Do not deploy.

 ── Authenticated encryption (SC bits 4,5 = 1) ★ ──────────────────────
 ┌─────┬─────┬────┬───────────┬─────────────────────────┬────────────┐
 │ Tag │ Len │ SC │    IC     │  Encrypted APDU (C)     │  Auth tag  │
 └─────┴─────┴────┴───────────┴─────────────────────────┴────────────┘
   1     1-3   1        4              n                      12
```

Note there is **no `system-title` field** in the service-specific form —
**[SPEC]** [GB] Table 39 shows `system-title` as `–` for service-specific and
`+` for general-glo/ded. The receiver must already know the originator's System
Title from the association context. That is why §11.4's exchange rules matter.

The length field uses A-XDR variable-length encoding: one octet for lengths
0–127, otherwise `0x81`/`0x82` followed by 1 or 2 length octets.

---

## 13.3 general-glo-ciphering — structure

**[SPEC]** [GB] Figure 83 and the ASN.1 in 9.5:

```
   General-Glo-Ciphering ::= SEQUENCE
   {
       system-title      OCTET STRING,
       ciphered-content  OCTET STRING
   }
```

```
 ┌──────┬──────┬───────────────────┬──────────────────────────────────┐
 │ 0xDB │ Len  │   system-title    │        ciphered-content          │
 └──────┴──────┴───────────────────┴──────────────────────────────────┘
    1      1        8 octets                     variable
                 (length-prefixed)

   ciphered-content decomposes exactly as the service-specific forms:
   ┌─────┬────┬─────────┬──────────────────────┬────────────┐
   │ Len │ SC │   IC    │  (compressed and/or  │  Auth tag  │
   │     │    │         │   encrypted) APDU    │            │
   └─────┴────┴─────────┴──────────────────────┴────────────┘
```

**[SPEC]** The differences from service-specific:

1. The **system-title is carried explicitly** — so the receiver need not know
   it in advance.
2. **Compression is available** (SC bit 7).
3. **Any** xDLMS APDU can be wrapped, not just the ones with a dedicated
   `glo-` tag.

**[INFER] When to prefer which.** Service-specific tags are 8 octets smaller on
the wire (no system-title field) and are the traditional choice for
client–server links where identities are already established. The general forms
are self-describing and are what you need for compression, for broadcast to
receivers that may not know you, and for anything involving a third party.

---

## 13.4 general-ciphering — structure

**[SPEC]** [GB] 9.5:

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

```
 ┌──────┬─────────┬───────────┬───────────┬──────┬───────┬──────┬──────────┐
 │ 0xDD │ trans-  │ originator│ recipient │ date │ other │ key- │ ciphered │
 │      │ action- │ -system-  │ -system-  │ -time│ -info │ info │ -content │
 │      │ id      │ title     │ title     │      │       │      │          │
 └──────┴─────────┴───────────┴───────────┴──────┴───────┴──────┴──────────┘
```

**[SPEC]** [GB] Figure 84: *"All fields are A-XDR encoded OCTET STRINGs. The
length and the value of each field is included in the AAD."*

Field purposes, from [GB] Table 39 and 9.2.7.2.4.8:

| Field | Purpose |
|-------|---------|
| `transaction-id` | Correlates request and response across a broker. Also feeds `Nonce_U` in the C(0e,2s) key agreement scheme — **[SPEC]** [GB] Table 17. |
| `originator-system-title` | **[SPEC]** *"identifying the party that applied the protection"* — [GB] 9.2.7.3 |
| `recipient-system-title` | **[SPEC]** *"the party that shall check / remove the protection"* |
| `date-time` | Freshness / audit |
| `other-information` | Extension point |
| `key-info` | **The distinguishing feature** — carries how the encryption key is identified or established |

**[SPEC]** `Key-Info` is a CHOICE of three, [GB] 9.5 and Table 21:

```
   Key-Info ::= CHOICE
   {
       identified-key  [0] Identified-Key,     -- key-id: GUEK or GBEK
       wrapped-key     [1] Wrapped-Key,        -- kek-id + wrapped key data
       agreed-key      [2] Agreed-Key          -- key-parameters + key data
   }
```

| Choice | Contents | Meaning |
|--------|----------|---------|
| `identified-key` | `key-id`: global-unicast-encryption-key or global-broadcast-encryption-key | **[SPEC]** *"The EK is identified"* — both parties already have it. |
| `wrapped-key` | `kek-id` (0 = Master Key), `key-ciphered-data` | **[SPEC]** *"Randomly generated key wrapped with KEK"* |
| `agreed-key` | `key-parameters` (`0x01` = C(1e,1s), `0x02` = C(0e,2s)), `key-ciphered-data` | **[SPEC]** For C(1e,1s): the ephemeral public key of party U, signed with U's private signature key. For C(0e,2s): *"an octet-string of length zero"* — U supplies `Nonce_U` instead. |

**[SPEC]** And a scope note, [GB] Table 21:

> *"NOTE Using key identification restricts exchanging protected xDLMS APDUs /
> COSEM data between a client and a server because the GUEK and the GBEK shall
> not be disclosed to any party other than the client and the server."*

That sentence tells you why `general-ciphering` exists: a third party cannot
use `identified-key`, because it does not hold the global keys. It must use
`wrapped-key` or `agreed-key`. Volume 4 develops the third-party model.

---

## 13.5 general-signing — structure

**[SPEC]** [GB] Figure 85 and 9.5:

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

Tag `0xDF` ([223]).

**[SPEC]** *"All fields are A-XDR encoded OCTET STRINGs. The length and the
value of each field contribute to the signature."*

**[SPEC]** The signature algorithm is ECDSA, [GB] 9.2.7.2.5, and the encoding is
specified precisely in 9.2.3.4.5:

> *"In DLMS/COSEM the plain format shall be used: the signature (r, s) is
> encoded as octet string R ‖ S, i.e. as concatenation of the octet strings
> R = I2OS(r, l) and S = I2OS(s, l) with l = ⌈log₂ n / 8⌉. Thus, the signature
> has a fixed length of 2·l octets."*

**[IMPL] This is important and easy to get wrong.** DLMS uses the **plain
`R‖S` format**, not the DER-encoded `SEQUENCE { INTEGER r, INTEGER s }` that
OpenSSL and most TLS libraries produce by default. A DER signature is
variable-length (70–72 octets for P-256) and will not interoperate. You must
convert:

```
   P-256:  l = 32  →  signature = 64 octets  (R:32 ‖ S:32)
   P-384:  l = 48  →  signature = 96 octets  (R:48 ‖ S:48)
```

Both `r` and `s` are **left-zero-padded** to exactly `l` octets. A library that
strips leading zeros will occasionally emit a 63-octet signature that fails
against a strict peer.

**[SPEC]** Note also [GB] 9.2.7.3 on ordering when both are applied:

> *"If both ciphering and digital signature is applied by the same party for
> the same party, then normally the digital signature is applied first."*

Sign, then encrypt.

---

## 13.6 The complete official worked example

**[SPEC]** [GB] Table 40, *"Encoding example: global-get-request xDLMS APDU"*.
Every value below is from the Green Book, and every computed value was
independently reproduced.

### 13.6.1 The security material

```
   Security suite       : GCM-AES-128  (Suite 0)
   System Title  Sys-T  : 4D4D4D0000BC614E
                          └─ [SPEC] "here, the five last octets contain
                             the manufacturing number in hexa"
   Invocation ctr  IC   : 01234567
   Initialization vector: 4D4D4D0000BC614E01234567        (12 octets)
   Block cipher key EK  : 000102030405060708090A0B0C0D0E0F (16 octets)
   Authentication key AK: D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF (16 octets)

   xDLMS APDU to protect:
     C0 01 00 00 08 00 00 01 00 00 FF 02 00           (13 octets)
     │  │  │  └──────────────────────┴─ OBIS 0.0.1.0.0.255 = Clock
     │  │  └─ invoke-id-and-priority = 0x00
     │  └─ Get-Request-Normal
     └─ get-request  [192] = 0xC0

     [SPEC] "(Get-request, attribute 2 of the Clock object)"
     ... 00 00 01 00 00 FF   02      00
         └─ class_id 0x0008 ┘ attr=2  no access selector
```

### 13.6.2 Mode 1 — Authentication only, SC = 0x10

```
 SC     = 10        →  suite 0, A=1, E=0, unicast, no compression
 SH     = SC ‖ IC   =  10 01234567                       (5 octets)

 P      = ∅  (nothing encrypted)

 A      = SC ‖ AK ‖ APDU
        = 10
          D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF
          C0010000080000010000FF0200
        = 10D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFC0010000080000010000FF0200
                                                        (30 octets)

 C      = NULL
 T      = 06725D910F9221D263877516                      (12 octets)
                                    ✅ VERIFIED against [GB] Table 40

 ── Complete APDU:  TAG ‖ LEN ‖ SH ‖ APDU ‖ T ───────────────────────

   C8 1E 10 01234567 C0010000080000010000FF0200 06725D910F9221D263877516
   │  │  │  │        │                          │
   │  │  │  │        │                          └─ 12-octet tag
   │  │  │  │        └─ the APDU, IN CLEARTEXT
   │  │  │  └─ invocation counter
   │  │  └─ security control
   │  └─ length 0x1E = 30 = 1(SC) + 4(IC) + 13(APDU) + 12(T)
   └─ glo-get-request [200]

   Total on wire: 32 octets                 ✅ matches [GB] Table 40
```

### 13.6.3 Mode 2 — Encryption only, SC = 0x20

```
 SC     = 20        →  suite 0, A=0, E=1, unicast
 SH     = 20 01234567

 P      = C0010000080000010000FF0200
 A      = – (null)   ← [GB] Table 38: AAD is null for encryption-only

 C      = 411312FF935A47566827C467BC                     (13 octets)
                                    ✅ VERIFIED against [GB] Table 40
 T      = – (not computed)

 ── Complete APDU:  TAG ‖ LEN ‖ SH ‖ C ──────────────────────────────

   C8 12 20 01234567 411312FF935A47566827C467BC
   │  │
   │  └─ length 0x12 = 18 = 1 + 4 + 13   (no tag)
   └─ glo-get-request

   Total on wire: 20 octets                 ✅ matches [GB] Table 40
```

### 13.6.4 Mode 3 — Authenticated encryption, SC = 0x30 ★

```
 SC     = 30        →  suite 0, A=1, E=1, unicast
 SH     = 30 01234567

 P      = C0010000080000010000FF0200            (the APDU)

 A      = SC ‖ AK                                ← note: APDU NOT included
        = 30D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF    (17 octets)

 C      = 411312FF935A47566827C467BC             (13 octets)
 T      = 7D825C3BE4A77C3FCC056B6B               (12 octets)
                                    ✅ BOTH VERIFIED against [GB] Table 40

 ── Complete APDU:  TAG ‖ LEN ‖ SH ‖ C ‖ T ──────────────────────────

   C8 1E 30 01234567 411312FF935A47566827C467BC 7D825C3BE4A77C3FCC056B6B
   │  │  │  │        │                          │
   │  │  │  │        │                          └─ tag over (SC‖AK) and C
   │  │  │  │        └─ ciphertext, same length as plaintext
   │  │  │  └─ IC — visible, and must be, for the receiver to build the IV
   │  │  └─ SC — visible, and must be, so the receiver knows what to do
   │  └─ length 0x1E = 30 = 1 + 4 + 13 + 12
   └─ glo-get-request

   Total on wire: 32 octets                 ✅ matches [GB] Table 40
```

**Two observations worth making explicit.**

*The ciphertext is identical in modes 2 and 3.* `411312FF935A47566827C467BC`
appears in both. That is expected: the keystream depends only on `(EK, IV)`,
and the AAD affects only the tag. The AAD does not change the ciphertext.

*Overhead is 17 octets* for authenticated encryption: 1 (SC) + 4 (IC) + 12
(tag). Plus tag and length octets. On a 13-octet APDU that is more than 100%
overhead; on a 200-octet load-profile response it is under 9%. **[INFER]** For
chatty small-APDU traffic on a constrained link this matters, and it is an
argument for reading multiple attributes per request rather than one at a time.

---

## 13.7 What is visible on the wire

Even under full authenticated encryption, a passive observer learns a
surprising amount:

```
   C8 1E 30 01234567 411312FF935A47566827C467BC 7D825C3BE4A77C3FCC056B6B
   ▲▲ ▲▲ ▲▲ ▲▲▲▲▲▲▲▲ ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲ ▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲▲
   │  │  │  │        │                          │
   │  │  │  │        │                          └─ opaque
   │  │  │  │        └─ opaque, but LENGTH is visible
   │  │  │  └─ INVOCATION COUNTER — message ordering, message rate,
   │  │  │     and whether the meter has been reset
   │  │  └─ SECURITY CONTROL — the suite, the protection level, the
   │  │     key set, whether compression is on
   │  └─ LENGTH
   └─ APDU TYPE — this is a GET REQUEST, globally ciphered
```

| Observable | What it reveals |
|------------|-----------------|
| APDU tag | Whether this is a GET, SET, or ACTION — **the service class is not hidden** |
| Length | Approximate size of the request/response; distinguishes a single register read from a load-profile dump |
| SC byte | Security suite, protection level, unicast vs broadcast, compression |
| Invocation counter | Message ordering, message rate, and counter resets (⇒ meter reboots) |
| System Title (in `general-glo`/`general`) | Manufacturer and probably serial number |
| Timing and direction | Polling schedule, whether the meter is responding |

**[INFER] The practically significant leak is the APDU tag.** An attacker
watching a meter's link can tell the difference between routine reads (`0xC8`
glo-get-request) and a configuration change (`0xC9` glo-set-request) or a relay
operation (`0xCB` glo-action-request) — without decrypting anything. On a
disconnect-capable meter that is meaningful: it tells an attacker exactly which
message to target for a replay attempt or a jamming attack.

Using `general-glo-ciphering` (`0xDB`) for everything hides the service class,
at the cost of 8 extra octets for the system-title field. **[INFER]** That is a
reasonable trade for high-value associations and is worth considering in a
threat model where traffic analysis matters.

---

## 13.8 Firmware: the complete processing paths

### 13.8.1 Transmit

```c
int dlms_protect_apdu(dlms_security_context_t *ctx,
                      const uint8_t *apdu, size_t apdu_len,
                      uint8_t *out, size_t out_cap, size_t *out_len)
{
    uint8_t  iv[12], aad[1 + 32], sc;
    uint32_t ic;
    size_t   aad_len = 0;
    int      rc;

    /* 1 ── Determine required protection: the STRONGER of policy and
            access rights. [GB] 9.2.2.4                              */
    sec_control_t s = { .suite         = ctx->suite,
                        .authenticated = required_auth(ctx),
                        .encrypted     = required_enc(ctx),
                        .broadcast     = ctx->use_broadcast_key,
                        .compressed    = false };
    sc = sc_encode(&s);

    /* 2 ── Obtain the next invocation counter. Fails if exhausted.  */
    rc = ic_next(&ic);
    if (rc != OK) return rc;                 /* [GB] 9.2.3.3.7.3     */

    /* 3 ── Build the IV from OUR OWN system title.                  */
    build_iv(ctx, DIR_OUTGOING, ic, iv);

    /* 4 ── Build the AAD per [GB] Table 38.                         */
    if (s.authenticated) {
        aad[aad_len++] = sc;                         /* SC           */
        memcpy(aad + aad_len, ctx->ak, ctx->key_len);/* AK           */
        aad_len += ctx->key_len;
        if (!s.encrypted) {                          /* auth-only:   */
            memcpy(aad + aad_len, apdu, apdu_len);   /* ...‖ APDU    */
            aad_len += apdu_len;                     /* (see note)   */
        }
    }

    /* 5 ── Emit tag, length, security header.                       */
    /*      ... A-XDR length encoding omitted for brevity ...        */

    /* 6 ── Run GCM. For auth-only, P is EMPTY.                      */
    if (s.encrypted)
        rc = gcm_encrypt(ctx->ek_handle, iv, aad, aad_len,
                         apdu, apdu_len, ciphertext_out, tag_out, 12);
    else
        rc = gcm_encrypt(ctx->ek_handle, iv, aad, aad_len,
                         NULL, 0,        NULL,           tag_out, 12);

    /* 7 ── For auth-only, the APDU is emitted in CLEARTEXT.         */
    return rc;
}
```

**[IMPL] Note on step 4, auth-only.** Copying the whole APDU into an AAD buffer
is wasteful on a constrained part. A better implementation streams it: call
`gcm_aad_update(sc)`, `gcm_aad_update(ak)`, `gcm_aad_update(apdu, len)` and let
GHASH consume it incrementally. Then the AAD buffer only needs to hold
`SC ‖ AK` — 17 or 33 octets. Any GCM API that forces a single contiguous AAD
buffer will force you to allocate `1 + keylen + max_apdu_len`, which on a
1500-octet PDU is 1533 bytes of RAM you did not need to spend.

### 13.8.2 Receive

```c
int dlms_unprotect_apdu(dlms_security_context_t *ctx,
                        const uint8_t *in, size_t in_len,
                        uint8_t *apdu_out, size_t cap, size_t *apdu_len)
{
    /* 1 ── Parse tag, length, SC, IC.                               */
    uint8_t  tag = in[0];
    sec_control_t s;
    sc_decode(sc_octet, &s);
    uint32_t ic = be32(ic_octets);

    /* 2 ── Validate the SC byte. See §9.2.3 checklist.              */
    if (s.suite != ctx->suite)             return ERR_WRONG_SUITE;
    if (!protection_sufficient(&s, ctx))   return ERR_INSUFFICIENT;
    if (uses_dedicated_or_general(tag) && s.broadcast)
                                           return ERR_MALFORMED;

    /* 3 ── REPLAY CHECK, before any crypto.                         */
    if (ic == 0xFFFFFFFFu)                 return ERR_IC_EXHAUSTED;
    if (ic <  ctx->ic_rx_floor)            return ERR_REPLAY;

    /* 4 ── Build the IV from the PEER's system title.               */
    uint8_t iv[12];
    build_iv(ctx, DIR_INCOMING, ic, iv);

    /* 5 ── Select the key indicated by the Key_Set bit.             */
    key_handle_t ek = s.broadcast ? ctx->gbek
                    : ctx->dedicated_present ? ctx->dedicated_key
                    : ctx->guek;

    /* 6 ── Rebuild the AAD exactly as the sender did, using the SC
            AS RECEIVED — not a locally assumed value.               */

    /* 7 ── Decrypt and verify. NOTHING is released unless the tag
            verifies. [GB] 9.2.2.5                                   */
    if (gcm_decrypt_verify(ek, iv, aad, aad_len,
                           ct, ct_len, rx_tag, 12, apdu_out) != OK) {
        secure_zero(apdu_out, ct_len);
        return ERR_TAG_MISMATCH;
    }

    /* 8 ── ONLY NOW advance the replay floor.                       */
    ctx->ic_rx_floor = ic + 1u;

    /* 9 ── Dispatch to the APDU parser.                             */
    return OK;
}
```

**The ordering in steps 3, 7, and 8 is the security-critical part** and is
worth stating as a rule: **check the counter before decrypting; advance the
counter only after the tag verifies; never let the parser see unverified
bytes.**

---

## 13.9 Volume 2 summary

1. AES has a 128-bit block regardless of key size. Suite 2 changes key length,
   not block or IV or tag length.
2. GCM = CTR encryption + GHASH authentication. GMAC is GCM with `P = ∅`.
3. `len(C) == len(P)`. AES decryption is never invoked by GCM.
4. **[SPEC]** The tag is 96 bits in all three suites, taken from the MSB end.
5. **[SPEC]** SC byte: bit 7 compression, bit 6 Key_Set, bit 5 E, bit 4 A,
   bits 3..0 suite. (Not the other way round — this is a common error.)
6. **[SPEC]** The authentication key goes in the **AAD**, never in the key slot
   and never on the wire.
7. **[SPEC]** Auth-only ⇒ AAD = `SC ‖ AK ‖ APDU`, `P` empty. Authenticated
   encryption ⇒ AAD = `SC ‖ AK`, `P` = APDU.
8. **[SPEC]** IV = System Title (8) ‖ Invocation Counter (4), always 12 octets.
   The IV uses the **originator's** System Title.
9. Nonce reuse breaks confidentiality *and* authenticity. Persist the counter;
   on doubt, jump forward, never back; fail closed rather than reset to zero.
10. **[SPEC]** TX and RX counters are separate. Advance the RX floor only after
    a successful tag verification.
11. All seven official test vectors in [GB] Tables 40 and 43 are reproduced in
    this volume and verified. Use them as your firmware self-test.

---

**Next: Volume 3 — key architecture and hierarchy, AES key wrap and the KEK,
global vs dedicated ciphering, ECDSA from elliptic curves upward, ECDH, the
three key agreement schemes, the NIST Concatenation KDF, and X.509 certificates
in DLMS.**

*End of Volume 2.*

---

← **Previous:** [Volume 1 — Foundations and Association Security](VOL-1-Foundations-and-Association-Security.md)  ·  **Next:** [Volume 3 — Keys, PKI and Key Agreement](VOL-3-Keys-PKI-and-Key-Agreement.md) →

[Back to the index](00-INDEX.md)
