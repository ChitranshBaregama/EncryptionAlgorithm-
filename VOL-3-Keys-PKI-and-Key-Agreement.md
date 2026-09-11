# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 3 — Key Architecture, Key Establishment, and Public Key Cryptography**
*Chapters 14–19*

> Prerequisites: Volume 0 (claim labels), Volume 1, Volume 2.

---

# CHAPTER 14 — THE COMPLETE KEY ARCHITECTURE

## 14.1 Why there are so many keys

A single key would be simpler. DLMS uses many because each answers a different
question about **blast radius** — what an attacker gains from stealing it.

**[SPEC]** [GB] 9.2.5.1 classifies symmetric keys along two axes:

```
                    BY PURPOSE                    BY LIFETIME
   ┌──────────────────────────────┐   ┌────────────────────────────────┐
   │ Key Encrypting Key (KEK)     │   │ STATIC — long-lived            │
   │   encrypts/decrypts other    │   │   · global (across many AAs)   │
   │   symmetric keys.            │   │       GUEK, GBEK, GAK          │
   │   "In DLMS/COSEM this is     │   │   · dedicated (one AA only)    │
   │    the master key."          │   │                                │
   ├──────────────────────────────┤   ├────────────────────────────────┤
   │ Encryption key               │   │ EPHEMERAL — "used generally    │
   │   the AES-GCM block          │   │   for a single exchange        │
   │   cipher key                 │   │   within an AA"                │
   ├──────────────────────────────┤   └────────────────────────────────┘
   │ Authentication key           │
   │   "used as Additional        │
   │    Authenticated Data (AAD)  │
   │    in the AES-GCM algorithm" │
   └──────────────────────────────┘
```

**[SPEC]** Direct quotes from [GB] 9.2.5.1 worth having exactly:

> *"a key encrypting key (KEK) is used to encrypt / decrypt other symmetric
> keys … **In DLMS/COSEM this is the master key**."*
>
> *"a global key that may be used over several AAs established repeatedly
> between the same partners. A global key may be a unicast encryption key
> (GUEK), a broadcast encryption key (GBEK) or an authentication key (GAK)."*
>
> *"a dedicated key that may be used repeatedly during a single AA established
> between two partners. Therefore, its lifetime is the same as the lifetime of
> the AA. **A dedicated key can be only a unicast encryption key.**"*

That last sentence is a constraint people get wrong: **there is no dedicated
authentication key and no dedicated broadcast key.** If you see "DAK" in a
design document, it does not exist.

---

## 14.2 The key hierarchy

```
                    ┌───────────────────────────────────┐
                    │      MASTER KEY  =  KEK           │
                    │  Established OUT OF BAND only     │
                    │  Wraps every other symmetric key  │
                    │  NEVER transmitted in plaintext   │
                    └─────────────────┬─────────────────┘
                                      │ AES key wrap (RFC 3394)
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
   ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
   │  GUEK              │  │  GBEK              │  │  GAK               │
   │  Global Unicast    │  │  Global Broadcast  │  │  Global            │
   │  Encryption Key    │  │  Encryption Key    │  │  Authentication Key│
   │                    │  │                    │  │                    │
   │  GCM block cipher  │  │  GCM block cipher  │  │  Placed in the AAD │
   │  key, unicast      │  │  key, broadcast    │  │  NEVER on the wire │
   │  SC bit 6 = 0      │  │  SC bit 6 = 1      │  │  Used with BOTH    │
   └─────────┬──────────┘  └────────────────────┘  └────────────────────┘
             │
             │ wraps / protects
             ▼
   ┌────────────────────┐         ┌────────────────────────────────┐
   │  DEDICATED KEY     │         │  EPHEMERAL ENCRYPTION KEY      │
   │  Unicast only      │         │  Single exchange               │
   │  Lifetime = the AA │         │  Established by key wrap or    │
   │  Carried in the    │         │  key agreement, carried in the │
   │  InitiateRequest,  │         │  key-info field of             │
   │  protected by GUEK │         │  general-ciphering             │
   └────────────────────┘         └────────────────────────────────┘

   ══════════ SEPARATE, ASYMMETRIC BRANCH (suites 1 and 2) ══════════

   ┌─────────────────────────────┐  ┌──────────────────────────────┐
   │ DIGITAL SIGNATURE KEY PAIR  │  │ KEY AGREEMENT KEY PAIR       │
   │  static private key d       │  │  static  (d_s , Q_s)         │
   │  static public key  Q = dG  │  │  ephemeral (d_e , Q_e)       │
   │  Certificate C(DataSign)    │  │  Certificate C(KeyAgree)     │
   │  Used by: ECDSA, HLS mech 7 │  │  Used by: ECDH schemes       │
   └─────────────────────────────┘  └──────────────────────────────┘

   ══════════ AUTHENTICATION CREDENTIALS (separate from all above) ══

   ┌─────────────────────────────┐  ┌──────────────────────────────┐
   │ LLS PASSWORD                │  │ HLS SECRET                   │
   │  "secret" attribute of the  │  │  "secret" attribute of the   │
   │  Association SN/LN object   │  │  Association SN/LN object    │
   │  Sent in cleartext in AARQ  │  │  Used by HLS mech 3, 4, 6    │
   │  change_LLS_secret          │  │  change_HLS_secret           │
   └─────────────────────────────┘  └──────────────────────────────┘
```

**[SPEC]** [GB] Table 20 assigns establishment methods:

| Key | Establishment methods |
|-----|----------------------|
| Master key / KEK | **Out of band**; key wrap; key agreement via C(2e,0s) |
| GUEK | Key wrap; key agreement via C(2e,0s) |
| GBEK | Key wrap; key agreement via C(2e,0s) |
| GAK | Key wrap; key agreement via C(2e,0s) |
| Dedicated key | **Key transport in xDLMS InitiateRequest APDU** |
| Ephemeral encryption key | Key wrap; key agreement via C(1e,1s) or C(0e,2s) |

Note the asymmetry: the master key is the only one that can be established out
of band, and everything else can be bootstrapped from it. That is the whole
point of a KEK.

---

## 14.3 Key-by-key property tables

The prompt asked for a full property table per key. Here they are.

### 14.3.1 Master Key / Key Encrypting Key (KEK)

| Property | Value |
|----------|-------|
| **Name** | Master key; Key Encrypting Key (KEK) |
| **Purpose** | **[SPEC]** *"used to encrypt / decrypt other symmetric keys"* — [GB] 9.2.5.1 |
| **Size** | **[SPEC]** 128 bits (suites 0, 1); 256 bits (suite 2) — [GB] 9.2.3.3.7.7 |
| **Lifetime** | Longest of any key. Often the device lifetime. |
| **Scope** | One client–server pair. **[SPEC]** *"this method can be used only between parties sharing the master key, i.e. between a client and a server"* — [GB] 9.2.5.4 |
| **Stored where** | Server: **[SPEC]** held by a "Security setup" object. Physically: OTP / secure element / eFuse. See Volume 5. |
| **Used by** | AES key wrap (RFC 3394), wrap and unwrap |
| **Transmitted?** | **NEVER in plaintext.** Only wrapped under a *previous* KEK, or established by C(2e,0s) key agreement, or injected out of band. |
| **Wrapped?** | It can itself be re-keyed by wrapping the new KEK under the old one |
| **Risk if compromised** | **Total.** An attacker can unwrap every key transfer, past and future, and inject arbitrary new keys. Full and permanent device compromise. |
| **Rotation** | Rarely, and painfully — requires the old KEK to install the new one. **[INFER]** In practice most deployments never rotate it, which is why its physical protection is the most important storage decision you make. |

### 14.3.2 Global Unicast Encryption Key (GUEK)

| Property | Value |
|----------|-------|
| **Name** | GUEK. **Field shorthand "GEK" is common but is not the specification term.** |
| **Purpose** | **[SPEC]** *"Block cipher key for unicast xDLMS APDUs and/or COSEM Data"* — [GB] Table 20 |
| **Size** | 128 / 128 / 256 bits by suite |
| **Lifetime** | **[SPEC]** Static, global — *"may be used over several AAs established repeatedly between the same partners"* |
| **Scope** | One client–server pair (or a client and a population, if provisioned identically — **[INFER]** a common and dangerous shortcut) |
| **Stored where** | "Security setup" object; NVM / secure element |
| **Used by** | AES-GCM as EK, in `glo-*`, `general-glo-ciphering`, and `general-ciphering` with `identified-key` |
| **Selected by** | **[SPEC]** SC bit 6 = 0, or `key-id = global-unicast-encryption-key` |
| **Transmitted?** | No |
| **Wrapped?** | Yes, for `key_transfer` |
| **Risk if compromised** | All unicast traffic to/from this meter is readable **and forgeable** if the GAK is also known. With GUEK alone and GAK unknown, traffic is readable but tags cannot be forged. **Past recorded traffic is decryptable** — no forward secrecy in suite 0. |
| **Rotation** | **[SPEC]** Via `key_transfer` (wrapped under KEK) or C(2e,0s) key agreement. **[SPEC]** On establishment the invocation counters reset to 0 — [GB] 9.2.3.3.7.3. |

### 14.3.3 Global Broadcast Encryption Key (GBEK)

| Property | Value |
|----------|-------|
| **Purpose** | **[SPEC]** *"Block cipher key for broadcast xDLMS APDUs and/or COSEM Data"* |
| **Size** | Same as GUEK |
| **Scope** | **A whole population of meters.** This is its defining property. |
| **Selected by** | **[SPEC]** SC bit 6 = 1, or `key-id = global-broadcast-encryption-key` |
| **Risk if compromised** | **Fleet-wide.** Any single compromised meter yields the key for the entire broadcast group. |
| **[INFER] Design rule** | Treat GBEK-protected content as *authenticated but not confidential*. Never broadcast anything you would not accept a hostile group member reading. Prefer SC `0x50` (authentication only, broadcast) over `0x70`. |

### 14.3.4 Global Authentication Key (GAK)

| Property | Value |
|----------|-------|
| **Name** | GAK; "AK" in the formulas |
| **Purpose** | **[SPEC]** *"Part of AAD to the ciphering process of xDLMS APDUs and/or COSEM data"* — [GB] Table 20 |
| **Size** | **[SPEC]** *"For its length and its generation, the same rules apply as for the encryption key"* — [GB] 9.2.3.3.7.5 |
| **Scope** | **[SPEC]** *"All APDUs between client-server and third party-server"* — used with **both** GUEK and GBEK |
| **Used by** | AES-GCM AAD construction; HLS mechanism 5 |
| **Transmitted?** | **Never — not even in ciphertext.** It appears only inside the AAD, which is authenticated but not sent. |
| **Risk if compromised** | Alone: an attacker can *verify* tags but not decrypt. Combined with GUEK: **full forgery capability** — arbitrary valid APDUs. |
| **[INFER] Note** | The GAK is a single key shared across unicast *and* broadcast. There is no separate broadcast authentication key. So a compromised GBEK plus the GAK gives forgery on the broadcast channel — and the GAK is on every meter. |

### 14.3.5 Dedicated key

| Property | Value |
|----------|-------|
| **Purpose** | **[SPEC]** *"Block cipher key of unicast xDLMS APDUs, within an established AA"* |
| **Size** | Same as GUEK |
| **Lifetime** | **[SPEC]** *"the same as the lifetime of the AA"* |
| **Direction** | **[SPEC]** *"A dedicated key can be only a unicast encryption key"* |
| **Established by** | **[SPEC]** *"generated by the DLMS/COSEM client and transported to the server in the dedicated-key field of the xDLMS InitiateRequest APDU, carried by the user-information field of the AARQ"* — [GB] 9.2.5.1 |
| **Protected by** | **[SPEC]** *"the xDLMS InitiateRequest APDU shall be authenticated and encrypted using the AES-GCM-128 / 256 algorithm, the global unicast encryption key and — if in use — the authentication key"* |
| **Used with** | `ded-*` service-specific APDUs, `general-ded-ciphering` |
| **SC Key_Set bit** | **[SPEC]** *"not relevant and shall be set to zero"* |
| **Risk if compromised** | Confined to one association. Traffic from other associations, and past traffic, remain protected. |
| **[INFER] Value** | This is DLMS's blast-radius reduction mechanism inside suite 0. It is the closest thing suite 0 has to session keys. |

### 14.3.6 Ephemeral encryption key

| Property | Value |
|----------|-------|
| **Purpose** | **[SPEC]** *"used generally for a single exchange within an AA"* |
| **Established by** | Key wrap under KEK, or key agreement C(1e,1s) / C(0e,2s) |
| **Carried in** | **[SPEC]** the `key-info` field of the `general-ciphering` APDU |
| **Scope** | One exchange. Discarded afterwards. |
| **Risk if compromised** | One message. |
| **Enables** | Third-party end-to-end security, where the third party has no global keys |

### 14.3.7 Asymmetric keys

**[SPEC]** [GB] Table 22 classifies these by purpose and lifetime.

| Key | Purpose | Held by | Certificate | Transmitted? |
|-----|---------|---------|-------------|--------------|
| **Digital signature private key** `d` | **[SPEC]** *"Signatory uses private key to compute digital signature: on xDLMS APDUs; and/or on COSEM data; or on an ephemeral public key agreement key"* | Signatory only | — | **Never** |
| **Digital signature public key** `Q` | Verification | Anyone | `C(DataSign)` | Yes, in the certificate |
| **Static key agreement private key** `d_s` | ECDH, C(1e,1s) party V, C(0e,2s) both | Owner only | — | **Never** |
| **Static key agreement public key** `Q_s` | ECDH | Anyone | `C(KeyAgree)` | Yes |
| **Ephemeral key agreement private key** `d_e` | C(2e,0s) both, C(1e,1s) party U | Owner, transiently | — | **Never** |
| **Ephemeral key agreement public key** `Q_e` | C(2e,0s), C(1e,1s) | Peer | — | Yes, **signed** with the digital signature key |

**[SPEC]** A rule from [GB] 9.2.3.4.1 that matters for provisioning:

> *"Keys used for one purpose shall not be used for other purposes."*

So the signature key pair and the key agreement key pair are **different key
pairs**, with **different certificates**. Reusing one for both is a
specification violation and a real cryptographic hazard (cross-protocol
attacks).

### 14.3.8 LLS password and HLS secret

| Property | LLS password | HLS secret |
|----------|--------------|------------|
| **Held by** | **[SPEC]** the "Association SN/LN" object's `secret` | Same |
| **Used by** | LLS authentication (mechanism 1) | HLS mechanisms 3, 4, 6 |
| **Not used by** | — | **HLS mechanism 5** (uses GAK/GUEK) or **7** (uses the private signature key) |
| **Transmitted?** | **Yes, in cleartext in the AARQ** | No — only a transform of it |
| **Changed by** | `change_LLS_secret` | `change_HLS_secret` |
| **Risk if compromised** | An attacker can open an association. Whether that gains them anything depends entirely on message security. | Same, plus they can impersonate the *meter* to a client. |

---

## 14.4 Key confusion — the four pairs that must never be mixed

Quality Rules 6 and 7 in your prompt. State these as invariants:

| Confusion | Why it is fatal |
|-----------|-----------------|
| **GUEK vs GAK** | GUEK is the GCM *block cipher key*. GAK goes in the *AAD*. Swapping them produces a valid-looking but wrong tag, and the failure is invisible in a capture. |
| **GEK vs KEK** | GUEK protects messages; KEK protects keys. Using the KEK as a message key exposes the key-wrapping key to chosen-plaintext exposure on every APDU. |
| **GUEK vs dedicated key** | Different lifetimes. Using the global key where the dedicated key is indicated defeats the entire blast-radius reduction. |
| **System Title vs Invocation Counter** | Both are IV components. The System Title is 8 octets, per-device, constant. The IC is 4 octets, per-message, incrementing. Swapping the split point produces a wrong IV and a tag mismatch. |

**[IMPL]** Enforce these in the type system, not by convention:

```c
/* Distinct opaque types so the compiler catches a swap. */
typedef struct { key_handle_t h; } enc_key_t;   /* GUEK/GBEK/dedicated */
typedef struct { key_handle_t h; } auth_key_t;  /* GAK                 */
typedef struct { key_handle_t h; } kek_t;       /* master key          */

int gcm_protect(enc_key_t ek, auth_key_t ak, /* ... */);
int aes_wrap   (kek_t kek,   const uint8_t *plain_key, /* ... */);
```

A `kek_t` passed where an `enc_key_t` is expected is now a compile error. It
costs nothing and removes an entire class of catastrophic bug.

---

# CHAPTER 15 — KEY WRAPPING, THE KEK, AND KEY TRANSFER

## 15.1 The problem key wrap solves

You need to install a new GUEK in a meter 200 km away, over a link an attacker
can read. You cannot send the key in the clear. You cannot encrypt it with the
key you are replacing (if that key were trustworthy you would not be replacing
it). You need a *separate* key whose only job is protecting other keys.

That is the KEK, and the operation is **key wrap**.

**[SPEC]** [GB] 9.2.3.3.6, quoting NIST SP 800-21:

> *"Symmetric key algorithms may be used to wrap (i.e., encrypt) keying
> material using a key-wrapping key (also known as a key encrypting key). The
> wrapped keying material can then be stored or transmitted securely.
> Unwrapping the keying material requires the use of the same key-wrapping key
> that was used during the original wrapping process."*
>
> *"**Key wrapping differs from simple encryption in that the wrapping process
> includes an integrity feature.** During the unwrapping process, this integrity
> feature detects accidental or intentional modifications to the wrapped keying
> material. For the purposes of DLMS/COSEM the AES key wrap algorithm shall be
> used."*

---

## 15.2 AES Key Wrap — RFC 3394

**[SPEC]** [GB] 9.2.3.3.7.7:

> *"For wrapping key data DLMS/COSEM has selected the AES key wrap algorithm
> specified in RFC 3394. The algorithm is designed to wrap or encrypt key data.
> It operates on blocks of 64 bits. Before being wrapped, the key data is
> parsed into n blocks of 64 bits. The only restriction the key wrap algorithm
> places on n is that n has to be at least two."*
>
> *"The inputs to the key wrapping process are the Key Encrypting Key KEK and
> the plaintext to be wrapped. The plaintext consists of n 64-bit blocks,
> containing the key data being wrapped. The output is the ciphertext,
> (n+1) 64 bit values."*
>
> *"The inputs to the unwrap process are the KEK and (n+1) 64-bit blocks of
> ciphertext consisting of previously wrapped key. It returns n blocks of
> plaintext consisting of the n 64-bit blocks of the decrypted key data."*

### 15.2.1 Sizes

```
   Suite 0 / 1:   128-bit key  =  2 semiblocks  →  wrapped = 3 × 64 = 192 bits
                                                             = 24 octets
   Suite 2:       256-bit key  =  4 semiblocks  →  wrapped = 5 × 64 = 320 bits
                                                             = 40 octets
```

**[IMPL]** The +8 octets is the integrity check. Size your `key_transfer`
buffers accordingly; a common bug is allocating 16 octets for a wrapped
128-bit key.

**[SPEC]** KEK size, [GB] 9.2.3.3.7.7: *"for security suite 0 and 1, 128 bits
… for security suite 2, 256 bits."*

### 15.2.2 The algorithm shape

RFC 3394 wraps by iterating a mixing function 6 times over all semiblocks:

```
   Initialise:
       A    = A6A6A6A6A6A6A6A6            ← the fixed Initial Value (IV)
       R[i] = P[i]        for i = 1..n

   for j = 0 to 5:
       for i = 1 to n:
           B    = AES-Encrypt(KEK, A ‖ R[i])
           A    = MSB64(B) XOR (n*j + i)   ← counter mixed into A
           R[i] = LSB64(B)

   Output:  C[0] = A ,  C[i] = R[i]        → (n+1) semiblocks
```

Unwrap runs the inverse with AES **decryption**, then checks that the recovered
`A` equals `A6A6A6A6A6A6A6A6`. If it does not, the unwrap **fails** — the key
data is rejected.

**Three consequences [IMPL]:**

1. **AES decryption is required.** Unlike GCM. If your firmware supports key
   unwrap, you need the inverse cipher and its key schedule — budget the flash.
2. **6n AES operations per wrap.** For n=2 that is 12 block operations. Cheap.
3. **The integrity check is the constant `A6A6...`**, not a MAC. It gives
   roughly 64 bits of assurance that the KEK was right and the data intact — a
   deliberate design, adequate for key data.

**[INFER] Why not just use AES-GCM to wrap keys?** You could, and it would also
give integrity. RFC 3394 was chosen because it is deterministic — **no IV, no
nonce**. That matters enormously here: key transfer is exactly the situation
where you cannot rely on the invocation counter being synchronised, and a
nonce-reuse bug during key installation would be catastrophic. AES key wrap
removes the nonce from the problem entirely.

---

## 15.3 What can be established by key wrap

**[SPEC]** [GB] 9.2.5.4:

> *"Key wrap can be used to establish static or ephemeral symmetric keys. The
> algorithm is the AES key wrap algorithm … **The KEK is the master key.**
> Consequently, this method can be used only between parties sharing the master
> key, i.e. between a client and a server."*
>
> *"The static keys that can be established using key wrap may be:*
> - *the master key, KEK; and/or*
> - *the global unicast encryption key GUEK; and/or*
> - *the global broadcast encryption key GBEK; and/or*
> - *the (global) authentication key, GAK."*

Note that **the master key can wrap a new master key.** That is how KEK
rotation works.

**[SPEC]** The transfer mechanism:

> *"To establish these static keys using key wrap, the key shall be first
> generated by the client, then it shall be transferred to the server by
> invoking the `key_transfer` method of the 'Security setup' object … The method
> invocation parameter shall carry the key_id(s) and the wrapped key(s). The
> APDU carrying the service that invokes the method and the method invocation
> parameters shall be protected as required by the security policy and the
> access rights."*

And for ephemeral keys:

> **[SPEC]** *"To establish an ephemeral key using key wrap, the originator of
> the xDLMS APDU or the COSEM data randomly generates an ephemeral key. This
> key shall be wrapped using the AES key wrap algorithm and the KEK and shall
> be sent to the recipient together with the xDLMS APDU or the COSEM data that
> have been ciphered using the ephemeral key. The recipient shall unwrap the
> key then it shall use it to decipher the xDLMS APDU / COSEM data received."*

This is the `wrapped-key` choice of `key-info` in `general-ciphering` — see
Volume 2 §13.4.

---

## 15.4 The key transfer flow

```
   ┌─────────────────────────────────────────────────────────────────┐
   │ CLIENT (Head-End System)                                        │
   └─────────────────────────────────────────────────────────────────┘

     ① Generate a new GUEK from a CSPRNG
        [SPEC] "shall be generated uniformly at random, or close to
         uniformly at random" — [GB] 9.2.3.3.7.4

        new_GUEK = 16 random octets

     ② Wrap it under the master key
        wrapped = AES-KeyWrap(KEK, new_GUEK)        → 24 octets

     ③ Build the key_transfer method invocation
        parameter = { key_id = global-unicast-encryption-key,
                      key_wrapped = wrapped }

     ④ Protect the APDU carrying the ACTION
        [SPEC] "shall be protected as required by the security policy
         and the access rights" — [GB] 9.2.5.4
        → glo-action-request (0xCB), SC = 0x30, under the CURRENT GUEK

                    ────────────► transmit ────────────►

   ┌─────────────────────────────────────────────────────────────────┐
   │ SERVER (Meter)                                                  │
   └─────────────────────────────────────────────────────────────────┘

     ⑤ Verify the tag on the incoming APDU.  Fail → discard, no change.

     ⑥ Check access rights on the key_transfer method.
        Fail → reject with a method-access error.

     ⑦ Unwrap:  new_GUEK = AES-KeyUnwrap(KEK, wrapped)
        The integrity check (A6A6...) must pass.
        Fail → reject. DO NOT install anything.

     ⑧ Install atomically:
          · write new_GUEK to protected storage
          · [SPEC] reset the associated invocation counters to 0
            ("when the key is established the corresponding ICs are
             reset to 0" — [GB] 9.2.3.3.7.3)

     ⑨ Respond with success, PROTECTED UNDER THE OLD KEY

                    ◄──────────── response ◄────────────

     ⑩ Client, on receiving success, switches to the new GUEK.
```

**[IMPL] Step ⑨ is the one people get wrong.** The response to a key change
must be protected under the **old** key. If the meter switches keys before
responding, the client cannot verify the response, and neither side knows the
state. Switch on the transmit path only after the response has been handed to
the lower layer.

**[IMPL] Step ⑧ must be atomic with respect to power loss.** A meter that loses
power between writing the key and resetting the counter comes back with a new
key and a stale counter — which is safe (counters only go up) — but a meter
that resets the counter first and then fails to write the key comes back with
the **old key and a zeroed counter**. That is nonce reuse. Order the operations:
write key, then reset counter, and make the whole thing journalled. See
Volume 5 §27.

---

## 15.5 Why the KEK must never be transported in plaintext

Trace the dependency:

```
   KEK compromised
        │
        ├──► attacker unwraps every past key_transfer they recorded
        │       └──► learns every GUEK, GBEK, GAK ever installed
        │              └──► decrypts all recorded traffic, forever
        │
        ├──► attacker wraps their OWN keys and injects a key_transfer
        │       └──► meter now uses attacker-chosen keys
        │              └──► full control of the meter's communications
        │
        └──► attacker wraps a new KEK and installs it
                └──► the legitimate operator is LOCKED OUT
```

The last branch is the one that turns a security incident into a field
replacement programme. There is no recovery path that does not involve
physically visiting the meter.

**[SPEC]** Hence [GB] Table 20 lists the KEK's establishment as **"Out of
band"** — plus, once one exists, wrapping and C(2e,0s) key agreement.

**[IMPL] Storage rule.** The KEK is the one key that should never exist in
application-accessible RAM. Use a secure element, a key ladder, or at minimum
an OTP region with a hardware-enforced read lock engaged before application
code starts. Volume 5 §28 develops the options.

---

## 15.6 Cryptoperiods

**[SPEC]** [GB] 9.2.5.6:

> *"Symmetric key cryptoperiods should be determined in project specific
> companion specifications. Recommendations are given in NIST SP 800-57:2007
> Part 1 5.3.5 Symmetric Key Usage Periods and Cryptoperiods and 5.3.6
> Cryptoperiod Recommendations for Specific Key Types."*

The Green Book deliberately does not mandate values. **[VENDOR]** Your national
companion specification (IDIS, DSMR, IS 15959, G3-PLC profile, etc.) probably
does — check it.

**[INFER] A hard bound the specification does impose implicitly:** the
invocation counter is 32 bits, so a GUEK can protect at most 2³²−1 messages.
That is a cryptoperiod ceiling regardless of what any companion specification
says, and it is the one your firmware must enforce.

---

# CHAPTER 16 — GLOBAL VERSUS DEDICATED CIPHERING

## 16.1 The comparison

| Dimension | **Global ciphering** | **Dedicated ciphering** |
|-----------|---------------------|------------------------|
| **Key** | GUEK or GBEK | Dedicated key |
| **Lifetime** | **[SPEC]** *"over several AAs established repeatedly between the same partners"* | **[SPEC]** *"the same as the lifetime of the AA"* |
| **Scope** | Unicast **or** broadcast | **[SPEC]** Unicast only |
| **Provisioning** | Out of band, key wrap, or key agreement | **[SPEC]** Generated by the client, sent in the `dedicated-key` field of the InitiateRequest |
| **APDU tags** | `glo-*` (0xC8–0xCF), `general-glo-ciphering` (0xDB) | `ded-*` (0xD0–0xD7), `general-ded-ciphering` (0xDC) |
| **SC Key_Set bit** | 0 = unicast, 1 = broadcast | **[SPEC]** *"not relevant and shall be set to zero"* |
| **Invocation counter** | Persists across associations; must survive power loss | Resets with the new key at each association |
| **Blast radius if compromised** | Every association with this peer, past and future | One association |
| **Performance** | No setup cost | One extra GCM operation on the InitiateRequest; one RNG draw |
| **Implementation complexity** | Lower | Higher — must decrypt an embedded APDU before the AA exists |

---

## 16.2 The dedicated key handshake

```
  CLIENT                                                     SERVER
    │                                                           │
    │ ① generate dedicated_key = 16 random octets               │
    │                                                           │
    │ ② build the xDLMS InitiateRequest containing:             │
    │      dedicated-key      = dedicated_key                   │
    │      proposed-conformance, max PDU sizes, etc.            │
    │                                                           │
    │ ③ PROTECT it with AES-GCM under the GLOBAL unicast key    │
    │      SC = 0x30, IV = Sys-T_client ‖ IC_client             │
    │      AAD = SC ‖ GAK                                       │
    │      → glo-initiateRequest, tag 0x21                      │
    │                                                           │
    │ ④ place it in user-information [30] of the AARQ           │
    │                                                           │
    │───── AARQ (tag 0x60, NOT protected) ────────────────────► │
    │        └── user-information                               │
    │              └── 0x21 glo-initiateRequest (PROTECTED)     │
    │                                                           │
    │                        ⑤ server locates the security      │
    │                           context from (client SAP,       │
    │                           server SAP) — BEFORE the AA     │
    │                           is established                  │
    │                        ⑥ decrypt + verify with GUEK       │
    │                        ⑦ extract dedicated_key            │
    │                        ⑧ install for this AA only         │
    │                                                           │
    │◄──── AARE (tag 0x61) ─────────────────────────────────────│
    │        └── user-information                               │
    │              └── 0x28 glo-initiateResponse (PROTECTED     │
    │                        under the GLOBAL key)              │
    │                                                           │
    │  ═══ from here, ded-* APDUs use the dedicated key ═══     │
    │                                                           │
    │───── ded-get-request (0xD0) ─────────────────────────────►│
    │◄──── ded-get-response (0xD4) ─────────────────────────────│
    │                                                           │
    │───── RLRQ ───────────────────────────────────────────────►│
    │      dedicated key DISCARDED on both sides                │
```

**[SPEC]** Confirming quotes from [GB] 9.2.5.1:

> *"When the dedicated key is present, the xDLMS InitiateRequest APDU shall be
> authenticated and encrypted using the AES-GCM-128 / 256 algorithm, the global
> unicast encryption key and — if in use — the authentication key. The xDLMS
> InitiateResponse APDU, carried by the user-information field of the AARE APDU
> shall be also encrypted and authenticated the same way."*
>
> *"NOTE The AARQ and the AARE APDUs themselves are not protected."*

---

## 16.3 Why dedicated keys reduce blast radius

```
   ── WITHOUT dedicated keys ────────────────────────────────────────

   GUEK compromised at time T
        │
        └──► ALL traffic decryptable:
                 · every association before T (if recorded)
                 · every association after T (until rotation)

   ── WITH dedicated keys ───────────────────────────────────────────

   Dedicated key for association #4728 compromised
        │
        └──► only association #4728 is readable
             associations #4727 and #4729 use different random keys

   GUEK compromised at time T
        │
        └──► attacker can decrypt the InitiateRequest of every
             association and thereby recover each dedicated key
             → equivalent to the no-dedicated-key case
```

**[INFER] The honest assessment.** Dedicated keys reduce blast radius against
*key extraction from a single session* — a side-channel attack on one exchange,
a leaked session key, a cryptanalytic break with limited data. They do **not**
provide forward secrecy against GUEK compromise, because the dedicated key is
transported *under* the GUEK. Anyone who later obtains the GUEK and has
recorded the AARQ recovers every dedicated key.

True forward secrecy requires ephemeral Diffie-Hellman, which means suite 1 or
2 and the C(2e,0s) scheme. That is the honest boundary of what suite 0 can do.

**[IMPL] Practical guidance.** Use dedicated ciphering when:

- The link carries long sessions with many APDUs (limits data under one key).
- You are concerned about side-channel leakage from repeated GCM operations
  under one key.
- The invocation counter management for the global key is awkward and a fresh
  per-AA counter simplifies things.

Skip it when the meter is severely constrained and associations are short —
the added complexity of pre-association decryption is a real source of bugs.

---

# CHAPTER 17 — ECDSA

## 17.1 Elliptic curves from first principles

**[SPEC]** [GB] 9.2.3.4.2.1:

> *"Elliptic curve cryptography involves arithmetic operations on an elliptic
> curve over a finite field. Elliptic curves can be defined over any field of
> numbers (i.e., real, integer, complex) although they are most often used over
> finite prime fields for applications in cryptography."*
>
> *"An elliptic curve on a prime field consists of the set of real numbers
> (x, y) that satisfy the equation:*
>
>     y² = x³ + ax + b
>
> *The set of all of the solutions to the equation forms the elliptic curve.
> Changing a and b changes the shape of the curve, and small changes in these
> parameters can result in major changes in the set of (x, y) solutions."*

### 17.1.1 The finite field

In cryptography we do not use real numbers. We work modulo a large prime `p`:

```
   y² ≡ x³ + ax + b   (mod p)
```

The solutions form a finite set of points — a few hundred bits' worth. For
P-256, `p` is a 256-bit prime.

### 17.1.2 Point addition and the group

Given two points on the curve, there is a geometric rule (chord-and-tangent)
that produces a third point on the curve. This makes the points a **group**
under addition. Adding a point to itself repeatedly gives scalar
multiplication:

```
   2G = G + G
   3G = G + G + G
   kG = G added to itself k times      ← computed in O(log k) by
                                          double-and-add
```

### 17.1.3 The hard problem

```
   Given G and Q = dG, find d.
```

This is the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**. Computing
`Q` from `d` is fast. Recovering `d` from `Q` is believed infeasible — the best
known generic attack is Pollard's rho at roughly `√n` operations, i.e. ~2¹²⁸ for
P-256.

**[SPEC]** [GB] 9.2.3.4.1 explains the selection:

> *"The RSA algorithm is based on the prime factorization of very large
> integers. Elliptic Curve Cryptography (ECC) is based on the difficulty of
> solving the Elliptic Curve Discrete Logarithm Problem (ECDLP). **ECC provides
> similar levels of security compared to RSA but with significantly reduced key
> sizes. ECC is particularly suitable for embedded devices** and therefore it
> has been selected for use in DLMS/COSEM."*

```
   Comparable security:
      RSA-3072   ≈   ECC P-256    (128-bit security)
      RSA-7680   ≈   ECC P-384    (192-bit security)

   Key sizes:
      RSA-3072 public key  = 384 octets
      P-256 public key     =  64 octets     ← 6× smaller
```

For a meter with 8 KB of RAM, that ratio is decisive.

---

## 17.2 The domain parameters

**[SPEC]** [GB] 9.2.6.2 and Table 13. A curve is fully specified by:

```
   D = (q, FR, a, b {, domain_parameter_seed}, G, n, h)

   q  — the field size (the prime p)
   FR — field representation
   a, b — the curve coefficients in y² = x³ + ax + b
   G  — the base point (generator)
   n  — the order of G: the smallest positive integer with nG = O
   h  — the cofactor
```

**[SPEC]** [GB] Table 13:

| DLMS security suite | Curve name in FIPS PUB 186-4 | ASN.1 Object Identifier |
|--------------------|------------------------------|-------------------------|
| Suite 0 | – | – |
| **Suite 1** | **NIST curve P-256** | **1.2.840.10045.3.1.7** |
| **Suite 2** | **NIST curve P-384** | **1.3.132.0.34** |

> **[SPEC]** *"NOTE The ASN.1 Object Identifier appears in the Certificate
> under AlgorithmIdentifier: Parameters."*

**[SPEC]** [GB] 9.2.3.4.2.2: *"FIPS PUB 186-4 recommends five prime field
elliptic curves over a prime field GF(p). Of these, the curves P-256 and P-384
have been selected for DLMS/COSEM."*

The full parameter values are in [GB] Annex A, Table A.1.

**[SPEC]** [GB] 9.2.6.2 imposes a validation requirement:

> *"Prior to generating ECDSA key pairs, assurance of the validity of the
> domain parameters (q, FR, a, b {, domain_parameter_seed}, G, n, h) shall have
> been obtained."*

**[IMPL]** In practice on a meter this means: hard-code the NIST curve
parameters in flash and never accept them from the wire. A device that accepts
attacker-supplied domain parameters can be steered onto a weak curve — the
"invalid curve attack" — where the ECDLP is easy and the private key is
recovered from a handful of exchanges. This is a real, demonstrated attack
class. **Never parse curve parameters from a certificate; parse only the curve
*OID* and look up the parameters locally.**

---

## 17.3 Key pair generation

**[SPEC]** [GB] 9.2.6.2:

> *"An ECC key pair d and Q is generated for a set of domain parameters …
> Two methods are provided for the generation of the ECC private key d and
> public key Q; one of these two methods shall be used to generate d and Q. …
> For details, see FIPS PUB 186-4 Annex B.4"*

```
   1. Generate d uniformly at random in [1, n-1]
   2. Compute Q = dG
   3. The pair is (d, Q)
```

**[IMPL] The entire security of the key pair rests on step 1.** A biased or
predictable `d` is recoverable. Chapter 30 (Volume 5) covers RNG requirements.
FIPS 186-4 B.4 gives two methods — "testing candidates" and "extra random
bits" — both designed to eliminate modulo bias. Do **not** simply take
`random_256_bits() mod n`; that biases the low values.

---

## 17.4 ECDSA — signing and verifying

**[SPEC]** [GB] 9.2.3.4.5:

> *"For DLMS/COSEM the elliptic curve digital signature (ECDSA) algorithm as
> specified in FIPS PUB 186-4 has been selected. … In DLMS/COSEM the elliptic
> curves and algorithms used shall be:*
> - *in the case of Security Suite 1, the elliptic curve P-256 with the SHA-256
>   hash algorithm;*
> - *in the case of Security Suite 2, the elliptic curve P-384 with the SHA-384
>   hash algorithm."*

### 17.4.1 Signature generation

**[SPEC]** *"The inputs to ECDSA digital signature generation are the
following: the message M to be signed; … the private key of the signatory, d.
The output is the ECDSA signature (r, s) over M."*

```
   1.  e = Hash(M)                        SHA-256 or SHA-384
   2.  Choose a random per-signature nonce k ∈ [1, n-1]
   3.  (x₁, y₁) = kG
   4.  r = x₁ mod n         ;  if r == 0, go back to step 2
   5.  s = k⁻¹ (e + r·d) mod n  ;  if s == 0, go back to step 2
   6.  Signature = (r, s)
```

**[SPEC]** *"NOTE 1 In the DLMS/COSEM context 'Message' may be a xDLMS APDU,
see 9.2.7.2 or COSEM data, see 9.2.7.5."*

### 17.4.2 Signature verification

**[SPEC]** *"The inputs to the verification … are the following: the signed
message M'; the received ECDSA signature (r', s'); the authentic public key of
the signatory, Q."*

```
   1.  Reject unless 1 ≤ r' ≤ n-1 and 1 ≤ s' ≤ n-1
   2.  e = Hash(M')
   3.  w  = s'⁻¹ mod n
   4.  u₁ = e·w mod n ,  u₂ = r'·w mod n
   5.  (x₁, y₁) = u₁G + u₂Q
   6.  Accept iff  x₁ mod n == r'
```

**[SPEC]** *"The process of generating and verifying the signatures shall be as
specified in NSA1 3.4."*

### 17.4.3 The encoding — the interoperability trap

**[SPEC]** [GB] 9.2.3.4.5, quoted exactly because this is where
implementations fail:

> *"In DLMS/COSEM the plain format shall be used: the signature (r, s) is
> encoded as octet string R ‖ S, i.e. as concatenation of the octet strings
> R = I2OS(r, l) and S = I2OS(s, l) with l = ⌈log₂ n / 8⌉. Thus, the signature
> has a fixed length of 2·l octets."*
>
> *"NOTE 2 Here, n is the order of the base point G of the elliptic curve. I2OS
> is the Integer to Octet String Conversion Primitive."*

```
   P-256:  l = 32  →  signature is EXACTLY 64 octets
   P-384:  l = 48  →  signature is EXACTLY 96 octets

   Layout:  [ r : l octets, left-zero-padded ] ‖ [ s : l octets, padded ]
```

**[IMPL] This is NOT the DER format** that OpenSSL, mbedTLS, and most TLS
stacks emit by default:

```
   DER (WRONG for DLMS):
     30 45 02 21 00 A1 B2 ... 02 20 3C 4D ...
     │  │  │  │  │            │  │
     │  │  │  │  │            │  └─ 32-octet s
     │  │  │  │  │            └─ length
     │  │  │  │  └─ leading 00 because the high bit of r is set
     │  │  │  └─ length 0x21 = 33  ← VARIABLE
     │  │  └─ INTEGER
     │  └─ total length            ← VARIABLE: 70–72 octets for P-256
     └─ SEQUENCE

   DLMS plain format (CORRECT):
     A1 B2 ... (exactly 32) 3C 4D ... (exactly 32)   = 64 octets, always
```

Conversion is mechanical: parse the two DER INTEGERs, strip any leading `00`
that was added for the sign bit, then left-pad each to exactly `l` octets.

**[IMPL] The bug that bites once a year in production:** roughly 1 signature in
256 has an `r` or `s` whose most significant octet is zero. A library that
strips leading zeros then emits 63 or 62 octets. Everything works in testing;
occasionally a signature is rejected by a strict peer. **Always pad to fixed
length.**

---

## 17.5 ECDSA in DLMS — where and why

**[SPEC]** Three uses, from [GB] Table 22:

> *"Signatory uses private key to compute digital signature: on xDLMS APDUs;
> and/or on COSEM data; or **on an ephemeral public key agreement key**."*

| Use | APDU / mechanism | Purpose |
|-----|------------------|---------|
| Signing xDLMS APDUs | `general-signing` (0xDF) | Non-repudiable message origin |
| Signing COSEM data | "Data protection" objects, [GB] 9.2.7.5 | Non-repudiable data (e.g. billing registers) |
| **Signing an ephemeral public key** | `key-info` → `agreed-key` in `general-ciphering` | **Authenticating the C(1e,1s) key agreement** |
| HLS authentication | mechanism_id(7) | Mutual authentication without a shared secret |

That third row is important and easy to miss. In the C(1e,1s) scheme, party U
sends an ephemeral public key. Without a signature over it, an
attacker could substitute their own — a classic man-in-the-middle on
Diffie-Hellman. **[SPEC]** [GB] Table 21 closes this: the `key-ciphered-data`
for C(1e,1s) is *"the public key Q_e,U of the ephemeral key agreement key pair
of party U, **signed with the private digital signature key of party U**."*

**ECDSA is what authenticates ECDH.** That is the cleanest statement of how the
two relate, and it is the answer to "why do we need both".

---

## 17.6 What ECDSA does and does not do

| ECDSA **does** | ECDSA **does NOT** |
|----------------|--------------------|
| Prove the message came from the private key holder | **Encrypt anything** |
| Prove the message was not modified | Provide confidentiality |
| Provide non-repudiation | Establish a shared key |
| Bind an identity (via certificate) to a message | Protect against replay by itself |

**[SPEC]** The specification's own words, [GB] 9.2.3.4.1 NOTE 2: *"Asymmetric
key algorithms are not used for encryption in DLMS/COSEM."*

Quality Rule 9 in your prompt. A `general-signing` APDU has its `content` field
**in the clear** — signing adds authenticity, not secrecy. **[SPEC]** [GB]
9.2.7.3: *"If both ciphering and digital signature is applied by the same party
for the same party, then normally the digital signature is applied first"* —
i.e. sign then encrypt, using two nested APDUs.

---

## 17.7 The `k` catastrophe

**[THEORY]** The per-signature nonce `k` in step 2 must be **secret, unique,
and unpredictable**. If any of these fails, the private key is recovered:

**If `k` is reused across two signatures:**

```
   s₁ = k⁻¹(e₁ + r·d)
   s₂ = k⁻¹(e₂ + r·d)      ← same k ⇒ same r

   s₁ - s₂ = k⁻¹(e₁ - e₂)
   ⇒  k = (e₁ - e₂) / (s₁ - s₂)          ← k recovered
   ⇒  d = (s₁·k - e₁) / r                ← PRIVATE KEY recovered
```

Two signatures, a few lines of arithmetic, and the key is gone. This is exactly
how the Sony PlayStation 3 signing key was extracted in 2010.

**If `k` is merely biased** — even a few bits — lattice techniques recover `d`
from a few hundred signatures.

**[IMPL] Mitigations for a meter:**

1. Use a proper DRBG seeded from a hardware TRNG, freshly for every signature.
2. **Better: use deterministic ECDSA (RFC 6979)**, which derives `k` from
   `HMAC(d, e)`. This removes the RNG from the signing path entirely and is
   fully interoperable — verification is unchanged.
   > **[INFER]** RFC 6979 is not mentioned by [GB]. It produces standard ECDSA
   > signatures that any verifier accepts, so it is a safe unilateral choice.
   > **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** if your project
   > companion specification constrains nonce generation.
3. Never log, expose, or debug-print `k`.

---

# CHAPTER 18 — ECDH AND THE KEY AGREEMENT SCHEMES

## 18.1 ECDH from first principles

The problem: Alice and Bob have never met and share no secret. They must agree
on a key over a channel an attacker reads completely.

```
   Alice                          Bob
   d_A random                     d_B random
   Q_A = d_A · G                  Q_B = d_B · G

        ──────── Q_A ─────────►
        ◄─────── Q_B ──────────

   Alice computes:  Z = d_A · Q_B  =  d_A · d_B · G
   Bob   computes:  Z = d_B · Q_A  =  d_B · d_A · G

   Same point.  Same shared secret.
```

The attacker sees `G`, `Q_A`, `Q_B` and must compute `d_A·d_B·G` — the Elliptic
Curve Computational Diffie-Hellman problem, as hard as the ECDLP.

**[SPEC]** [GB] 9.2.3.4.6.1:

> *"Key agreement allows two entities to jointly compute a shared secret and
> derive secret keying material from it. See also NIST SP 800-56A Rev. 2: 2013.
> For DLMS/COSEM three elliptic curve key agreement schemes have been selected
> from NIST SP 800-56A Rev. 2: 2013:*
> - *the Ephemeral Unified Model C(2e, 0s, ECC CDH) scheme;*
> - *the One-Pass Diffie-Hellman C(1e, 1s, ECC CDH) scheme;*
> - *the Static Unified Model C(0e, 2s, ECC CDH) scheme."*

**Critically: `Z` is never used directly as a key.** It is passed through a KDF.

---

## 18.2 Reading the C(xe, ys) notation

```
   C ( 2e , 0s , ECC CDH )
   │   │    │      │
   │   │    │      └─ the primitive: Elliptic Curve Cofactor
   │   │    │          Diffie-Hellman
   │   │    └─ number of STATIC key pairs contributed, total
   │   └─ number of EPHEMERAL key pairs contributed, total
   └─ "Cofactor" scheme family
```

| | Ephemeral key | Static key |
|--|---------------|------------|
| **Lifetime** | One exchange, then destroyed | Long-lived |
| **Certified?** | No — authenticated by a signature instead | Yes — bound by a certificate |
| **Provides forward secrecy?** | Yes | No |
| **Provides authentication?** | No, by itself | Yes, via the certificate |

The three schemes are three points on the trade-off between forward secrecy and
authentication.

---

## 18.3 Scheme 1 — Ephemeral Unified Model C(2e, 0s)

**[SPEC]** [GB] 9.2.3.4.6.2:

> *"This scheme is for use between a DLMS/COSEM client and a server to agree on
> the master key, on global encryption keys and/or on the authentication key.
> **The client plays the role of party U and the server plays the role of party
> V.** The process is supported by the methods of the 'Security setup'
> interface class."*
>
> *"The parties generate an ephemeral key pair from the domain parameters D.
> The parties exchange ephemeral public keys and then compute the shared secret
> Z using the domain parameters, their ephemeral private key and the ephemeral
> public key of the other party."*

```
                 U's Ephemeral Public Key
      U  ──────────────────────────────────────►  V
      (client)                                    (server)
         ◄──────────────────────────────────────
                 V's Ephemeral Public Key

   U:  Z = ECC_CDH( d_e,U , Q_e,V )        V:  Z = ECC_CDH( d_e,V , Q_e,U )
   U:  kdf(Z, OtherInput) ; destroy Z      V:  kdf(Z, OtherInput) ; destroy Z
```

**[SPEC]** Table 14 summary:

| | Party U (client) | Party V (server) |
|--|------------------|------------------|
| Static data | **N/A** | **N/A** |
| Ephemeral data | `d_e,U` , `Q_e,U` | `d_e,V` , `Q_e,V` |
| Computation | `Z = ECC_CDH(d_e,U, Q_e,V)` | `Z = ECC_CDH(d_e,V, Q_e,U)` |
| Derive | `kdf(Z, OtherInput)`; **destroy Z** | `kdf(Z, OtherInput)`; **destroy Z** |

**[SPEC]** Prerequisites, [GB] 9.2.3.4.6.2:

> 1. *"each party has an authentic copy of the same set of domain parameters,
>    D."*
> 2. *"the parties have agreed on using the NIST Concatenation KDF … SHA-256 is
>    the hash function to use with the domain parameters for P-256 and SHA-384
>    … for P-384"*
> 3. *"prior to or during the key agreement process, the parties obtain the
>    identifier associated with the other party"*

**What it establishes.** **[SPEC]** [GB] 9.2.5.5: the master key KEK, GUEK,
GBEK, and/or GAK — *"supported by the `key_agreement` method of the 'Security
setup' interface class."*

**Properties:**

- ✅ **Forward secrecy.** Both keys are ephemeral and destroyed. Compromising
  any long-term key later does not reveal `Z`.
- ❌ **No authentication built in.** Both keys are ephemeral and uncertified,
  so nothing binds them to an identity. **[INFER]** This is why [GB] 9.2.5.5
  requires that *"The APDUs carrying the service that invokes the method as
  well as the method invocation parameters shall be protected as required by
  the security policy and the access rights"* — the authentication comes from
  the surrounding protected association, not from the scheme itself.

**[INFER] This is the scheme that gives suite 1/2 forward secrecy for the
global keys.** Run C(2e,0s) periodically to re-key GUEK/GAK, and an attacker
who later extracts the current keys cannot decrypt previously recorded traffic.

---

## 18.4 Scheme 2 — One-Pass Diffie-Hellman C(1e, 1s)

**[SPEC]** [GB] 9.2.3.4.6.3:

> *"This scheme is for use by a DLMS/COSEM server and another party to agree on
> an ephemeral encryption key to protect xDLMS APDUs or COSEM data. **The party
> sending the message (the originator) plays the role of party U and the other
> party (the recipient) plays the role of party V.**"*
>
> *"NOTE 1 The terms originator and recipient refer to fields of the
> general-ciphering APDU."*
>
> *"For this scheme, party U generates an ephemeral key pair; party V has only a
> static key pair. **Party U obtains Party V's static public key in a trusted
> manner (for example, from a certificate signed by a trusted CA)** and sends
> its ephemeral public key to party V."*

```
                 V's Static Public Key
      U  ◄──────────────────────────────────────  V
      (originator)                                (recipient)
         ──────────────────────────────────────►
                 U's Ephemeral Public Key
                 (SIGNED with U's ECDSA key)

   U:  Z = ECC_CDH( d_e,U , Q_s,V )
   V:  Z = ECC_CDH( d_s,V , Q_e,U )
```

**[SPEC]** Table 15:

| | Party U (originator) | Party V (recipient) |
|--|---------------------|---------------------|
| Static data | N/A | `d_s,V` , `Q_s,V` |
| Ephemeral data | `d_e,U` , `Q_e,U` | N/A |
| Computation | `Z = ECC_CDH(d_e,U, Q_s,V)` | `Z = ECC_CDH(d_s,V, Q_e,U)` |

**Why "one-pass".** Only one message is needed. U can compute `Z` and send the
protected message immediately, because V's static key was already known. There
is no round trip. **[INFER]** For a battery-powered meter or a high-latency PLC
link, this is a decisive advantage — key agreement costs zero extra messages.

**[SPEC]** The default choice, [GB] 9.2.5.5 NOTE 2:

> *"Unless specified otherwise in a project specific companion specification,
> the C(1e, 1s ECC CDH) scheme shall be used."*

**On the wire.** **[SPEC]** [GB] Table 21, `key-info` → `agreed-key`:

```
   key-parameters    = 0x01                    ← C(1e, 1s ECC CDH)
   key-ciphered-data = Q_e,U  signed with U's private digital signature key
```

**Properties:**

- ✅ **Partial forward secrecy.** U's key is ephemeral. But compromising
  `d_s,V` lets an attacker recompute `Z` for every recorded exchange, because
  `Q_e,U` was sent in the clear. So: forward secrecy against U's compromise,
  **none** against V's.
- ✅ **V is authenticated** by its certificate.
- ✅ **U is authenticated** by the ECDSA signature over its ephemeral public
  key.

---

## 18.5 Scheme 3 — Static Unified Model C(0e, 2s)

**[SPEC]** [GB] 9.2.3.4.6.4:

> *"In this case, the parties use only static key pairs. Each party obtains the
> other party's static public key. **A nonce, Nonce_U, is sent by party U to
> party V to ensure that the derived keying material is different for each
> key-establishment transaction.**"*

```
      U  ◄────── V's Static Public Key ────────►  V
         ◄────── U's Static Public Key ────────►
         ──────────── Nonce_U ─────────────────►

   U:  Z = ECC_CDH( d_s,U , Q_s,V )
   V:  Z = ECC_CDH( d_s,V , Q_s,U )
   Both: DerivedKeyingMaterial = kdf(Z, ... Nonce_U ...)
```

**[SPEC]** On the wire, [GB] Table 21:

```
   key-parameters    = 0x02                    ← C(0e, 2s ECC CDH)
   key-ciphered-data = "an octet-string of length zero"
                        (no key material is sent — U supplies Nonce_U instead)
```

**[SPEC]** Table 17 tells you where `Nonce_U` comes from: it is the
**`transaction-id`** field of the `general-ciphering` APDU, contributed as part
of `PartyUInfo`.

**[SPEC]** The critical warning, [GB] 9.2.3.4.6.4 NOTE 2, quoted in full:

> *"The value of Z is the same in all C(0e, 2s) key-establishment transactions
> between the same two parties, therefore **if it is ever compromised, then all
> of the keying material derived in past, current, and future C(0e, 2s)
> key-agreement transactions between these same two entities that employ these
> same static key pairs may be compromised as well.** Any shared secret Z that
> is not 'zeroized' shall be stored and used with the same security protections
> as private keys."*

**Properties:**

- ❌ **No forward secrecy at all.** `Z` is a fixed function of two long-term
  keys.
- ✅ **Both parties authenticated** by certificates.
- ✅ **Zero key-exchange messages.** Only a nonce, which rides in a field that
  was going to be there anyway.
- ⚠️ **`Z` must be protected like a private key.** Cache it and you have created
  a new long-term secret to defend. Recompute it and you pay a full ECDH per
  message.

**[INFER] When to choose it.** Only when the message budget is so tight that
you cannot afford to carry a 64/96-octet ephemeral public key, and forward
secrecy is genuinely not required. On most links C(1e,1s) is the better trade.

---

## 18.6 The three schemes compared

| | **C(2e, 0s)** Ephemeral Unified | **C(1e, 1s)** One-Pass DH | **C(0e, 2s)** Static Unified |
|--|-------------------------------|--------------------------|------------------------------|
| **[SPEC] Purpose** | Agree master key, GUEK, GBEK, GAK | Agree ephemeral encryption key | Agree ephemeral encryption key |
| **[SPEC] Parties** | Client ↔ Server | Server ↔ another party | Server ↔ another party |
| **Party U** | Client | Originator | Originator |
| **Party V** | Server | Recipient | Recipient |
| **U contributes** | ephemeral pair | ephemeral pair | static pair + `Nonce_U` |
| **V contributes** | ephemeral pair | static pair | static pair |
| **Messages needed** | 2 (exchange) | 1 | 1 (nonce only) |
| **`key-parameters` value** | — (uses `key_agreement` method) | **`0x01`** | **`0x02`** |
| **`key-ciphered-data`** | — | signed `Q_e,U` | zero-length string |
| **Forward secrecy** | ✅ Full | ⚠️ Partial (U only) | ❌ None |
| **U authenticated by** | surrounding protected AA | ECDSA signature on `Q_e,U` | certificate |
| **V authenticated by** | surrounding protected AA | certificate | certificate |
| **Z reused across transactions** | No | No | **Yes — must be protected** |
| **Cost per use** | 2 keygen + 2 ECDH | 1 keygen + 1 ECDH + 1 sign | 1 ECDH (or cache Z) |
| **[SPEC] Supported by** | `key_agreement` method of "Security setup" | `key-info` of `general-ciphering` | `key-info` of `general-ciphering` |

---

## 18.7 The NIST Concatenation KDF

`Z` is a curve point coordinate — structured, not uniformly random. It must
never be used as a key directly. **[SPEC]** [GB] 9.2.3.4.6.5 specifies the
derivation.

> *"The NIST Concatenation KDF as specified in NIST SP 800-56A Rev. 2: 2013
> 5.8.1.1 and NSA2:2009 Clause 5 shall be used."*
>
> *"Function call: kdf(Z, OtherInput) where OtherInput consists of keydatalen
> and OtherInfo."*

### 18.7.1 Parameters

**[SPEC]**

| Parameter | Suite 1 | Suite 2 |
|-----------|---------|---------|
| Hash function `H` | **SHA-256** | **SHA-384** |
| `hashlen` | 256 bits | 384 bits |
| `keydatalen` | **128 bits** | **256 bits** |

> *"keydatalen: an integer that indicates the length (in bits) of the secret
> keying material to be generated: 128 bit for security suite 1 and 256 bit for
> security suite 2"*
>
> *"In DLMS/COSEM, key derivation delivers a **single key for a given
> purpose**. The length is as determined by the security suite."*

Since `keydatalen ≤ hashlen` in both suites, **one hash invocation suffices** —
no counter loop is needed. That is a useful simplification for firmware.

### 18.7.2 OtherInfo

**[SPEC]**

```
   OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo
                             {‖ SuppPubInfo} {‖ SuppPrivInfo}
```

> *"(Optional) SuppPubInfo … **Not used in DLMS/COSEM**."*
> *"(Optional) SuppPrivInfo … **Not used in DLMS/COSEM**."*

**[SPEC]** [GB] Table 17 — the field layout:

| Subfield | Substring | C(2e,0s) | C(1e,1s) | C(0e,2s) | Length (octets) | Value |
|----------|-----------|----------|----------|----------|-----------------|-------|
| `AlgorithmID` | | Fixed | Fixed | Fixed | **7** | See Table 18 |
| `PartyUInfo` | | Fixed | Fixed | Variable | **8 + n** | — |
| | `ID_U` | Fixed | Fixed | Fixed | **8** | `originator-system-title` |
| | `Nonce_U` | – | – | Variable | `n` | Datalen = length of `transaction-id` (1 octet); Data = value of `transaction-id` |
| `PartyVInfo` | | Fixed | Fixed | Fixed | **8** | — |
| | `ID_V` | Fixed | Fixed | Fixed | **8** | `recipient-system-title` |

> **[SPEC]** *"'originator-system-title', 'transaction-id' and
> 'recipient-system-title' are the fields of the general-ciphering APDU"*

**Note what this means:** the derived key is cryptographically bound to *who is
talking to whom* (both system titles) and *for what algorithm*. Even with the
same `Z`, a different originator or recipient produces a different key. That
kills key-substitution and identity-misbinding attacks.

### 18.7.3 AlgorithmID — the OIDs

**[SPEC]** [GB] Table 18 and Table 76:

| Algorithm | COSEM cryptographic algorithm ID | Encoded value (7 octets) |
|-----------|----------------------------------|--------------------------|
| **AES-GCM-128** | `2.16.756.5.8.3.0` | `60 85 74 06 08 03 00` |
| **AES-GCM-256** | `2.16.756.5.8.3.1` | `60 85 74 06 08 03 01` |
| **AES-WRAP-128** | `2.16.756.5.8.3.2` | `60 85 74 06 08 03 02` |
| **AES-WRAP-256** | `2.16.756.5.8.3.3` | `60 85 74 06 08 03 03` |

**[SPEC]** [GB] 9.4.2.2.4:

```
   COSEM_Cryptographic_Algorithm_Id ::=
     { joint-iso-ccitt(2) country(16) country-name(756)
       identified-organization(5) DLMS-UA(8)
       cryptographic-algorithms(3) algorithm_id(x) }
```

**[INFER] A note on the encoding.** The 7-octet encoding shown in Table 18
(`60 85 74 06 08 03 00`) uses `06` for the DLMS-UA arc, whereas the
authentication-mechanism and application-context OIDs in [GB] Table 74/75
encode DLMS-UA as `05 08`. This is an inconsistency in the printed table.

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — the exact octet
> encoding of the AlgorithmID substring used inside the KDF should be confirmed
> against a current edition and against a reference implementation before you
> rely on it for interoperability. Getting it wrong produces a derived key that
> differs from the peer's, with no diagnostic beyond "everything fails".
> **[IMPL]** Test this against a known-good peer early; it is not something you
> can discover from a capture.

### 18.7.4 The derivation

```
   1.  reps = ⌈ keydatalen / hashlen ⌉          ← always 1 in DLMS
   2.  counter = 00000001                       (32-bit big-endian)
   3.  K = H( counter ‖ Z ‖ OtherInfo )
   4.  DerivedKeyingMaterial = leftmost keydatalen bits of K
   5.  DESTROY Z
```

**[SPEC]** Both Tables 14, 15, and 16 end with the same instruction:
**"Destroy Z."** This is a specification requirement, not advice.

**[IMPL]**

```c
/* Z must not survive the derivation. */
uint8_t Z[48];
ecdh_compute(&Z, d_local, Q_peer);
kdf_concat(Z, z_len, other_info, oi_len, derived_key, key_len);
secure_zero(Z, sizeof Z);           /* mandatory — [GB] Tables 14/15/16 */
```

Use a `secure_zero()` the compiler cannot elide (`memset_s`, an explicit
volatile write loop, or a memory barrier). A plain `memset` on a
soon-to-be-out-of-scope buffer is a legal target for dead-store elimination,
and optimising compilers do remove it.

---

# CHAPTER 19 — CERTIFICATES AND PKI

## 19.1 The trust model

**[SPEC]** [GB] 9.2.6.3.2:

> *"A public key certificate binds a public key to an identity: the subject. A
> certificate is digitally signed by a Certification Authority."*
>
> *"To provide and manage the certificates, some form of Public Key
> Infrastructure is required. A PKI consists of Certification Authorities
> issuing certificates and end entities using these certificates."*
>
> *"In its simplest form, a certification hierarchy consists of a single CA.
> However, the hierarchy usually contains multiple CAs that have clearly
> defined parent-child relationships. It is also possible to deploy multiple
> hierarchies."*
>
> *"The PKI needs a **trust anchor** that is used to validate the first
> certificate in a sequence of certificates. The trust anchor may be a Root-CA
> certificate, a Sub-CA certificate or a **directly trusted key**."*

**[SPEC]** And the provisioning requirement that shapes your manufacturing
process:

> *"DLMS/COSEM servers **shall be provisioned with one or more trust anchors
> during manufacturing using a trusted Out of Band (OOB) process.**"*

That is a *shall*. The trust anchor cannot arrive over the wire — there would
be nothing to validate it against. It is a factory operation.

---

## 19.2 The PKI architecture

**[SPEC]** [GB] 9.2.6.3.3, marked **informative**:

> *"NOTE 2 The actual structure of the PKI is left to project specific
> companion specifications to meet the operators' needs."*

```
                        ┌──────────────────────┐
                        │      Root-CA         │
                        │  C(Root) self-signed │
                        │  + Certificate       │
                        │    Revocation List   │
                        └──────────┬───────────┘
                                   │ signs C(Sub-CA)
                    ┌──────────────┴──────────────┐
                    ▼                             ▼
          ┌───────────────────┐         ┌───────────────────┐
          │     Sub-CA        │         │     Sub-CA        │
          │  C(Root)          │         │  C(Root)          │
          │  C(Sub-CA)        │         │  C(Sub-CA)        │
          │  + CRL            │         │  + CRL            │
          └─────────┬─────────┘         └─────────┬─────────┘
                    │ signs end-entity certs      │
        ┌───────────┴───────────┐     ┌───────────┴──────────┐
        ▼                       ▼     ▼                      ▼
   ┌──────────┐          ┌──────────┐ ┌──────────┐    ┌──────────┐
   │End entity│          │End entity│ │End entity│    │End entity│
   │ C(Root)  │          │          │ │          │    │          │
   │ C(Sub-CA)│          │  ...     │ │   ...    │    │   ...    │
   │ C(KeyAgree)                    │ │          │    │          │
   │ C(DataSign)                    │ │          │    │          │
   │ C(TLS)   │          │          │ │          │    │          │
   └──────────┘          └──────────┘ └──────────┘    └──────────┘
```

**[SPEC]** Roles:

> **Root-CA** — *"provides the trust anchor of the PKI. It issues certificates
> for Sub-CAs and maintains a certificate revocation list (CRL). … The
> Certificate of the Root-CA is self-signed with the Root-CA private key."*
>
> **Sub-CA** — *"an organisation that issues certificates for end entities.
> Each Sub-CA is authorised by the Root-CA to do so. … NOTE Sub-CAs may be
> independent organizations, or may be meter market participants, meter
> operators, manufacturers."*
>
> **End entities** — *"DLMS/COSEM clients, DLMS/COSEM servers and third
> parties"*

**[SPEC]** The three end-entity certificate types, [GB] 9.2.6.3.3.4:

| Certificate | Purpose |
|-------------|---------|
| `C(digitalSignature)` / `C(DataSign)` | *"used for digital signature"* — ECDSA, HLS mech 7 |
| `C(keyAgreement)` / `C(KeyAgree)` | *"used for key agreement"* — static ECDH key for C(1e,1s), C(0e,2s) |
| `C(TLS)` *(optional)* | *"used for performing authentication between a DLMS/COSEM client and a DLMS/COSEM server prior the establishment of a TLS secure channel"* |

**[INFER]** Note the separation: **signature and key agreement use different
key pairs and different certificates.** This enforces [GB] 9.2.3.4.1's rule
that *"Keys used for one purpose shall not be used for other purposes."*

---

## 19.3 The X.509 v3 certificate profile

**[SPEC]** [GB] 9.2.6.4.1:

> *"All certificates shall have the structure specified for X.509 version 3
> certificates."*
>
> *"Each certificate extension is designated either as critical or
> non-critical. **A certificate-using system MUST reject the certificate if it
> encounters a critical extension it does not recognize** or a critical
> extension that contains information that it cannot process. A non-critical
> extension MAY be ignored if it is not recognized, but MUST be processed if it
> is recognized."*
>
> *"This Technical Report specifies minimum requirements. Project specific
> companion specifications may specify more strict requirements."*

Notation: `m` = mandatory, `o` = optional, `x` = do not use.

### 19.3.1 Certificate structure

**[SPEC]** [GB] Table 23:

```
   Certificate ::= SEQUENCE {
       tbsCertificate       m
       signatureAlgorithm   m
       signatureValue       m
   }
```

**[SPEC]** The signature algorithm identifiers:

| Algorithm | OID | Used in |
|-----------|-----|---------|
| `ecdsa-with-SHA256` | **1.2.840.10045.4.3.2** | Security suite 1 |
| `ecdsa-with-SHA384` | **1.2.840.10045.4.3.3** | Security suite 2 |

**[SPEC]** *"The `signatureValue` contains a digital signature computed upon
the ASN.1 DER encoded `tbsCertificate`. The ASN.1 DER encoded tbsCertificate is
used as the input to the signature function."*

**[IMPL] Note the format collision.** Inside an X.509 certificate the
signature is **DER-encoded** per RFC 5280. In a DLMS `general-signing` APDU it
is **plain R‖S** per [GB] 9.2.3.4.5. Your firmware needs both encodings, and
they are not interchangeable. This is a genuine trap.

### 19.3.2 tbsCertificate fields

**[SPEC]** [GB] Table 24:

| Field | m/x/o | Comment |
|-------|-------|---------|
| Version | m | **`v3` (value is 2)** |
| Serial Number | m | *"assigned by the CA (not longer than 20 octets)"* |
| Signature | m | *"Same algorithm identifier as the signatureAlgorithm in the Certificate"* |
| Issuer | m | Distinguished name of the issuer |
| Validity | m | Validity of the certificate |
| Subject | m | Distinguished name of the subject |
| SubjectPublicKeyInfo | m | The public key + curve OID |
| Extensions | — | See §19.4 |

**[SPEC]** On validity, [GB] 9.2.6.3.2:

> *"Certificates generally have a validity period. However, **certificates
> issued to DLMS/COSEM servers may be indefinitely valid.** Certificates may be
> replaced when they expire."*

**[INFER] This concession exists because meters have unreliable clocks and
20-year field lives.** It is pragmatic and it is also a real weakening: an
indefinitely valid certificate cannot expire out of a compromise, so revocation
becomes the only remedy — and CRL distribution to millions of meters over
narrowband links is largely impractical. Understand this trade-off before you
adopt indefinite validity.

---

## 19.4 Certificate extensions

**[SPEC]** [GB] Table 28 (reconstructed), showing which extensions apply to
which certificate type:

| # | Extension | RFC 5280 | `C(Root)` | `C(Sub-CA)` | `C(TLS)` | `C(KeyAgree)` | `C(DataSign)` |
|---|-----------|----------|-----------|-------------|----------|---------------|---------------|
| 1 | AuthorityKeyIdentifier | 4.2.1.1 | | | | | |
| 2 | SubjectKeyIdentifier | 4.2.1.2 | | | | | |
| 3 | KeyUsage | 4.2.1.3 | m | m | m | m | m |
| 4 | CertificatePolicies | 4.2.1.4 | o | m | m | o | o |
| 5 | SubjectAltNames | 4.2.1.6 | o | o | o | o | o |
| 6 | IssuerAltNames | 4.2.1.7 | o | o | **x** | **x** | **x** |
| 7 | BasicConstraints | 4.2.1.9 | **m** | **m** | **x** | **x** | **x** |
| 8 | ExtendedKeyUsage | 4.2.1.12 | **x** | **x** | **m** | **x** | **x** |
| 9 | cRLDistributionPoints | 4.2.1.13 | o | o | **x** | **x** | **x** |

### 19.4.1 KeyUsage — critical

**[SPEC]** [GB] 9.2.6.4.4.4:

> - *Extension-ID (OID): **2.5.29.15***
> - *Critical: **TRUE***
> - *Description: the KeyUsage extension defines the purpose of the key
>   contained in the certificate*

**[SPEC]** [GB] Table 29 — the bits that shall be set:

| Certificate | Bits to be set |
|-------------|----------------|
| `C(Root)` | `keyCertSign`, `cRLSign` |
| `C(Sub-CA)` | `keyCertSign`, `cRLSign` |
| `C(TLS)` | `digitalSignature`, `keyAgreement` |
| `C(KeyAgree)` | `keyAgreement` |
| `C(DataSign)` | `digitalSignature` |

**[IMPL] This is your enforcement point for key separation.** When verifying an
ECDSA signature, check that the certificate carries `digitalSignature`. When
performing ECDH, check `keyAgreement`. A certificate presented for the wrong
purpose must be rejected. Because the extension is **critical**, a
certificate-using system that does not process it must reject the certificate
outright.

### 19.4.2 SubjectAltName — the System Title binding

**[SPEC]** [GB] 9.2.6.4.4.6, and this is a DLMS-specific detail you will not
find in generic X.509 guidance:

> - *Extension-ID (OID): **2.5.29.17***
> - *Critical: TRUE if the "subject" field of the certificate is empty (an
>   empty sequence), else FALSE*
>
> *"If the subject name is an empty sequence, then the `subjectAltName`
> extension MUST be added in the End Entity Signature and Key Establishment
> Certificates and MUST be marked as critical."*
>
> *"The SubjectAltName extension when used shall contain a single GeneralName
> of type OtherName that is further sub-typed as a **HardwareModuleName**
> (`id-on-HardwareModuleName`) as defined in IETF RFC 4108. **The `hwSerialNum`
> field shall be set to the system title.**"*

```
   SubjectAltName
     └── GeneralName: otherName
           └── HardwareModuleName  (RFC 4108, id-on-HardwareModuleName)
                 ├── hwType
                 └── hwSerialNum  ═══►  THE 8-OCTET SYSTEM TITLE
```

**[INFER] This is the bridge between the symmetric and asymmetric worlds.** The
System Title is the identity used in the IV for AES-GCM; here it is bound
cryptographically into the certificate. A verifier can therefore check that the
certificate presented in the AARQ belongs to the same device whose System Title
appears in the ciphered APDUs. **[IMPL] Do that check.** Without it, a valid
certificate for device A can be presented by device B.

### 19.4.3 Key identifiers

**[SPEC]** AuthorityKeyIdentifier (**OID 2.5.29.35**, critical: FALSE) and
SubjectKeyIdentifier (**OID 2.5.29.14**, critical: FALSE). Both use the same
`keyIdentifier` computation:

> *"with method 1 defined in RFC 5280:2008 4.2.1.2, i.e. the keyIdentifier is
> composed of the 160-bit SHA-1 hash of the value of the BIT STRING
> `SubjectPublicKey` (excluding the tag, length, and number of unused bits); or*
>
> *with method 2 …, i.e. the keyIdentifier is composed of a four-bit type field
> with the value 0100 followed by the least significant 60 bits of the SHA-1
> hash of the value of the BIT STRING `subjectPublicKey`"*
>
> *"NOTE The choice of the method is left to project specific companion
> specifications."*

**[INFER]** SHA-1 here is used only as an identifier, not for security — a
collision would cause an ambiguous chain lookup, not a forgery. Its use is not
a weakness in this role. But note that a meter must implement SHA-1 *as well as*
SHA-256/384 if it validates key identifiers.

### 19.4.4 Other extensions

**[SPEC]**

| Extension | OID | Critical | Notes |
|-----------|-----|----------|-------|
| CertificatePolicies | 2.5.29.32 | FALSE | *"contains the OID for the applicable certificate policy"* |
| IssuerAltName | 2.5.29.18 | FALSE | rfc822Name / URI, CA certificates only |
| BasicConstraints | 2.5.29.19 | — | Mandatory for `C(Root)` and `C(Sub-CA)`, forbidden for end entities |
| ExtendedKeyUsage | 4.2.1.12 | — | Mandatory for `C(TLS)` only |
| cRLDistributionPoints | 2.5.29.13 | — | CA certificates only |

---

## 19.5 Suite B certificate types

**[SPEC]** [GB] 9.2.6.5:

> *"Every DLMS/COSEM server must use X.509 v3 format and contain either: a
> P-256 or P-384 ECDSA-capable signing key; or a P-256 or P-384 ECDH-capable
> key agreement key."*
>
> *"**Every certificate must be signed using ECDSA. The signing CA's key must
> be P-256 or P-384 if the certificate contains a key on P-256. The signing
> CA's key must be P-384 if the certificate contains a key on P-384.**"*

That second rule is a one-way constraint worth stating plainly:

```
   P-256 end-entity key  →  may be signed by a P-256 or P-384 CA
   P-384 end-entity key  →  MUST be signed by a P-384 CA
```

You may not sign a stronger key with a weaker CA key.

**[SPEC]** [GB] Table 33 — the certificates DLMS/COSEM end entities must handle:

| Role | Security suite 1 | Security suite 2 |
|------|------------------|------------------|
| **Trust anchor** (may be more than one) | Root-CA self-signed, P-256 signed with P-256 | Root-CA self-signed, P-384 signed with P-384 |
| **Issuing CA** (Sub-CAs may also be trust anchors) | Sub-CA P-256 signed with P-256 | Sub-CA P-384 signed with P-384 |
| | — | Sub-CA P-256 signed with **P-384** |
| **ECDSA signature key** | End-entity P-256 signed with P-256 | End-entity P-384 signed with P-384 |
| | — | End-entity P-256 signed with **P-384** |
| **Key establishment** (C(1e,1s) or C(0e,2s)) | End-entity P-256 signed with P-256 | End-entity P-384 signed with P-384 |
| | — | End-entity P-256 signed with **P-384** |
| **TLS** | End-entity P-256 signed with P-256 | End-entity P-384 signed with P-384 |
| | — | End-entity P-256 signed with **P-384** |

> **[SPEC]** *"Example Certificates are given in Annex B."*

**[INFER]** Note that a suite-2 deployment must handle *both* curves — P-256
end-entity certificates signed by a P-384 CA are explicitly listed. So "suite 2
support" does not mean you can drop P-256 code. Budget flash for both.

---

## 19.6 Certificate verification

**[SPEC]** [GB] 9.2.6.3.2:

> *"Before a server uses a Certificate, it has to be verified. Verification
> includes:*
> - *checking syntactic validity of the certificate;*
> - *checking the attributes included in the certificate;*
> - *checking that the certificate validity period has not expired;*
> - *checking the certification path to the trust anchor;*
> - *checking the signature of the issuer of the certificate."*

```
   ┌────────────────────────────────────────────────────────────┐
   │ ① SYNTACTIC VALIDITY                                       │
   │    · DER parses cleanly, no trailing data                  │
   │    · Version == v3                                         │
   │    · Serial number ≤ 20 octets                             │
   │    · Reject on ANY unrecognised CRITICAL extension         │
   ├────────────────────────────────────────────────────────────┤
   │ ② ATTRIBUTES                                               │
   │    · KeyUsage matches the intended purpose                 │
   │    · BasicConstraints present iff it is a CA cert          │
   │    · SubjectAltName hwSerialNum == expected System Title   │
   │    · Curve OID is 1.2.840.10045.3.1.7 or 1.3.132.0.34      │
   ├────────────────────────────────────────────────────────────┤
   │ ③ VALIDITY PERIOD                                          │
   │    · notBefore ≤ now ≤ notAfter                            │
   │    ⚠ requires a trustworthy clock — see below              │
   ├────────────────────────────────────────────────────────────┤
   │ ④ CERTIFICATION PATH                                       │
   │    · chain each cert's Issuer to the next cert's Subject   │
   │    · terminate at a provisioned trust anchor               │
   │    · enforce the P-384-signs-P-384 rule                    │
   ├────────────────────────────────────────────────────────────┤
   │ ⑤ ISSUER SIGNATURE                                         │
   │    · ECDSA verify over the DER-encoded tbsCertificate      │
   │    · using the issuer's public key                         │
   │    · SHA-256 (suite 1) or SHA-384 (suite 2)                │
   └────────────────────────────────────────────────────────────┘
```

**[SPEC]** A significant simplification the Green Book grants:

> *"It is assumed that the trust anchor, other CA-certificates, as well as the
> certificates of DLMS/COSEM clients and third parties held by the server are
> all valid. **It is the responsibility of the system to replace / remove any
> certificates the validity of which have expired or that have been revoked.**"*

**[INFER] Read that carefully: the meter does not do revocation checking.** The
burden is pushed to the operator to actively remove revoked certificates using
`remove_certificate`. There is no OCSP, no CRL fetch on a meter. This is
realistic for a constrained device on a narrowband link, but it means
**revocation latency equals your field-management cycle time**, which may be
months. Factor that into your threat model.

**[IMPL] The clock problem.** Step ③ requires a trustworthy time source. A
meter whose RTC has reset to 1970 will reject every valid certificate; a meter
whose clock an attacker can set backwards will accept expired ones. Options:

- Accept indefinitely-valid server certificates (explicitly permitted).
- Use a monotonic counter or last-known-good-time floor that never moves
  backwards.
- Gate clock-setting behind a high-security association and treat a large
  backwards jump as a tamper event.

---

## 19.7 Certificate lifecycle management

**[SPEC]** [GB] 9.2.6.6.1 scopes this: *"This subclause applies only to the
management of public key certificates in DLMS/COSEM servers"* — management in
clients and third-party systems is out of scope.

### 19.7.1 Trust anchor provisioning

**[SPEC]** [GB] 9.2.6.6.2:

> *"Before starting steady state operations, servers shall be provisioned with
> trust anchors that will be used to validate the certificates. Trust anchors
> may be Root-CA (i.e. self-signed) certificates, Sub-CA certificates or
> directly trusted CA keys."*
>
> *"**Trust anchors shall be placed in the server out of band (OOB).**"*
>
> *"Trust anchor certificates are stored together with other certificates.
> **They can be exported, but they cannot be imported or removed.**
> Directly trusted CA keys cannot be exported."*

**[IMPL]** "Cannot be imported or removed" is a firmware requirement, not a
suggestion. Your `import_certificate` and `remove_certificate` handlers must
reject any attempt that targets a trust anchor. Otherwise an attacker installs
their own root and the entire PKI collapses.

### 19.7.2 Security personalisation

**[SPEC]** [GB] 9.2.6.6.4:

> *"Security personalisation means the provision of the server with asymmetric
> key pairs and the corresponding public key certificates. This can take place
> either:*
> - *using the security primitives provided by the manufacturer to inject the
>   private key and the public key certificates. **The private keys have to be
>   securely stored in the server and shall never be exposed**; or*
> - *using the appropriate methods of a 'Security setup' object."*

```
   Issuing CA          DLMS Client              DLMS Server (meter)
       │                    │                          │
       │                    │─── generate_key_pair ───►│
       │                    │      (digital signature /│
       │                    │       key agreement/TLS) │
       │                    │                          │ generate d, Q
       │                    │◄── SUCCESS / FAIL ───────│ store d securely
       │                    │                          │
       │                    │── generate_certificate ─►│
       │                    │   _request               │
       │                    │                          │ build CSR,
       │                    │                          │ SIGN with the new
       │                    │◄── X.509 v3 CSR ─────────│ private key
       │                    │                          │
       │◄── CSR ────────────│                          │
       │                    │                          │
       │─── X.509 v3 cert ─►│                          │
       │                    │                          │
       │                    │─── import_certificate ──►│
       │                    │                          │ VERIFY the cert
       │                    │                          │ add to certificates
       │                    │                          │   attribute
       │                    │◄── SUCCESS / FAIL ───────│
```

**[SPEC]** The four steps, from [GB] 9.2.6.6.4:

> *"Step 1: the client invokes the `generate_key_pair` method. The method
> invocation parameters specify the key pair to be generated: digital
> signature, key agreement or TLS key pair."*
>
> *"NOTE 1 The new key pair can be used in transactions once its certificate
> will have been imported and successfully verified."*
>
> *"Step 2: the client invokes the `generate_certificate_request` method. …
> The return parameters include the X.509 v3 CSR, **signed by the private key
> of the newly generated key pair**."*
>
> *"Step 3: The client sends the X.509 v3 CSR to the CA. … NOTE 2 The format of
> the messages between the client and the issuing CA is out of the Scope."*
>
> *"Step 4: The client invokes the `import_certificate` method. … The server
> verifies the certificate and if successful adds information on the
> certificate to the `certificates` attribute. **If the verification fails, the
> certificate shall be discarded.**"*

**[SPEC]** And a one-of-each rule:

> *"There may be **only one key pair and certificate present for the same
> purpose** (digital signature, key agreement, TLS). Therefore when the new
> certificate is successfully imported the old certificate is removed. From
> this point, the new key pair can be used for transactions."*

**[INFER] This creates a hard cutover with no overlap window.** Importing the
new certificate atomically retires the old one. If the head-end has not yet
learned the new certificate, verification of the meter's signatures fails until
it does. Sequence renewal so the client learns the new certificate *before* it
imports it — which it does naturally, since the client received it from the CA
in step 3.

**Note also the elegance of the CSR being self-signed with the new private
key:** that is proof-of-possession. The CA can verify the requester actually
holds the private key for the public key being certified.

### 19.7.3 Provisioning peer certificates

**[SPEC]** [GB] 9.2.6.6.5:

> *"To verify digital signatures, to perform key agreement using a scheme that
> uses static key agreement keys, or to establish a TLS connection, the server
> needs to have the appropriate public key certificates of the other party."*
>
> *"If, at the time of manufacturing, the client and/or third parties are
> already known, their public keys certificates may be injected into the server
> by the manufacturer. Otherwise, the servers can be provisioned … using the
> `import_certificate` method."*
>
> *"In the case of HLS authentication mechanism using ECDSA, the public key
> certificate of the clients' digital signature key can be carried by the
> **`calling-AE-qualifier`** field of the AARQ."*

And the reverse direction, **[SPEC]** [GB] 9.2.6.6.6:

> *"The certificate may be delivered with the server and inserted in clients /
> third parties OOB. Alternatively, the client or third party can request the
> certificate from the server using the `export_certificate` method."*
>
> *"NOTE In the case of HLS authentication using ECDSA — this is
> authentication_mechanism 7 — the public key certificate of the server for
> digital signature is transported in the AARE."*

So there are three routes for each direction, and HLS mechanism 7 gives you the
in-band one for free.

### 19.7.4 Certificate removal

**[SPEC]** [GB] 9.2.6.6.7:

> *"**When a certificate that belongs to the server is removed, the private key
> associated with the public key shall be destroyed.**"*
>
> *"The information on the certificate removed shall be also removed from the
> `certificates` attribute of the 'Security setup' object. The key pair the
> public key certificate of which has been removed cannot be used any more for
> transactions."*

**[IMPL]** "Shall be destroyed" is a specification requirement with a firmware
consequence: you must actually erase the private key from NVM, not merely
unlink an index entry. On flash that means erasing the containing page, or
storing keys in a secure element with a real delete operation. A deleted-but-
recoverable private key is a specification violation and a real forensic
exposure.

---

## 19.8 The "Security setup" object — what [GB] tells us

**[SPEC]** [GB] 9.2.6.3.2 enumerates the capabilities without giving attribute
numbers:

> *"The 'Security setup' interface class provides:*
> - *an attribute that provides information on the certificates stored on the
>   server;*
> - *a method to generate server key pairs and a method to generate Certificate
>   Signing Request (CSR) information on the server to be sent by the client to
>   a CA;*
> - *methods to import, export and remove certificates."*

Collected across [GB] clause 9.2, the methods referenced are:

| Method | Referenced in | Purpose |
|--------|---------------|---------|
| `security_activate` | [GB] 9.2 | Activate a security policy |
| `key_transfer` | [GB] 9.2.5.4 | Install wrapped symmetric keys |
| `key_agreement` | [GB] 9.2.5.5 | C(2e,0s) ephemeral unified model |
| `generate_key_pair` | [GB] 9.2.6.6.4 | Create an ECC key pair on the server |
| `generate_certificate_request` | [GB] 9.2.6.6.4 | Produce a signed X.509 v3 CSR |
| `import_certificate` | [GB] 9.2.6.6.4/.5 | Install and verify a certificate |
| `export_certificate` | [GB] 9.2.6.6.6 | Retrieve a stored certificate |
| `remove_certificate` | [GB] 9.2.6.6.7 | Delete a certificate (and its private key) |

And the attributes referenced: `security_policy`, `security_suite`,
`client_system_title`, `server_system_title`, and a `certificates` attribute.

> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** — attribute and
> method **numbering**, the exact invocation and return parameter structures,
> and the version 0 / version 1 differences of the "Security setup" IC are
> specified in **Blue Book DLMS UA 1000-1 Ed. 12:2014 clause 4.4.7**, which was
> outside this source set. Treat any attribute table for this IC that models
> keys as directly-writable attributes with suspicion — that conflicts with
> [GB]'s `key_transfer`-based model.

---

## 19.9 Volume 3 summary

1. **[SPEC]** The KEK **is** the master key. It wraps every other symmetric key
   and must be established out of band.
2. **[SPEC]** Global keys are GUEK (unicast), GBEK (broadcast), GAK
   (authentication, used with both). A dedicated key can only be a unicast
   encryption key.
3. **[SPEC]** The GAK lives in the AAD and is never transmitted, in any form.
4. **[SPEC]** AES key wrap is RFC 3394; a 128-bit key wraps to 24 octets, a
   256-bit key to 40. It requires AES *decryption* to unwrap.
5. Dedicated keys reduce blast radius but do **not** give forward secrecy —
   they are transported under the GUEK.
6. **[SPEC]** ECDSA uses P-256/SHA-256 (suite 1) or P-384/SHA-384 (suite 2), and
   the signature is **plain R‖S of fixed length**, not DER.
7. Reusing or biasing the ECDSA nonce `k` leaks the private key. Prefer
   deterministic ECDSA (RFC 6979).
8. **ECDSA is what authenticates ECDH** — the ephemeral public key in C(1e,1s)
   is signed.
9. **[SPEC]** Three key agreement schemes: C(2e,0s) for global keys with full
   forward secrecy; C(1e,1s) as the default for ephemeral encryption keys;
   C(0e,2s) with no forward secrecy and a `Z` that must be protected like a
   private key.
10. **[SPEC]** `Z` is never a key. The NIST Concatenation KDF binds it to both
    system titles and the algorithm OID. **Destroy Z** afterwards.
11. **[SPEC]** Trust anchors are provisioned out of band at manufacture, can be
    exported, and **cannot be imported or removed**.
12. **[SPEC]** The System Title is bound into end-entity certificates via
    `SubjectAltName` → `HardwareModuleName` → `hwSerialNum`. Check it.
13. **[SPEC]** Meters do not perform revocation checking; removal is an
    operator responsibility via `remove_certificate`.

---

**Next: Volume 4 — general-ciphering and general-signing in depth, multi-layer
protection by multiple parties, the third-party end-to-end model, COSEM data
protection, packet-by-packet capture analysis, Wireshark technique, and vendor
implementation differences.**

*End of Volume 3.*

---

← **Previous:** [Volume 2 — The Symmetric Core and the Wire Format](VOL-2-Symmetric-Core-and-Wire-Format.md)  ·  **Next:** [Volume 4 — General Ciphering and Packet Analysis](VOL-4-General-Ciphering-and-Packet-Analysis.md) →

[Back to the index](00-INDEX.md)
