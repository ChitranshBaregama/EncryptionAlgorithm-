# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 5 — Embedded Firmware Implementation**
*Chapters 25–30*

> Prerequisites: Volumes 0–4.
>
> This volume leaves the specification behind. The Green Book specifies a
> protocol, not a firmware architecture. Almost everything here is labelled
> **[IMPL]** or **[INFER]** — engineering judgement built on top of [SPEC].
> Where a specification requirement drives a design decision, I say so.

---

# CHAPTER 25 — SECURITY MODULE ARCHITECTURE

## 25.1 The layered design

```
 ┌───────────────────────────────────────────────────────────────────┐
 │  DLMS APPLICATION                                                 │
 │  COSEM object model · service dispatch · access rights check      │
 └───────────────────────────┬───────────────────────────────────────┘
                             │ protect() / unprotect()
 ┌───────────────────────────▼───────────────────────────────────────┐
 │  SECURITY MANAGER                                                 │
 │  · security context lifecycle (per association)                   │
 │  · SC byte encode / decode / validate                             │
 │  · IV construction (direction-aware)                              │
 │  · AAD construction (per [GB] Table 38)                           │
 │  · invocation counter policy (TX reserve, RX floor)               │
 │  · HLS challenge generation and f() computation                   │
 │  · key selection (Key_Set, dedicated, key-info)                   │
 └───────────────────────────┬───────────────────────────────────────┘
                             │ opaque key handles, never key bytes
 ┌───────────────────────────▼───────────────────────────────────────┐
 │  CRYPTO ABSTRACTION LAYER (CAL)                                   │
 │  One narrow API. Hides hardware vs software. Never leaks state.   │
 └──┬──────────┬──────────┬──────────┬──────────┬────────────────────┘
    │          │          │          │          │
 ┌──▼───┐ ┌────▼───┐ ┌────▼───┐ ┌────▼───┐ ┌────▼──────┐
 │AES-  │ │AES-    │ │SHA-256 │ │ECDSA   │ │ECDH +     │
 │GCM / │ │WRAP    │ │SHA-384 │ │sign/   │ │NIST       │
 │GMAC  │ │RFC3394 │ │        │ │verify  │ │Concat KDF │
 └──┬───┘ └────┬───┘ └────┬───┘ └────┬───┘ └────┬──────┘
    └──────────┴──────────┴──────────┴──────────┘
                             │
 ┌───────────────────────────▼───────────────────────────────────────┐
 │  SECURE KEY STORAGE                                               │
 │  key handles → key material. Application never sees the bytes.    │
 └──┬────────────┬────────────┬────────────┬─────────────────────────┘
    │            │            │            │
 ┌──▼───┐  ┌─────▼────┐  ┌────▼─────┐  ┌───▼──────────┐
 │ OTP  │  │  eFuse   │  │  Secure  │  │ TrustZone /  │
 │      │  │          │  │ Element  │  │ protected NVM│
 └──────┘  └──────────┘  └──────────┘  └──────────────┘

 ┌───────────────────────────────────────────────────────────────────┐
 │  COUNTER STORE  (separate from key storage — different threat)    │
 │  reservation-block persistence · ping-pong records · CRC          │
 └───────────────────────────────────────────────────────────────────┘

 ┌───────────────────────────────────────────────────────────────────┐
 │  ENTROPY SOURCE   TRNG → DRBG → challenges, keys, ECDSA k         │
 └───────────────────────────────────────────────────────────────────┘
```

**[IMPL] The two design rules that make this architecture work:**

**Rule 1 — the Security Manager never sees key bytes.** It passes opaque
`key_handle_t` values into the CAL. If the manager has a
`uint8_t guek[16]` field, then any buffer overflow anywhere above the CAL can
leak it, and any firmware dump recovers it.

**Rule 2 — the CAL knows nothing about DLMS.** It takes `(key, iv, aad,
plaintext)` and returns `(ciphertext, tag)`. It does not know what a Security
Control byte is. This keeps the DLMS-specific logic — which is where the bugs
are — in one testable place, and lets you swap a software AES for a hardware
one without touching protocol code.

---

## 25.2 The public API

```c
/* ─── Security context lifecycle ──────────────────────────────── */
int  sec_ctx_open (uint16_t client_sap, uint16_t server_sap,
                   dlms_security_context_t **out);
int  sec_ctx_close(dlms_security_context_t *ctx);   /* wipes dedicated key */

/* ─── Message protection ──────────────────────────────────────── */
int  sec_protect  (dlms_security_context_t *ctx,
                   apdu_kind_t kind,          /* glo / ded / general      */
                   const uint8_t *apdu, size_t apdu_len,
                   uint8_t *out, size_t out_cap, size_t *out_len);

int  sec_unprotect(dlms_security_context_t *ctx,
                   const uint8_t *in, size_t in_len,
                   uint8_t *apdu_out, size_t cap, size_t *apdu_len,
                   sec_status_t *status);     /* what WAS applied         */

/* ─── HLS ─────────────────────────────────────────────────────── */
int  sec_hls_make_challenge(dlms_security_context_t *ctx,
                            uint8_t *out, size_t len);   /* 8..64 octets */
int  sec_hls_compute_f     (dlms_security_context_t *ctx,
                            const uint8_t *challenge, size_t clen,
                            uint8_t *f_out, size_t *f_len);
int  sec_hls_verify_f      (dlms_security_context_t *ctx,
                            const uint8_t *f_in, size_t f_len);

/* ─── Key management ──────────────────────────────────────────── */
int  sec_key_transfer(dlms_security_context_t *ctx,
                      key_id_t id, const uint8_t *wrapped, size_t wlen);
int  sec_key_agreement(dlms_security_context_t *ctx, /* C(2e,0s) */
                       const uint8_t *peer_eph_pub, size_t plen,
                       uint8_t *our_eph_pub, size_t *olen);
```

**[IMPL] Note `sec_unprotect` returns a `sec_status_t`.** The caller must know
*what protection was actually applied*, not just that it succeeded — because
**[SPEC]** [GB] 9.2.7.2.2 requires the applied protection to meet the stronger
of the security policy and the per-object access rights, and access rights are
only known once you have parsed the APDU and identified the target object.
So the check happens in two stages:

```
   sec_unprotect()  → verifies crypto, returns what was applied
                      and enforces the SECURITY POLICY minimum
        │
        ▼
   parse APDU, identify target object/attribute/method
        │
        ▼
   access rights check → does the APPLIED protection also meet the
                         per-object requirement?  If not → reject.
```

Collapsing this into one step is a common design error; it forces you to know
the target object before you have decrypted the APDU that names it.

---

## 25.3 The security state machine

```
                          ┌──────────┐
                ┌────────►│   IDLE   │◄──────────┐
                │         └────┬─────┘           │
                │              │ AARQ received   │
                │              ▼                 │
                │      ┌───────────────┐         │
                │      │ VALIDATING    │         │ release / abort /
                │      │ · context name│         │ timeout
                │      │ · mechanism   │         │
                │      │ · SAP → assoc │         │
                │      └───┬───────┬───┘         │
                │  reject  │       │ accept      │
                └──────────┘       │             │
                                   ▼             │
                     ┌─────────────────────┐     │
          LLS/none ◄─┤ which mechanism?    ├─► HLS
                     └─────────────────────┘     │
                       │                    │    │
                       ▼                    ▼    │
             ┌──────────────────┐  ┌────────────────────────┐
             │  ESTABLISHED     │  │  HLS_PASS2_SENT        │
             │                  │  │  ★ ONLY                │
             │  all services    │  │  reply_to_HLS_         │
             │  permitted,      │  │  authentication        │
             │  subject to      │  │  is permitted          │
             │  access rights   │  │  ★ timeout armed       │
             └────────┬─────────┘  └──────┬──────────┬──────┘
                      │                   │ f() ok   │ f() bad
                      │                   ▼          │ or timeout
                      │            ┌──────────────┐  │
                      │            │ send f(CtoS) │  │
                      │            └──────┬───────┘  │
                      │                   │          │
                      │◄──────────────────┘          │
                      │                              ▼
                      │                        ┌──────────┐
                      │                        │  ABORT   │
                      │                        │ log +    │
                      │                        │ backoff  │
                      │                        └────┬─────┘
                      │                             │
                      ▼                             │
             ┌──────────────────┐                   │
             │   RELEASING      │───────────────────┘
             └──────────────────┘

   ┌───────────────────────────────────────────────────────────────┐
   │  SEC_FAULT  — entered from ANY state on:                      │
   │    · invocation counter unrecoverable from NVM                │
   │    · counter exhausted (2³²-1)                                │
   │    · key storage integrity failure                            │
   │  Behaviour: FAIL CLOSED. Ciphering disabled, alarm raised.    │
   │  Exit: only via key rotation or field intervention.           │
   └───────────────────────────────────────────────────────────────┘
```

**[IMPL] Three requirements this diagram encodes:**

1. **`HLS_PASS2_SENT` gates every service except one.** Volume 1 §4.5 explains
   why: a server that accepts a GET in this state has a complete
   authentication bypass. Test it explicitly.
2. **A failed pass 3 aborts, it does not retry in place.** Otherwise an
   attacker gets unlimited guesses against one StoC.
3. **`SEC_FAULT` fails closed.** Chapter 27 argues why this is correct even
   though it means the meter stops communicating.

---

## 25.4 Concurrency, watchdog, and power failure

### 25.4.1 Concurrency

**[IMPL]** The invocation counter is shared mutable state. If your stack has
more than one thread that can transmit — say, a scheduled push and a
client-initiated response — the counter must be protected:

```c
static uint32_t ic_next_locked(void)
{
    uint32_t ic;
    critical_section_enter();     /* or a mutex, if you have an RTOS */
    ic = ic_tx++;
    critical_section_exit();
    return ic;
}
```

**[INFER] Getting this wrong produces nonce reuse.** Two threads that read the
same counter value before either increments it will both encrypt under the same
IV. This is a race condition whose consequence is a total cryptographic break —
which is why it deserves a critical section rather than a "probably fine".

**[IMPL]** Prefer a single-writer design: one transmit path, one counter,
serialised by construction. Concurrency here buys you nothing and costs a lot.

### 25.4.2 Watchdog interaction

**[IMPL]** ECC operations are slow. On a Cortex-M4 without a PKA, a P-256
ECDSA signature may take 200–800 ms; P-384 several times that. If your watchdog
period is shorter than the longest crypto operation, you will reset mid-signature.

Options, in order of preference:

1. **Chunk the operation.** Split scalar multiplication into windows and kick
   the watchdog between them. Requires a library that exposes an incremental
   API, or your own point-multiplication loop.
2. **Extend the watchdog window** around known-long operations, and restore it
   afterwards. Simple, but widens the window in which a genuine hang goes
   undetected.
3. **Offload to a secure element** with its own timing. Best answer if the BOM
   allows.

**[IMPL] Do not** simply kick the watchdog inside a tight crypto loop from a
timer interrupt — that defeats the watchdog entirely.

### 25.4.3 Power failure

The critical windows, and what must be true on each side of them:

| Window | If power is lost here | Required behaviour |
|--------|----------------------|--------------------|
| After reserving a counter block, before using it | Some counter values wasted | ✅ Safe — gaps are permitted |
| After using a counter, before persisting | Counter may be reused | ❌ **Must not happen.** Reservation blocks prevent it: the block ceiling is persisted *before* any value in it is used |
| During key install (`key_transfer`) | Key half-written | Must be journalled — see §29.3 |
| After key write, before counter reset | New key, stale counter | ✅ Safe — counters only move forward |
| After counter reset, before key write | **Old key, zeroed counter** | ❌ **Catastrophic nonce reuse.** Order the operations: key first, then counter |
| During certificate import | Partial certificate | Must be journalled; reject on CRC failure |

**[IMPL]** That fifth row is the reason the ordering in Volume 3 §15.4 step ⑧
is not arbitrary. Write the key, *then* reset the counter, and make the pair
atomic with a journal.

---

## 25.5 Relationship to secure boot and OTA

**[INFER]** This is where DLMS security meets the wider firmware-security
picture, and it is worth being explicit about the dependency direction.

```
   ┌─────────────────────────────────────────────────────────────┐
   │  SECURE BOOT                                                │
   │  Root of trust in ROM/OTP verifies the bootloader,          │
   │  which verifies the application.                            │
   └──────────────────────────┬──────────────────────────────────┘
                              │ establishes
                              ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  TRUSTWORTHY FIRMWARE                                       │
   │  The code that handles keys is the code that was signed.    │
   └──────────────────────────┬──────────────────────────────────┘
                              │ enables
                              ▼
   ┌─────────────────────────────────────────────────────────────┐
   │  MEANINGFUL DLMS SECURITY                                   │
   │  Key storage protection, constant-time comparison, counter  │
   │  persistence — all of it assumes the code is genuine.       │
   └─────────────────────────────────────────────────────────────┘
```

**Without secure boot, DLMS security is decorative.** An attacker who can flash
modified firmware simply replaces the security module with one that prints the
keys. Every protection in this manual assumes the running code is the code you
shipped.

**[IMPL] OTA implications:**

| Concern | Requirement |
|---------|-------------|
| Image authenticity | Signature verified against a key in OTP/ROM, not in updatable flash |
| Rollback | Monotonic version counter in OTP; refuse to install an older version |
| Key survival | The security context and counters must survive the update, or the meter loses communications |
| Counter across update | Treat an update like an unclean shutdown: **jump the counter forward** by a safety margin |
| Key migration | If the key storage format changes, migrate atomically with a journal and a version tag |
| Interrupted update | A/B image slots with an atomic pointer switch; never erase the running image |

**[INFER] The counter-across-update point catches people.** An OTA update is a
reset. If your `ic_init()` does the right thing on a normal power cycle it will
also do the right thing here — but only if the counter store survives the
update. Placing the counter in a flash region that the update erases is a
straightforward path to nonce reuse, and it is a mistake I would specifically
look for in a review.

---

# CHAPTER 26 — MEMORY DESIGN

## 26.1 What consumes memory

```
   RAM
   ├── AES key schedule            176 B (AES-128) / 240 B (AES-256)
   ├── GCM/GHASH state             ~16 B accumulator
   │   └── GHASH multiply tables   0 B (bitwise) … 64 KB (8-bit table)
   ├── IV, AAD, tag buffers        12 + (1+keylen[+APDU]) + 16 B
   ├── APDU buffers                ×2 if you decrypt out-of-place
   ├── ECC scratch (suite 1/2)     point coords + temporaries
   ├── Certificate parse buffer    500 B – 2 KB per certificate
   ├── Security context            ~100 B per association
   └── Stack during ECC            can be 2–4 KB

   FLASH
   ├── AES core                    2–4 KB software; ~0 with hardware
   ├── GHASH                       0.5–2 KB depending on table size
   ├── AES key wrap                ~0.5 KB (reuses AES, plus inverse)
   ├── AES inverse cipher          1–3 KB (needed ONLY for key unwrap)
   ├── SHA-256 / SHA-384           2–4 KB
   ├── ECC point arithmetic        8–20 KB
   ├── ECDSA sign + verify         2–5 KB
   ├── ECDH + KDF                  1–2 KB
   ├── X.509 DER parser            5–15 KB
   └── Curve constants             P-256 ~256 B, P-384 ~384 B
```

---

## 26.2 Budget estimates by suite

**[IMPL]** Order-of-magnitude figures for a Cortex-M, software crypto, `-Os`.
Actual numbers vary by library; use these for early architecture decisions, not
for a BOM commitment.

### Suite 0

| Component | Flash | RAM |
|-----------|-------|-----|
| AES-128 core (software) | 3.0 KB | 176 B key schedule |
| AES inverse (key unwrap only) | 2.0 KB | +176 B |
| GHASH, 4-bit table | 1.0 KB | 256 B table + 16 B state |
| GCM wrapper | 1.0 KB | 64 B |
| AES key wrap (RFC 3394) | 0.5 KB | 64 B |
| Security manager | 3.0 KB | 128 B/association |
| Counter store | 1.0 KB | 32 B |
| **Total** | **≈ 11.5 KB** | **≈ 0.8 KB** + APDU buffers |

With a hardware AES peripheral, drop ~5 KB of flash and the key schedule RAM.

### Suite 1 (adds P-256, SHA-256, X.509)

| Component | Flash | RAM |
|-----------|-------|-----|
| Suite 0 baseline | 11.5 KB | 0.8 KB |
| SHA-256 | 2.5 KB | 110 B |
| P-256 field + point arithmetic | 12.0 KB | 800 B |
| ECDSA sign + verify | 3.0 KB | 400 B |
| ECDH + NIST Concat KDF | 1.5 KB | 200 B |
| X.509 v3 DER parser | 10.0 KB | 1.5 KB parse buffer |
| Certificate storage (3 certs) | — | 3.0 KB (or flash-resident) |
| **Total** | **≈ 40 KB** | **≈ 4–7 KB** |
| **Peak stack during ECC** | — | **+2–3 KB** |

### Suite 2 (P-384, SHA-384, AES-256)

| Component | Flash | RAM |
|-----------|-------|-----|
| Suite 1 baseline | 40 KB | 4–7 KB |
| AES-256 (extra round keys) | +0.2 KB | +64 B |
| SHA-384 (64-bit words) | +2.0 KB | +200 B |
| P-384 arithmetic (in addition to P-256 — **[SPEC]** Table 33 requires both) | +6.0 KB | +600 B |
| Larger certificates | — | +1.0 KB |
| **Total** | **≈ 48 KB** | **≈ 6–10 KB** |
| **Peak stack during ECC** | — | **+3–4 KB** |

**[SPEC] Note the "in addition to" on P-384.** [GB] Table 33 lists P-256
end-entity certificates signed with P-384 as valid in suite 2, so a suite-2
meter must implement both curves. You cannot delete P-256 to save space.

---

## 26.3 Optimisation techniques

### 26.3.1 The GHASH table trade-off

| Method | Flash/RAM | Speed | Use when |
|--------|-----------|-------|----------|
| Bitwise (no table) | ~0 | Slowest (~128 iterations/block) | RAM is critical and throughput is not |
| 4-bit table (16 entries) | 256 B | ~8× faster | **The usual sweet spot** |
| 8-bit table (256 entries) | 4 KB | ~16× faster | Only with RAM to spare |

**[IMPL] Security note:** the table is derived from H, which is derived from
the key. It is key material. Do not place it in a shared scratch buffer, and
wipe it when the key changes.

### 26.3.2 Streaming AAD instead of buffering

Volume 2 §13.8.1 flagged this. For authentication-only protection the AAD is
`SC ‖ AK ‖ APDU`. Buffering it contiguously costs `1 + keylen + max_apdu_len`
bytes of RAM — over 1.5 KB on a large PDU, for no reason.

```c
/* Streaming: AAD buffer only needs to hold SC ‖ AK (17 or 33 octets). */
gcm_start(ctx, key, iv);
gcm_aad_update(ctx, &sc, 1);
gcm_aad_update(ctx, ak, ak_len);
if (!encrypted)
    gcm_aad_update(ctx, apdu, apdu_len);    /* streamed, never copied */
gcm_aad_finish(ctx);
```

**[IMPL]** If your GCM library demands a single contiguous AAD buffer, that is
a reason to change library, not a reason to allocate 1.5 KB.

### 26.3.3 In-place decryption

CTR mode is `C XOR keystream`, so decryption can be done in place. But you
**must not** release the buffer until the tag verifies (Volume 2 §8.7).

```c
/* Safe in-place pattern: decrypt in place, but gate the caller. */
int rc = gcm_decrypt_verify_inplace(ctx, buf, len, tag);
if (rc != OK) {
    secure_zero(buf, len);          /* wipe the unverified plaintext */
    return ERR_TAG_MISMATCH;
}
/* Only now is buf valid to parse. */
```

This saves one full APDU buffer — often 1–1.5 KB — at the cost of needing
discipline about the `secure_zero`.

### 26.3.4 Flash-resident certificates

**[IMPL]** Certificates are read-only after import. Store them in flash, parse
lazily, and keep only an index in RAM:

```c
typedef struct {
    uint32_t flash_offset;
    uint16_t length;
    uint8_t  purpose;                  /* DataSign / KeyAgree / TLS   */
    uint8_t  system_title[8];          /* from SubjectAltName         */
    uint8_t  subject_key_id[20];       /* for chain lookup            */
} cert_index_t;                        /* ~36 B vs 1–2 KB per cert    */
```

Parse the DER only when you need a field, directly from flash. On a part with
plenty of flash and little RAM — the usual metering profile — this is the
single largest RAM saving available in suite 1/2.

### 26.3.5 Suite-conditional compilation

**[IMPL]** If the product ships suite 0 only, compile out the entire ECC
branch:

```c
#if DLMS_SUITE_MAX >= 1
    /* ECC, X.509, SHA — ~30 KB of flash */
#endif
```

Do not ship dead ECC code "in case we need it later". It is attack surface and
it is flash you could spend on metrology.

---

# CHAPTER 27 — SECURE KEY STORAGE

## 27.1 Why application flash is inadequate

```c
/* ══════ DANGEROUS ══════ */
static const uint8_t guek[16] = { 0x00, 0x01, /* ... */ };
```

Or, only marginally better, sixteen bytes in a known EEPROM offset. The threats:

| Attack | How it works |
|--------|--------------|
| **Debug port readout** | SWD/JTAG left enabled, or re-enabled via a glitch. Dump flash, grep for entropy. |
| **Bootloader readout** | Many MCU ROM bootloaders expose flash read over UART/USB unless explicitly locked. |
| **Firmware image analysis** | The OTA image or a service-tool image contains the key. |
| **Decapsulation / microprobing** | Expensive, but a fleet-wide key justifies the cost. |
| **Cold-boot / RAM remanence** | Keys copied into RAM survive briefly after reset. |
| **Fault injection** | Voltage/clock glitch to skip the read-protect check. |
| **Software vulnerability** | A buffer overflow anywhere in a flat address space reads the key. |

**[INFER] The economic argument that should drive your decision:** if the same
key is in a million meters, an attacker's cost to extract it from *one* device
is amortised over the whole fleet. A €50,000 laboratory attack that yields a
fleet-wide key is cheap. This is why per-device keys matter as much as storage
technology, and why "nobody will bother" is not an argument.

---

## 27.2 The storage options

| Option | Read protection | Tamper resistance | Cost | Verdict |
|--------|-----------------|-------------------|------|---------|
| **Internal flash, unprotected** | None | None | Free | ❌ Never |
| **Internal flash + RDP level 2** | Debug disabled, permanent | Low — glitching attacks documented | Free | ⚠️ Minimum viable, with per-device keys |
| **External EEPROM** | None — bus is sniffable | None | Low | ❌ Worse than internal |
| **OTP / one-time programmable** | Often lockable | Medium | Free (on-die) | ✅ Good for the KEK and root of trust |
| **eFuse** | Hardware-enforced, irreversible | Medium–high | Free (on-die) | ✅ Good for immutable roots |
| **Protected RAM / key ladder** | Keys never leave the crypto block | High | Free (on-die) | ✅ Excellent when available |
| **TrustZone (Cortex-M33/A)** | Secure world only | Medium–high | Free (on-die) | ✅ Strong if the secure partition is small and audited |
| **Secure element (SE)** | Keys never leave the chip | **High** — certified, tamper-responsive | €0.50–2 | ✅ **Best** |
| **HSM** | — | Highest | High | For the head-end, not the meter |

---

## 27.3 The key handle abstraction

**[IMPL]** Whatever the backend, present one interface:

```c
typedef uint16_t key_handle_t;

#define KEY_HANDLE_INVALID  ((key_handle_t)0)

/* The application NEVER receives key bytes. */
int keystore_use_gcm(key_handle_t ek, key_handle_t ak,
                     const uint8_t iv[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *in,  size_t in_len,
                     uint8_t *out, uint8_t *tag, size_t tag_len);

int keystore_unwrap_into(key_handle_t kek, key_handle_t dest,
                         const uint8_t *wrapped, size_t wlen);
```

Note `keystore_unwrap_into`: the unwrapped key goes **directly into another
slot**, never through application memory. With a secure element this maps onto
a native command. With flash-based storage you emulate it, but the API shape
means you can upgrade the backend later without touching protocol code.

**[IMPL] Also note that the GCM call takes `ak` as a handle.** The
authentication key must be prepended to the AAD — so either the CAL builds the
AAD internally (preferred, keeps AK out of caller memory), or you accept that
the AK is briefly in RAM. With a secure element that supports "AAD from key
slot", choose the former.

---

## 27.4 Per-device key derivation

**[IMPL]** Even with modest storage, never ship a fleet-wide key:

```
   Factory HSM holds:  MASTER_SEED   (never leaves the HSM)

   Per meter:
       device_KEK = KDF( MASTER_SEED, "DLMS-KEK-v1" ‖ system_title )
       device_GUEK, device_GAK similarly, with distinct labels

   Injected into the meter at manufacture.
   The head-end recomputes them on demand from the HSM.
```

Properties:

- Extracting one meter's keys yields **one** meter.
- The head-end stores no key database — just the seed, in an HSM.
- Keys are recoverable if the meter database is lost.
- **[INFER]** The trade-off: `MASTER_SEED` compromise is fleet-wide and
  catastrophic. It must live in an HSM with strict access control, and it must
  be versioned so a future generation can migrate.

Include the **System Title** in the derivation, since it is unique per device
by specification ([GB] 4.3.4) and is already provisioned.

---

## 27.5 The storage layout

```
   ┌──────────────────────────────────────────────────────────────┐
   │  OTP / eFuse  — write once, never erased                     │
   │  · secure boot root public key hash                          │
   │  · device KEK (master key)          ← [SPEC] the KEK         │
   │  · System Title                     ← [SPEC] 8 octets        │
   │  · debug-disable / RDP lock bits                             │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────┐
   │  Protected NVM  — rewritable, integrity-checked              │
   │  · GUEK, GBEK, GAK          (wrapped under the KEK at rest)  │
   │  · ECC private keys         (suite 1/2)                      │
   │  · trust anchors            ← [SPEC] cannot be imported or   │
   │                                removed ([GB] 9.2.6.6.2)      │
   │  · peer certificates                                         │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────┐
   │  Counter store  — high write rate, separate wear domain      │
   │  · IC ceiling records, ping-pong, CRC-protected              │
   └──────────────────────────────────────────────────────────────┘
   ┌──────────────────────────────────────────────────────────────┐
   │  Application flash  — no key material, ever                  │
   └──────────────────────────────────────────────────────────────┘
```

**[IMPL] Wrapping the global keys under the KEK at rest** means a flash dump
yields only ciphertext. The KEK stays in OTP and is used only inside the crypto
block. This is a cheap and large improvement over storing global keys in the
clear, and it works even without a secure element.

**[IMPL] Separating the counter store from key storage** matters because they
have opposite profiles: keys are written rarely and must be maximally
protected; counters are written constantly and must be endurance-managed. Put
them in the same sector and you will either wear out your key storage or
under-protect your counters.

---

## 27.6 Runtime hygiene

```c
/* Not elidable by the optimiser. */
static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
    __asm__ __volatile__("" ::: "memory");
}
```

**[IMPL] Wipe:**

- The shared secret `Z` after key derivation — **[SPEC]** required by [GB]
  Tables 14, 15, 16 ("Destroy Z").
- Ephemeral private keys immediately after use.
- The ECDSA nonce `k`.
- GHASH tables when the key changes.
- Any unverified plaintext after a tag failure.
- The dedicated key when the association closes.

**[IMPL] Also:**

- Disable SWD/JTAG in production images, and verify it is actually disabled on
  a sample from the line — not just in the build configuration.
- Ensure keys are not printed by any diagnostic path. Grep your codebase for
  format strings near key variables.
- Consider whether a crash dump or a core file could contain key material.

---

# CHAPTER 28 — RANDOM NUMBER GENERATION

## 28.1 The specification

**[SPEC]** [GB] 9.2.3.5, in full — it is short:

> *"Strong random number generator (RNG) shall be provided to generate the
> random numbers required for the various algorithms used in DLMS/COSEM. The
> RNG shall be preferably non-deterministic. If a non-deterministic RBG is not
> available, the system shall make use of sufficient entropy to create a good
> quality seed for a deterministic RNG."*

**[SPEC]** And for keys, [GB] 9.2.3.3.7.4:

> *"The key shall be generated uniformly at random, or close to uniformly at
> random, i.e., so that each possible key is (nearly) equally likely to be
> generated. Consequently, the key will be fresh, i.e., unequal to any previous
> key, with high probability."*

---

## 28.2 What depends on the RNG

| Consumer | Requirement | Consequence of failure |
|----------|-------------|------------------------|
| **CtoS / StoC challenges** | Unpredictable, 8–64 octets (32–64 for mech 7) | Predictable challenge ⇒ an attacker precomputes `f()` and replays it ⇒ **authentication bypass** |
| **Symmetric keys** (GUEK, GBEK, GAK, KEK) | Uniform | Weak or repeated key ⇒ traffic decryptable |
| **Dedicated keys** | Uniform, fresh per AA | Repeated dedicated key ⇒ cross-session correlation |
| **ECDSA nonce `k`** | Secret, unique, unbiased | **Private key recovery** (Volume 3 §17.7) |
| **ECC private keys** | Uniform in [1, n-1] | Key guessable |
| **Ephemeral ECDH keys** | Fresh per exchange | Forward secrecy lost |

**[INFER] The challenge row is the one people underestimate.** A meter that
generates `StoC` from a counter, or from `rand()` seeded with a boot counter,
lets an attacker who has observed one session predict the next `StoC`,
precompute nothing (they still need the key)… but it lets an attacker who has
*recorded* a session replay `f(StoC)` when the same `StoC` recurs. With a
16-bit LCG, `StoC` repeats within 65536 associations. That is a working
authentication bypass.

---

## 28.3 The architecture

```
   ┌──────────────────────────────────────────────────────────────┐
   │  ENTROPY SOURCES (raw, biased, low rate)                     │
   │  · hardware TRNG (ring oscillator / thermal noise)           │
   │  · ADC noise on a floating or reference input                │
   │  · clock jitter between independent oscillators              │
   │  · timing of external events (mains zero-cross, comms)       │
   └────────────────────────────┬─────────────────────────────────┘
                                │ conditioning
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  ENTROPY POOL  (hash-based accumulation, e.g. SHA-256)       │
   │  · continuous health tests: repetition count, adaptive       │
   │    proportion (NIST SP 800-90B)                              │
   └────────────────────────────┬─────────────────────────────────┘
                                │ seed material
                                ▼
   ┌──────────────────────────────────────────────────────────────┐
   │  DRBG  (NIST SP 800-90A: CTR_DRBG or HMAC_DRBG)              │
   │  · reseed periodically and after every N outputs             │
   │  · state is KEY MATERIAL — protect and wipe accordingly      │
   └────────────────────────────┬─────────────────────────────────┘
                                ▼
              challenges · keys · ECDSA k · ephemeral keys
```

**[IMPL] CTR_DRBG is the pragmatic choice** on a part with hardware AES: you
already have the primitive, and it is fast.

---

## 28.4 MCU-specific guidance

| Source | Quality | Notes |
|--------|---------|-------|
| **Hardware TRNG (STM32, ESP32, nRF, many others)** | Good | ✅ Use it. Still condition and health-test the output. |
| **ADC noise on a floating pin** | Poor–fair | Low entropy per sample; hash many samples. Vulnerable to a determined attacker driving the pin. |
| **Internal temperature sensor LSBs** | Poor | Very low rate. Contributory only. |
| **Clock jitter between LSI and HSE** | Fair | Classic technique; measure actual entropy before trusting it. |
| **Mains zero-cross timing jitter** | Fair | Available on a meter by construction; correlated across meters on the same feeder — **[INFER]** contributory only, never sole. |
| **`rand()` / LCG** | **None** | ❌ Never. |
| **Uninitialised SRAM at boot** | One-shot, device-specific | Useful as a *seed contribution*, not as an ongoing source. Varies with SRAM technology. |

**[IMPL] Boot-time seeding.** The classic embedded failure is generating a key
seconds after power-on, before enough entropy has accumulated:

```c
int rng_init(void)
{
    entropy_pool_reset();

    /* Contributions available immediately. */
    pool_add(uninit_sram_snapshot(), 64);
    pool_add(persisted_seed_from_nvm(), 32);   /* saved at last shutdown */
    pool_add(&boot_counter, 4);

    /* Then collect from the TRNG until the estimator is satisfied. */
    while (entropy_estimate_bits() < 256) {
        pool_add_trng(32);
        if (timeout()) return ERR_INSUFFICIENT_ENTROPY;  /* FAIL CLOSED */
    }

    drbg_instantiate(pool_extract(48));
    persist_new_seed();          /* for the NEXT boot */
    return OK;
}
```

**[IMPL] Two details that matter:**

- **Persist a seed across reboots**, and rotate it immediately on use so a
  flash dump does not predict future output.
- **Fail closed on insufficient entropy.** A meter that generates a challenge
  from a half-filled pool is worse than a meter that refuses the association
  and raises an alarm.

**[IMPL] Health testing.** NIST SP 800-90B's two continuous tests are cheap and
catch a stuck TRNG:

- **Repetition count**: same value N times in a row → fail.
- **Adaptive proportion**: one value dominating a window → fail.

A ring oscillator that stops oscillating produces a constant. Without these
tests you will happily generate a key of all zeros.

---

## 28.5 Removing the RNG from the ECDSA path

**[IMPL]** Because ECDSA nonce failure is so severe, prefer **deterministic
ECDSA (RFC 6979)**, which derives `k` from `HMAC(private_key, message_hash)`.
The signature is a standard ECDSA signature; verification is unchanged, so it
is fully interoperable.

> **[INFER]** RFC 6979 is not referenced by [GB]. It produces conformant
> signatures, so adopting it is a safe unilateral implementation decision.
> **«SOURCE GAP / VERIFY AGAINST APPLICABLE DLMS EDITION»** if your project
> companion specification constrains nonce generation.

You still need a good RNG for challenges, keys, and ephemeral ECDH — but you
remove the single worst failure mode from the signing path.

---

# CHAPTER 29 — KEY PROVISIONING AND LIFECYCLE

## 29.1 The lifecycle

```
   ┌──────────────────────────────────────────────────────────────┐
   │ ① MANUFACTURING                                              │
   │   · System Title assigned (unique — [SPEC] [GB] 4.3.4)       │
   │   · KEK injected from the factory HSM                        │
   │   · Trust anchors injected OOB ([SPEC] [GB] 9.2.6.6.2)       │
   │   · Debug interfaces permanently disabled                    │
   │   · Secure boot enabled and verified                         │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ② SECURITY PERSONALISATION                                   │
   │   · GUEK, GBEK, GAK installed (wrapped under KEK)            │
   │   · suite 1/2: generate_key_pair → CSR → import_certificate  │
   │     ([SPEC] [GB] 9.2.6.6.4)                                  │
   │   · security_policy activated                                │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ③ INSTALLATION                                               │
   │   · System Title registered with the head-end                │
   │   · first association; keys validated end to end             │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ④ NORMAL OPERATION                                           │
   │   · associations established and released                    │
   │   · invocation counters advance and persist                  │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ⑤ KEY ROTATION / CERTIFICATE RENEWAL   (Chapter 30)          │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ⑥ COMPROMISE RESPONSE                                        │
   │   · emergency rotation; certificate removal; forensics       │
   └────────────────────────┬─────────────────────────────────────┘
   ┌────────────────────────▼─────────────────────────────────────┐
   │ ⑦ DECOMMISSIONING                                            │
   │   · destroy all key material                                 │
   │   · [SPEC] "the private key associated with the public key   │
   │     shall be destroyed" ([GB] 9.2.6.6.7)                     │
   │   · deregister from the head-end                             │
   └──────────────────────────────────────────────────────────────┘
```

---

## 29.2 Responsibilities

| Party | Responsibilities |
|-------|------------------|
| **Manufacturer** | Assign unique System Titles; inject KEK and trust anchors OOB; enable secure boot; disable debug; **[SPEC]** *"The private keys have to be securely stored in the server and shall never be exposed"* ([GB] 9.2.6.6.4) |
| **Utility / operator** | Own the key management policy; run rotation; respond to compromise; maintain the certificate inventory |
| **Head-End System** | Generate and wrap keys; invoke `key_transfer` and `key_agreement`; track per-meter invocation counters; **[SPEC]** *"verifies that the TP has the right to use that AA"* when brokering ([GB] 9.2.2.5) |
| **Meter (server)** | Enforce policy and access rights; verify every tag; maintain counters; protect keys; **[SPEC]** verify certificates before use ([GB] 9.2.6.3.2) |
| **Provisioning system** | Bridge factory HSM and head-end database; guarantee System Title uniqueness |
| **Certification Authority** | Issue and sign certificates; maintain the CRL; **[SPEC]** the Root-CA is the trust anchor ([GB] 9.2.6.3.3.2) |

**[INFER] The uniqueness of the System Title is a manufacturing-process
requirement, not a firmware one**, and it is the one most often broken. A line
that programs a placeholder and relies on a later step will eventually ship
duplicates. Duplicated System Titles under a shared broadcast key means
**IV collision across devices** — Volume 2 §11.2. Build a hard gate: the meter
refuses to leave the factory-test state until a non-default System Title is
programmed, and the test station verifies uniqueness against a database.

---

## 29.3 Atomic key installation

**[IMPL]** `key_transfer` must be all-or-nothing across power loss:

```c
typedef struct {
    uint32_t magic;                /* journal validity marker      */
    uint8_t  key_id;
    uint8_t  key_len;
    uint8_t  wrapped[40];          /* max: 256-bit key wrapped     */
    uint32_t crc;
} key_journal_t;

int key_install(key_id_t id, const uint8_t *wrapped, size_t wlen)
{
    key_journal_t j = { .magic = KEY_JOURNAL_MAGIC,
                        .key_id = id, .key_len = (uint8_t)wlen };
    memcpy(j.wrapped, wrapped, wlen);
    j.crc = crc32(&j, offsetof(key_journal_t, crc));

    /* 1. Journal the intent FIRST. */
    if (nvm_write(JOURNAL_ADDR, &j, sizeof j) != OK) return ERR_NVM;

    /* 2. Unwrap and install. */
    if (keystore_unwrap_into(KEK_HANDLE, handle_for(id), wrapped, wlen) != OK)
        { journal_clear(); return ERR_UNWRAP; }

    /* 3. Reset the counters for the new key.
          [SPEC] [GB] 9.2.3.3.7.3 — AFTER the key is installed.     */
    ic_reset_for_key(id);

    /* 4. Clear the journal — the operation is complete. */
    journal_clear();
    return OK;
}

/* On boot: if a valid journal exists, the previous install was
   interrupted. Replay it — the wrapped key is idempotent.          */
void key_journal_recover(void)
{
    key_journal_t j;
    if (journal_read_valid(&j))
        key_install(j.key_id, j.wrapped, j.key_len);
}
```

**[IMPL] Why the journal holds the *wrapped* key, not the plaintext key:** the
journal lives in ordinary NVM. Storing the plaintext key there, even
transiently, defeats the entire storage design. The wrapped form is safe at
rest and replaying the unwrap is idempotent.

---

## 29.4 The chicken-and-egg problems

**[IMPL]** Three bootstrap orderings that must be right:

**Dedicated key before association.** The `glo-initiateRequest` inside the AARQ
must be decrypted *before* the AA exists (Volume 3 §16.2). Your security
context must be resolvable from `(client SAP, server SAP)` at AARQ-parse time,
not only after establishment.

**System Title before ciphering.** **[SPEC]** [GB] 4.3.4: *"Before the
cryptographic security algorithms can be used … the peers have to exchange
system titles."* A ciphered APDU from an unknown System Title must be
**rejected**, because you cannot construct the IV.

**Trust anchor before certificate verification.** **[SPEC]** Trust anchors are
provisioned OOB at manufacture and *"cannot be imported or removed"* ([GB]
9.2.6.6.2). A meter with no trust anchor cannot verify anything and must not
accept a certificate presented over the wire as a substitute.

---

# CHAPTER 30 — KEY ROTATION

## 30.1 Why rotate

| Reason | Detail |
|--------|--------|
| **Counter exhaustion** | **[SPEC]** 2³²−1 invocations per key. This is a hard specification limit. |
| **Cryptoperiod policy** | **[SPEC]** [GB] 9.2.5.6 defers to companion specifications and NIST SP 800-57. |
| **Data volume under one key** | Limits exposure to any future cryptanalytic advance. |
| **Personnel change** | Staff with key access leave. |
| **Suspected or confirmed compromise** | Emergency rotation. |
| **Certificate expiry** | Suite 1/2. |

**[SPEC]** The mechanism resets the counters: *"when the key is established the
corresponding ICs are reset to 0"* ([GB] 9.2.3.3.7.3). This is also the
sanctioned recovery from a counter fault (Volume 2 §10.5.5).

---

## 30.2 The two rotation mechanisms

| | **`key_transfer` (key wrap)** | **`key_agreement` C(2e,0s)** |
|--|------------------------------|------------------------------|
| **[SPEC] Reference** | [GB] 9.2.5.4 | [GB] 9.2.5.5 |
| Requires | Shared KEK | ECC key pairs + certificates |
| Suite | 0, 1, 2 | 1, 2 only |
| Messages | 1 ACTION | Exchange of ephemeral public keys |
| Forward secrecy for the new key | ❌ — recoverable by anyone with the KEK | ✅ |
| Can establish | KEK, GUEK, GBEK, GAK | KEK, GUEK, GBEK, GAK |
| Cost | 1 AES key wrap | 2 keygen + 2 ECDH + KDF |

**[INFER] The forward-secrecy row is the real argument for suite 1.** Under
`key_transfer`, every key you have ever installed is recoverable by anyone who
eventually obtains the KEK, because the wrapped keys were on the wire. Under
C(2e,0s), the ephemeral keys are destroyed and the new key is not derivable
from any long-term secret.

---

## 30.3 The rotation sequence

```
   PRECONDITION: the current association is authenticated and the
   security policy is being enforced.

   ① HES generates new_GUEK from an HSM-backed CSPRNG.
   ② HES wraps it:  wrapped = AES-KeyWrap(KEK, new_GUEK)   → 24 octets
   ③ HES records the pending change in its own database FIRST.
      (If step ⑤ succeeds but the HES has not recorded it, the HES
       loses the meter.)
   ④ HES sends key_transfer, protected under the CURRENT GUEK.
   ⑤ Meter verifies tag → checks access rights → unwraps → journals →
      installs → resets counters.
   ⑥ Meter responds SUCCESS, protected under the OLD key.
   ⑦ HES receives and verifies the response, then marks the new key
      active and resets its own counter tracking.
   ⑧ Next association uses the new key.
```

---

## 30.4 The half-completed rotation

This is the failure mode worth designing for explicitly.

```
   Failure point                     Meter state    HES state    Recovery
   ─────────────────────────────────────────────────────────────────────
   Before ④ transmitted              old key        old key      Retry
   In flight, meter never received   old key        pending      Retry
   Meter installed, response lost    NEW key        pending      ★ see below
   Response received but HES crashed NEW key        pending      Recover from DB
```

**★ The dangerous case** is identical in shape to the `change_HLS_secret`
problem the Green Book explicitly declines to solve (Volume 1 §6.6): the meter
has moved on, the head-end does not know it.

**[IMPL] The recovery, and it must be designed in from the start:**

```c
/* HES side: keep BOTH keys until a successful association proves
   which one is live.                                              */
typedef struct {
    uint8_t key_current[32];
    uint8_t key_pending[32];
    bool    pending_valid;
} hes_key_state_t;

/* On association: try pending first, then current. */
int hes_associate(meter_t *m)
{
    if (m->keys.pending_valid && try_associate(m, m->keys.key_pending) == OK) {
        promote_pending_to_current(m);      /* rotation confirmed */
        return OK;
    }
    if (try_associate(m, m->keys.key_current) == OK) {
        /* Old key still live ⇒ the rotation did not complete.
           Retry it.                                              */
        m->keys.pending_valid = false;
        return OK;
    }
    alarm(ALARM_METER_KEY_LOST);            /* neither works — field visit */
    return ERR;
}
```

**[IMPL] Meter-side hardening (optional, [VENDOR]).** A meter *may* accept
either the old or the new key for a short grace window after a rotation. This
converts the dangerous case into a self-healing one. It is not specified
behaviour, so a client must not depend on it — but if you control both ends it
is a worthwhile robustness measure. Bound the window tightly and log every use
of the old key after rotation.

---

## 30.5 Rotation ordering

**[IMPL]** When rotating several keys, order matters:

```
   1. GAK   (authentication key)
   2. GUEK  (unicast encryption key)
   3. GBEK  (broadcast encryption key)
   4. KEK   (master key) — LAST
```

Rationale: the KEK protects the transfer of all the others. Rotate it first and
you must re-wrap everything under a key whose installation you have not yet
confirmed. Rotate it last, after all dependent keys are confirmed working, and
a KEK failure leaves you with a functioning meter you can retry against.

**[IMPL] Rotate one key per association, and confirm before proceeding.**
Batching all four into one exchange means a single interruption leaves four
keys in an unknown state.

---

## 30.6 Certificate renewal

**[SPEC]** [GB] 9.2.6.6.4:

> *"There may be only one key pair and certificate present for the same purpose
> (digital signature, key agreement, TLS). Therefore when the new certificate
> is successfully imported the old certificate is removed. From this point, the
> new key pair can be used for transactions."*

**[IMPL] This hard cutover has no overlap window,** so sequence it carefully:

```
   ① generate_key_pair          — new pair exists, but the old one is
                                  still in use (no certificate yet)
   ② generate_certificate_request
   ③ CA issues the certificate  — the HES now HAS the new certificate
   ④ HES stores it and distributes it to any verifying parties
   ⑤ import_certificate         — ★ ATOMIC CUTOVER on the meter
   ⑥ verify with a test signature before declaring success
```

Step ④ before step ⑤ is the important ordering. If the meter cuts over before
verifiers know the new certificate, every signature it produces is unverifiable
until they catch up.

**[SPEC]** Note also from [GB] 9.2.6.6.7 that removing a server certificate
requires destroying the associated private key. So an import that replaces an
old certificate must also destroy the old private key — an erase, not an
unlink (Volume 3 §19.7.4).

---

## 30.7 Volume 5 summary

1. Layer the design: application → security manager → crypto abstraction →
   key storage. **The manager never sees key bytes; the CAL never sees DLMS.**
2. Protection checking is **two-stage**: policy minimum at unprotect time,
   per-object access rights after parsing.
3. `HLS_PASS2_SENT` must permit exactly one method. Test the bypass explicitly.
4. Serialise the invocation counter. A race here is nonce reuse.
5. Order power-loss-sensitive operations: **key first, then counter reset**,
   journalled.
6. Budget roughly 12 KB flash / 1 KB RAM for suite 0; ~40 KB / 4–7 KB for suite
   1; ~48 KB / 6–10 KB for suite 2 — plus 2–4 KB of peak stack for ECC.
7. **[SPEC]** A suite-2 meter must implement P-256 *and* P-384 ([GB] Table 33).
8. Stream the AAD; store certificates in flash with a small RAM index.
9. Application flash is not key storage. Wrap global keys under a KEK held in
   OTP, and derive keys per device from an HSM seed plus the System Title.
10. **[SPEC]** The RNG *"shall be preferably non-deterministic"*. Fail closed on
    insufficient entropy; run continuous health tests; prefer RFC 6979 to remove
    the RNG from the ECDSA path.
11. Rotate GAK → GUEK → GBEK → KEK, one at a time, confirming each.
12. Both ends must survive a half-completed rotation: keep old and new until an
    association proves which is live.

---

**Next: Volume 6 — the security failure-mode matrix, attack analysis,
key-compromise blast radius, the top 50 engineering mistakes, twelve hands-on
labs, four tiers of interview questions with answers, the SME capstone project
with a grading rubric, and the full glossary.**

*End of Volume 5.*

---

← **Previous:** [Volume 4 — General Ciphering and Packet Analysis](VOL-4-General-Ciphering-and-Packet-Analysis.md)  ·  **Next:** [Volume 6 — Failure Analysis, Attacks, Labs and Capstone](VOL-6-Debugging-Attacks-Labs-and-SME-Capstone.md) →

[Back to the index](00-INDEX.md)
