# DLMS/COSEM SECURITY — MASTER ENGINEERING REFERENCE

**Volume 6 — Failure Analysis, Attacks, Labs, and the SME Capstone**
*Chapters 31–38*

> Prerequisites: Volumes 0–5.

---

# CHAPTER 31 — THE SECURITY FAILURE-MODE MATRIX

## 31.1 How to use this

Find the symptom, read across. **Packet evidence** is what you can see in a
capture; **firmware evidence** is what you would find with a debugger or a log.

---

### F-01 Authentication failed (AARE rejected)

| | |
|--|--|
| **Symptom** | AARE returns `result = rejected(permanent)` with a diagnostic |
| **Likely cause** | Wrong mechanism, wrong password/secret, wrong application context, unknown client SAP |
| **Packet evidence** | Compare AARQ `mechanism-name` OID against the meter's configuration; check `application-context-name` |
| **Firmware evidence** | Association lookup failed on `(client SAP, server SAP)`; secret comparison failed |
| **Diagnostic steps** | 1. Decode the `mechanism-name` last arc against [GB] Table 75. 2. Confirm the context_id permits ciphering if you intend to use it. 3. Confirm the client SAP maps to a configured association |
| **Fix** | Align the mechanism ID and context name with the meter's configuration |

### F-02 HLS pass 3 rejected

| | |
|--|--|
| **Symptom** | ACTION on `reply_to_HLS_authentication` returns failure; association aborts |
| **Likely cause** | Wrong `f()` computation, wrong secret/AK, wrong system title in the IV, challenge mismatch |
| **Packet evidence** | `f(StoC)` length wrong (should be 17 octets for mech 5 suite 0, 32 for mech 6, 64 for mech 7 on P-256) |
| **Firmware evidence** | Constant-time comparison of tags failed |
| **Diagnostic steps** | Reproduce [GB] Table 43 offline. If your code cannot reproduce it, the bug is yours, not the meter's |
| **Fix** | See F-03 through F-08 |

### F-03 GMAC mismatch

| | |
|--|--|
| **Symptom** | HLS mech 5 tag does not match |
| **Likely cause** | Challenge placed in plaintext rather than AAD; wrong AK; wrong system title; wrong SC in the AAD |
| **Packet evidence** | If `f(StoC)` is longer than 17 octets, a ciphertext field is present that should not be |
| **Firmware evidence** | `gcm_encrypt` called with non-empty plaintext |
| **Diagnostic steps** | Assert `plaintext_len == 0` on the GMAC path. Print the AAD and compare against `10 D0D1…DEDF ‖ StoC` |
| **Fix** | `P = ∅`, `A = SC ‖ AK ‖ challenge` |

### F-04 GCM tag mismatch on a data APDU

| | |
|--|--|
| **Symptom** | Ciphered GET/SET fails verification |
| **Likely cause** | Wrong AAD (missing AK, missing metadata lengths), wrong IV, wrong key set, tag truncated from the wrong end |
| **Packet evidence** | SC byte, IC, and tag length all look correct — this failure is invisible on the wire |
| **Firmware evidence** | Computed tag differs from received tag |
| **Diagnostic steps** | Follow the Volume 4 §24.3 chain. Check AAD construction first — it is the most common cause |
| **Fix** | For `E=1,A=1`: `A = SC ‖ AK` only. For `E=0,A=1`: `A = SC ‖ AK ‖ APDU` |

### F-05 Wrong System Title

| | |
|--|--|
| **Symptom** | Tag mismatch on every APDU, in one direction only |
| **Likely cause** | Used the peer's title for an outgoing message, or vice versa |
| **Packet evidence** | For `general-glo-ciphering`, compare the `system-title` field against the expected originator |
| **Firmware evidence** | `build_iv()` called without a direction parameter |
| **Diagnostic steps** | The IV always uses the **originator's** title. Verify separately for TX and RX |
| **Fix** | Make direction an explicit parameter (Volume 2 §11.3) |

### F-06 Wrong Invocation Counter / replay rejected

| | |
|--|--|
| **Symptom** | Peer rejects before decryption; or your decryption fails |
| **Likely cause** | Counter not incremented; TX and RX counters shared; endianness wrong; counter reset on boot |
| **Packet evidence** | IC repeats, or decreases, or resets to a low value |
| **Firmware evidence** | Single `ic` variable used for both directions |
| **Diagnostic steps** | Log IC on every TX and RX. It must be strictly increasing per direction |
| **Fix** | Separate TX and RX counters ([SPEC] [GB] 9.2.3.3.7.3); big-endian in the IV |

### F-07 Replay detected (legitimate traffic rejected)

| | |
|--|--|
| **Symptom** | Valid messages rejected as replays after a meter reset |
| **Likely cause** | Meter's RX floor is ahead of the client's TX counter, or the client reset its counter |
| **Packet evidence** | Client's IC lower than the last accepted value |
| **Firmware evidence** | `ic_rx_floor` above the incoming IC |
| **Diagnostic steps** | Read the meter's exposed invocation counter if available; resynchronise |
| **Fix** | Client jumps its TX counter forward past the meter's floor. **Never** ask the meter to lower its floor |

### F-08 Wrong key

| | |
|--|--|
| **Symptom** | Everything fails; nothing decrypts |
| **Likely cause** | GUEK/GAK swapped; wrong key set selected; dedicated key expected but global used |
| **Packet evidence** | SC bit 6 indicates a key set you did not expect |
| **Firmware evidence** | Key handle resolution picked the wrong slot |
| **Diagnostic steps** | Test against [GB] Table 40 with known keys to isolate whether the bug is key selection or algorithm |
| **Fix** | Distinct opaque types for EK / AK / KEK (Volume 3 §14.4) |

### F-09 Wrong security suite

| | |
|--|--|
| **Symptom** | SC low nibble does not match the negotiated context |
| **Likely cause** | Misconfiguration, or a downgrade attempt |
| **Packet evidence** | SC bits 3..0 ≠ configured `security_suite` |
| **Firmware evidence** | Suite check missing from the receive path |
| **Diagnostic steps** | Decode SC per [GB] Table 37 — suite ID is the low nibble, compression is bit 7 |
| **Fix** | Reject any APDU whose SC suite differs from the security context |

### F-10 Wrong Security Control byte

| | |
|--|--|
| **Symptom** | Protection weaker than policy; or a malformed-APDU rejection |
| **Likely cause** | Wrong Security Control bit layout; Key_Set set on a `ded`/`general` APDU; compression set on a service-specific APDU |
| **Packet evidence** | Decode all 8 bits and check against the constraints in Volume 2 §9.2.3 |
| **Fix** | Apply the full SC validation checklist |

### F-11 Incorrect key length

| | |
|--|--|
| **Symptom** | Crypto library error, or a tag that never matches |
| **Likely cause** | 128-bit key used with suite 2, or 256-bit with suite 0/1 |
| **Firmware evidence** | Key schedule built for the wrong round count |
| **Fix** | Derive key length from the suite: 16 octets for suites 0/1, 32 for suite 2 |

### F-12 Incorrect IV

| | |
|--|--|
| **Symptom** | Tag mismatch |
| **Likely cause** | IV not 12 octets; System Title and IC concatenated in the wrong order; IC little-endian |
| **Firmware evidence** | `iv[12]` built with `memcpy` of a `uint32_t` |
| **Fix** | `IV = Sys-T(8) ‖ IC(4)`, IC big-endian, exactly 12 octets |

### F-13 Malformed ciphered APDU

| | |
|--|--|
| **Symptom** | Parse error before any crypto |
| **Likely cause** | A-XDR length encoding wrong; tag/length mismatch; segmentation not reassembled |
| **Packet evidence** | Declared length ≠ actual remaining bytes |
| **Fix** | Reassemble HDLC segments and `general-block-transfer` before decrypting |

### F-14 Certificate validation failure

| | |
|--|--|
| **Symptom** | `import_certificate` returns FAIL; HLS mech 7 fails |
| **Likely cause** | Expired validity; chain does not reach a trust anchor; unrecognised critical extension; wrong curve; `hwSerialNum` ≠ System Title |
| **Packet evidence** | Certificate present in `calling-AE-qualifier` but rejected |
| **Firmware evidence** | Which of the five [GB] 9.2.6.3.2 checks failed |
| **Diagnostic steps** | Check the meter's clock first — it is the most common cause |
| **Fix** | Correct the clock, provision the missing CA certificate, or reissue |

### F-15 ECDSA verification failure

| | |
|--|--|
| **Symptom** | Signature rejected |
| **Likely cause** | **DER format used instead of plain `R‖S`**; wrong hash for the suite; leading zeros stripped; wrong public key |
| **Packet evidence** | Signature length ≠ 64 (P-256) or 96 (P-384) |
| **Fix** | Convert DER → fixed-length `R‖S` with left zero padding (Volume 3 §17.4.3) |

### F-16 ECDH / key agreement failure

| | |
|--|--|
| **Symptom** | Derived keys differ between the parties; nothing decrypts |
| **Likely cause** | Wrong `AlgorithmID` octets in `OtherInfo`; system titles in the wrong order; `Nonce_U` omitted for C(0e,2s); `Z` used directly without the KDF |
| **Firmware evidence** | KDF input differs from the peer's |
| **Diagnostic steps** | Log the full `OtherInfo` on both sides and diff it byte by byte |
| **Fix** | `OtherInfo = AlgorithmID ‖ ID_U ‖ [Nonce_U] ‖ ID_V`. See the source-gap note in Volume 3 §18.7.3 |

### F-17 Key wrap / unwrap failure

| | |
|--|--|
| **Symptom** | `key_transfer` returns FAIL |
| **Likely cause** | Wrong KEK; wrapped data corrupted; wrong length (must be key length + 8) |
| **Firmware evidence** | RFC 3394 integrity check `A6A6A6A6A6A6A6A6` did not match |
| **Fix** | Verify the KEK and that the wrapped blob is 24 octets (128-bit) or 40 (256-bit) |

### F-18 Counter rollback

| | |
|--|--|
| **Symptom** | IC lower after a reset than before |
| **Likely cause** | Counter reset on boot; NVM write not persisted; reservation block not implemented |
| **Packet evidence** | **IC decreases across a capture — a critical finding** |
| **Firmware evidence** | `ic_tx = 0` in an init function |
| **Fix** | Reservation-block persistence; on doubt jump forward (Volume 2 §10.5) |

### F-19 Counter overflow

| | |
|--|--|
| **Symptom** | Transmission refused; `ERR_IC_EXHAUSTED` |
| **Likely cause** | 2³²−1 reached, or an injected high-IC message pushed the RX floor up |
| **Fix** | **[SPEC]** Key rotation resets the counters. Consider a forward sanity window on the RX path |

### F-20 Corrupted NVM

| | |
|--|--|
| **Symptom** | Counter or key store unreadable at boot |
| **Likely cause** | Flash wear; interrupted write; no CRC |
| **Correct behaviour** | **Fail closed.** Disable ciphering, raise an alarm. **Never** reset the counter to zero |
| **Fix** | Ping-pong records with CRC; recover via key rotation |

---

# CHAPTER 32 — ATTACK ANALYSIS

Format: **attack → prerequisite → path → weakness exploited → DLMS defence →
residual risk.**

### A-01 Eavesdropping

- **Prerequisite:** physical or radio access to the link
- **Path:** passive capture
- **Weakness:** no confidentiality
- **DLMS defence:** AES-GCM encryption, SC bit 5
- **Residual risk:** APDU tag, length, SC, IC, and System Title remain visible.
  Traffic analysis reveals polling schedule and service class (Volume 2 §13.7)

### A-02 Replay

- **Prerequisite:** a captured valid ciphered APDU
- **Path:** retransmit the identical bytes
- **Weakness:** no freshness
- **DLMS defence:** **[SPEC]** invocation counter verification ([GB]
  9.2.3.3.7.3); random HLS challenges
- **Residual risk:** if the receiver does not implement the floor check, or
  resets it on reboot, replay works. This is an implementation risk, not a
  protocol one

### A-03 Impersonation of the client

- **Prerequisite:** the LLS password, or the HLS secret/AK
- **Path:** open an association as the head-end
- **Weakness:** credential compromise
- **DLMS defence:** HLS mutual authentication; message security independent of
  authentication
- **Residual risk:** with LLS the password is on the wire in cleartext (Volume 1
  §5.2). Under a mandatory-encryption policy the password alone is insufficient

### A-04 Impersonation of the server (rogue meter)

- **Prerequisite:** ability to intercept and answer
- **Path:** answer the AARQ, harvest client behaviour
- **Weakness:** unilateral authentication
- **DLMS defence:** HLS pass 4 — the server must prove key knowledge
- **Residual risk:** clients that skip pass 4 verification, or skip the
  `StoC != CtoS` check, are vulnerable

### A-05 Man-in-the-middle

- **Prerequisite:** position on the link
- **Path:** relay and modify
- **Weakness:** no integrity, or unilateral authentication
- **DLMS defence:** authenticated encryption; HLS; ECDSA-signed ephemeral keys
  in C(1e,1s)
- **Residual risk:** **unverified ephemeral public keys** in key agreement give
  a textbook MITM. Volume 4 §20.7 check 4 is not optional

### A-06 Key extraction from the device

- **Prerequisite:** physical possession
- **Path:** debug port, ROM bootloader, decapsulation, glitching
- **Weakness:** keys in application-readable flash
- **DLMS defence:** none — this is outside the protocol
- **Residual risk:** **entirely an implementation problem.** Volume 5 §27

### A-07 Key injection

- **Prerequisite:** the KEK, or write access to key storage
- **Path:** wrap attacker keys, invoke `key_transfer`
- **Weakness:** KEK compromise
- **DLMS defence:** access rights on `key_transfer`; the wrapped transfer must
  itself be protected
- **Residual risk:** with the KEK, the attacker can lock the legitimate operator
  out permanently (Volume 3 §15.5)

### A-08 Nonce reuse

- **Prerequisite:** the target reuses an IV
- **Path:** collect two ciphertexts under the same (key, IV)
- **Weakness:** counter reset or duplicated System Title
- **DLMS defence:** **[SPEC]** the uniqueness requirement in [GB] 9.2.3.3.7.3
- **Residual risk:** **catastrophic** — confidentiality *and* authenticity lost,
  including recovery of the GHASH subkey H and arbitrary forgery (Volume 2
  §10.3)

### A-09 Counter rollback

- **Prerequisite:** ability to force a reset (power glitch, tamper switch)
- **Path:** reset repeatedly until the counter restarts
- **Weakness:** counter not persisted
- **DLMS defence:** none in the protocol
- **Residual risk:** high on any implementation without reservation-block
  persistence. **[INFER]** A deliberately induced brownout is a realistic field
  attack on a meter an adversary physically controls

### A-10 Weak RNG

- **Prerequisite:** predictable challenge or key generation
- **Path:** predict `StoC`, or recover a key
- **Weakness:** poor entropy
- **DLMS defence:** **[SPEC]** [GB] 9.2.3.5 requires a strong RNG
- **Residual risk:** entirely implementation-dependent (Volume 5 §28)

### A-11 Password guessing

- **Prerequisite:** ability to send AARQs
- **Path:** brute force the LLS password
- **Weakness:** short, low-entropy, fleet-wide passwords; no lockout
- **DLMS defence:** none specified
- **Residual risk:** **[VENDOR]** lockout and backoff are implementation choices

### A-12 HLS challenge manipulation

- **Prerequisite:** MITM position
- **Path:** substitute `StoC` with `CtoS`, or replay a challenge
- **Weakness:** missing `StoC != CtoS` check; reused challenges
- **DLMS defence:** **[SPEC]** *"If StoC is the same as CtoS, the client shall
  reject it and shall abort"* ([GB] 9.2.2.2.2.4)
- **Residual risk:** the check is frequently omitted in client implementations

### A-13 Certificate compromise

- **Prerequisite:** a CA private key, or a mis-issued certificate
- **Path:** issue a certificate for an attacker key
- **Weakness:** CA compromise
- **DLMS defence:** trust anchors provisioned OOB and immutable; certificate
  removal
- **Residual risk:** **[SPEC]** [GB] 9.2.6.3.2 pushes revocation to the operator
  — meters do not check CRLs. Revocation latency equals field-management cycle
  time (Volume 3 §19.6)

### A-14 Firmware extraction

- **Prerequisite:** physical access, or an unsigned OTA image
- **Path:** dump flash, recover keys and logic
- **DLMS defence:** none — outside the protocol
- **Residual risk:** without secure boot, all DLMS security is decorative
  (Volume 5 §25.5)

### A-15 Fault injection

- **Prerequisite:** physical access, glitching equipment
- **Path:** skip a tag comparison, skip a read-protect check, corrupt an ECDSA
  computation
- **DLMS defence:** none
- **Residual risk:** **[IMPL]** mitigate with redundant checks, random delays,
  and verifying signatures after generating them

### A-16 Side-channel attack

- **Prerequisite:** physical access, power/EM measurement
- **Path:** DPA on AES; timing on tag comparison; template attacks on ECC
- **DLMS defence:** none
- **Residual risk:** **[IMPL]** constant-time comparison is mandatory and free;
  masked AES and constant-time scalar multiplication cost more. A secure element
  moves this problem off your die

### A-17 Downgrade

- **Prerequisite:** ability to modify the AARQ or the SC byte
- **Path:** negotiate a weaker mechanism or suite
- **Weakness:** missing validation that the applied protection meets policy
- **DLMS defence:** **[SPEC]** *"APDUs with less protection than required by the
  security policy and the access rights shall be rejected"* ([GB] 9.2.7.2.2)
- **Residual risk:** implementations that check equality instead of a superset,
  or omit the suite check

### A-18 Denial of service

- **Prerequisite:** ability to send frames
- **Path:** open associations and never complete HLS; inject high-IC messages to
  exhaust the counter; inject RLRQ to tear down sessions
- **DLMS defence:** partial — the RLRQ can be protected
- **Residual risk:** **[IMPL]** association timeouts, a cap on concurrent
  pending associations, and a forward sanity window on the RX counter

---

# CHAPTER 33 — KEY COMPROMISE: BLAST RADIUS

For each key: what the attacker gains, what they do not, whether past and
future traffic are affected, and how to recover.

### GUEK compromised

| | |
|--|--|
| **Can do** | Decrypt all unicast traffic, past (if recorded) and future |
| **Cannot do** | Forge valid tags without the GAK; decrypt broadcast traffic |
| **Blast radius** | Every association with this peer using this key |
| **Past traffic** | ❌ **Affected** — no forward secrecy in suite 0 |
| **Future traffic** | ❌ Affected until rotation |
| **Recovery** | Rotate GUEK via `key_transfer` (needs an uncompromised KEK) or C(2e,0s) |

### GAK compromised

| | |
|--|--|
| **Can do** | Verify tags; with the GUEK also, forge arbitrary valid APDUs; impersonate in HLS mechanism 5 |
| **Cannot do** | Decrypt anything alone |
| **Blast radius** | **Unicast and broadcast** — the GAK is shared across both |
| **Past traffic** | Confidentiality unaffected; authenticity retrospectively unprovable |
| **Future traffic** | ❌ Forgery possible if the GUEK is also known |
| **Recovery** | Rotate GAK first (Volume 5 §30.5) |

### GBEK compromised

| | |
|--|--|
| **Can do** | Decrypt all broadcast traffic |
| **Blast radius** | ⚠️ **The entire broadcast group** — every meter sharing it |
| **Recovery** | Rotate GBEK on every member. **[INFER]** Operationally the most expensive rotation, which is why broadcast confidentiality should not be relied upon |

### Dedicated key compromised

| | |
|--|--|
| **Can do** | Decrypt one association |
| **Cannot do** | Touch any other association |
| **Past/future** | ✅ Both unaffected outside that association |
| **Recovery** | None needed — the key dies with the association |

### KEK / master key compromised

| | |
|--|--|
| **Can do** | Unwrap every past and future key transfer; inject arbitrary keys; **install a new KEK and lock the operator out** |
| **Cannot do** | Nothing meaningful is out of reach |
| **Blast radius** | 🔴 **Total and permanent** |
| **Past traffic** | ❌ Every key ever transferred is recoverable from recorded traffic |
| **Recovery** | **Physical field visit.** There is no remote recovery |

### HLS secret compromised

| | |
|--|--|
| **Can do** | Authenticate as the client; impersonate the meter to a client (mechanisms 3, 4, 6) |
| **Cannot do** | Decrypt anything — it is not an encryption key |
| **Recovery** | `change_HLS_secret`, with the lost-acknowledgement handling of Volume 1 §6.6 |

### LLS password compromised

| | |
|--|--|
| **Can do** | Open an association |
| **Cannot do** | Anything useful if the security policy mandates authenticated encryption |
| **Recovery** | `change_LLS_secret` |

### ECDSA private key compromised

| | |
|--|--|
| **Can do** | Sign as that entity; pass HLS mechanism 7; forge non-repudiable data |
| **Cannot do** | Decrypt anything; derive ECDH secrets (different key pair — **[SPEC]** [GB] 9.2.3.4.1) |
| **Past traffic** | Confidentiality unaffected; **all past signatures become repudiable** |
| **Recovery** | `remove_certificate` (destroys the private key), `generate_key_pair`, re-issue |

### ECDH static private key compromised

| | |
|--|--|
| **Can do** | Derive `Z` for every C(1e,1s) exchange where this party was V, and every C(0e,2s) exchange |
| **Past traffic** | ❌ **Affected** — C(1e,1s) and C(0e,2s) offer no forward secrecy against V's compromise |
| **Not affected** | C(2e,0s) exchanges — both keys were ephemeral |
| **Recovery** | New key agreement key pair and certificate |

### Certificate compromised (CA key)

| | |
|--|--|
| **Can do** | Issue certificates for attacker-controlled keys, accepted by every meter trusting that CA |
| **Blast radius** | 🔴 Every meter under that CA |
| **Recovery** | Revoke and remove — but **[SPEC]** meters do not check CRLs, so removal must be pushed to every meter individually |

---

# CHAPTER 34 — TOP 50 ENGINEERING MISTAKES

**Counter and IV**

1. Resetting the invocation counter to zero on power-up.
2. Sharing one counter between transmit and receive.
3. Writing the counter to flash on every message (wear-out).
4. Non-atomic counter persistence with no CRC.
5. Little-endian invocation counter in the IV.
6. Building the IV with the peer's System Title on the transmit path.
7. Advancing the RX floor before the tag verifies.
8. Using `<=` instead of `<` in the replay check.
9. No handling for counter exhaustion.
10. Losing the counter across an OTA update.

**AAD and GMAC**

11. Placing the HLS challenge in the plaintext instead of the AAD.
12. Omitting the authentication key from the AAD.
13. Including the APDU in the AAD when it is already the plaintext.
14. Omitting length octets from the `general-ciphering` AAD.
15. Rebuilding the AAD metadata instead of slicing the received bytes.
16. Using a hardcoded SC in the AAD rather than the transmitted one.
17. Buffering a full-size AAD instead of streaming it.

**Security Control byte**

18. Using the wrong Security Control bit layout.
19. Not validating the suite against the negotiated context (downgrade).
20. Testing protection equality instead of a superset.
21. Setting Key_Set on a `ded-` or `general-` ciphering APDU.
22. Setting compression on a service-specific ciphering APDU.
23. Deploying encryption-only (`SC = 0x20`).

**Keys**

24. Confusing GUEK and GAK.
25. Using the KEK as a message encryption key.
26. Storing keys in application flash.
27. Fleet-wide keys with no per-device derivation.
28. Using the same key pair for both ECDSA and ECDH.
29. Wrong key length for the suite.
30. Sizing a wrapped-key buffer at the key length instead of key length + 8.
31. Not destroying `Z` after key derivation.
32. Not destroying the private key when a certificate is removed.

**Authentication**

33. Accepting services other than `reply_to_HLS_authentication` in
    `HLS_PASS2_SENT` — an authentication bypass.
34. Omitting the `StoC != CtoS` check.
35. Reusing a challenge across association attempts.
36. Not aborting the association after a failed pass 3.
37. `memcmp` for tag or password comparison.
38. No timeout on a pending HLS association.
39. Using HMAC-SHA-256 for mechanism 6 instead of a plain hash.
40. Using the wrong mechanism ID.

**Public key**

41. DER-encoded ECDSA signature instead of plain `R‖S`.
42. Stripping leading zeros from `r` or `s`.
43. Not verifying the signature on an ephemeral public key in C(1e,1s).
44. Accepting curve parameters from the wire instead of the curve OID.
45. Reusing or biasing the ECDSA nonce `k`.
46. Not checking `KeyUsage` before using a certificate.
47. Not checking `hwSerialNum` against the System Title.

**Architecture and operations**

48. Releasing unverified plaintext to the APDU parser.
49. Resetting the counter to zero on NVM corruption instead of failing closed.
50. Deploying a ciphered application context with `security_policy = 0` — it
    looks secure in a configuration screen and enforces nothing.

---

# CHAPTER 35 — PRACTICAL LABS

Each lab states the objective, materials, procedure, and success criterion.
Labs 1–7 need only a computer. Labs 8–12 build toward firmware.

### LAB 1 — Decode the Security Control byte

**Objective:** fluency with [GB] Table 37.
**Procedure:** decode `0x10, 0x20, 0x30, 0x31, 0x32, 0x50, 0x70, 0x90, 0xB0,
0xF2` — for each, write the binary, then suite / A / E / Key_Set / compression,
then the expected APDU shape.
**Success:** your decodes match Volume 2 §9.2.3 without consulting it.
**Trap:** `0x50` is **not** "suite 1".

### LAB 2 — Construct AES-GCM inputs

**Objective:** build `IV`, `P`, and `A` for each protection mode.
**Materials:** [GB] Table 40 security material.
**Procedure:** for `SC = 0x10`, `0x20`, `0x30`, write out `IV`, `P`, `A` by hand
before running any code.
**Success:** your `A` for `SC=0x10` is 30 octets and for `SC=0x30` is 17.

### LAB 3 — System Title and Invocation Counter

**Objective:** understand the IV split.
**Procedure:** given `Sys-T = 4D4D4D0000BC614E` and `IC = 0x01234567`, produce
the IV. Then compute the IV for the *next* three messages. Then compute what the
IV would be after a counter reset, and explain why that is dangerous.
**Success:** you can state the consequence of the reset in terms of keystream
reuse, not just "it is bad".

### LAB 4 — Reproduce the GMAC test vector

**Objective:** prove your GMAC construction against [GB] Table 43.
**Materials:** `dlms_test_vectors.py` in the repository root.
**Procedure:** compute `T = GMAC(SC ‖ AK ‖ StoC)` with the client IV. Then
deliberately break it four ways: put StoC in the plaintext; drop the AK; use the
server's System Title; truncate the tag from the LSB end. Observe each failure.
**Success:** `T = 1A52FE7DD3E72748973C1E28`, and you can predict which
modification produces which symptom.

### LAB 5 — Analyse HLS

**Objective:** walk all four passes.
**Procedure:** using [GB] Table 43, compute `f(StoC)` and `f(CtoS)`. Identify
which System Title and which counter each uses. Then answer: why can the server
not simply echo `f(StoC)` back as `f(CtoS)`?
**Success:** both 17-octet values match, and you can articulate the asymmetry.

### LAB 6 — Decode a ciphered APDU

**Objective:** full byte-level decode.
**Materials:** `C81E3001234567411312FF935A47566827C467BC7D825C3BE4A77C3FCC056B6B`
**Procedure:** identify tag, length, SC, IC, ciphertext, tag. Verify the length
arithmetic. Decrypt with the [GB] Table 40 keys. Identify the OBIS code and
attribute in the recovered APDU.
**Success:** you recover `C0010000080000010000FF0200` and identify it as a GET
of Clock attribute 2.

### LAB 7 — Compare the suites

**Objective:** justify a suite choice.
**Procedure:** build the Volume 2 §12.6 matrix from memory. Then write a
one-page recommendation for: (a) a 2 MB-flash meter on a private network; (b) a
meter that must give third-party access; (c) a meter with a 25-year regulatory
retention requirement.
**Success:** each recommendation cites a *capability* difference, not "stronger
encryption".

### LAB 8 — Conceptual ECDSA verification

**Objective:** understand what verification proves.
**Materials:** [GB] Table 44.
**Procedure:** write out the verification steps with the given `Pub-KC` and
`f(StoC)`. Explain why you cannot *recompute* the signature from the Green
Book's data, and what that tells you about `k`.
**Success:** you can explain the difference between verifying and signing here.

### LAB 9 — Conceptual ECDH

**Objective:** distinguish the three schemes.
**Procedure:** for each of C(2e,0s), C(1e,1s), C(0e,2s), draw the message flow,
state what each party contributes, and state the forward-secrecy property. Then
determine which scheme a third party with only a certificate can use, and why.
**Success:** you identify `agreed-key` as the only third-party-capable
`key-info` choice.

### LAB 10 — Design secure key storage

**Objective:** produce a storage plan.
**Procedure:** for a Cortex-M4 with 512 KB flash, 128 KB RAM, a hardware AES
peripheral, no secure element, and internal flash read-protection: decide where
the KEK, GUEK, GAK, System Title, and counters live. Justify each. State what an
attacker with physical possession gains.
**Success:** the KEK is not in application-readable flash, and you have an
honest answer for the physical-possession case.

### LAB 11 — Design invocation counter persistence

**Objective:** a correct persistence scheme.
**Procedure:** given 100,000 flash write cycles, a 15-year life, and 200,000
messages/year, compute the minimum reservation block size. Then design the
ping-pong record layout and write the boot-time recovery logic. Then answer:
what happens if both records are corrupt?
**Success:** block size ≥ 30, recovery takes the **higher** ceiling, and both-
corrupt fails closed.

### LAB 12 — Debug a broken implementation

**Objective:** systematic diagnosis.
**Procedure:** implement DLMS AES-GCM protection. Then introduce these bugs one
at a time and, for each, predict the symptom *before* testing:

| # | Bug |
|---|-----|
| 1 | AAD omits the authentication key |
| 2 | IC little-endian in the IV |
| 3 | Tag truncated to 16 octets |
| 4 | Peer's System Title used on the transmit path |
| 5 | Counter reset on init |
| 6 | `memcmp` for tag comparison |
| 7 | APDU included in the AAD when `E=1` |
| 8 | Suite check omitted on receive |

**Success:** you predict all eight symptoms correctly, and for each you can name
which step of the Volume 4 §24.3 chain would catch it.

---

# CHAPTER 36 — QUESTION BANKS

Answers follow each tier.

## 36.1 Beginner (10)

1. What are the three DLMS authentication mechanism families?
2. How long is the System Title, and what do its leading three octets hold?
3. How long is the Invocation Counter?
4. What is the length of the IV, and what are its two parts?
5. What does bit 5 of the Security Control byte indicate?
6. What is the authentication tag length in DLMS?
7. Which key is the GCM block cipher key?
8. What does LLS transmit that HLS does not?
9. Which APDU carries the CtoS challenge?
10. What is the difference between authentication and authorization?

**Answers:** 1. No security (lowest), LLS, HLS. 2. 8 octets; the FLAG
three-letter manufacturer ID. 3. 4 octets / 32 bits. 4. 12 octets = System Title
(8) ‖ Invocation Counter (4). 5. Encryption applied ("E"). 6. 96 bits / 12
octets, in all three suites. 7. The encryption key — GUEK, GBEK, or the
dedicated key. 8. A cleartext password in the AARQ. 9. The AARQ, in
`calling-authentication-value`. 10. Authentication is *who are you*;
authorization is *what may you do*.

## 36.2 Intermediate (10)

1. Why is the authentication key placed in the AAD rather than used as a key?
2. What is the AAD for `SC = 0x10` versus `SC = 0x30`?
3. Decode `0x70` fully.
4. Why must the client reject `StoC == CtoS`?
5. What does `context_id(3)` permit that `context_id(1)` does not?
6. Which APDU protects the dedicated key, and with which key?
7. Why are TX and RX invocation counters separate?
8. What is the wrapped size of a 128-bit key under AES key wrap?
9. What is the difference between `glo-` and `general-glo-ciphering`?
10. Which HLS mechanisms are deprecated by the specification itself?

**Answers:** 1. So that an attacker with only the encryption key still cannot
forge tags; two-key security at no extra cost, and the AK is never transmitted.
2. `0x10`: `SC ‖ AK ‖ APDU`, plaintext empty. `0x30`: `SC ‖ AK`, APDU is the
plaintext. 3. `0111 0000` — suite 0, A=1, E=1, Key_Set=1 (broadcast), no
compression: authenticated encryption under the GBEK. 4. Otherwise a rogue
server can replay the client's own `f(StoC)` as `f(CtoS)` without knowing the
secret. 5. Ciphered APDUs. 6. `glo-initiateRequest` inside the AARQ's
`user-information`, protected with the **global unicast** key. 7. **[SPEC]** [GB]
9.2.3.3.7.3 requires it; they track different sequences and a shared counter
breaks replay protection. 8. 24 octets (n+1 semiblocks). 9. `general-glo-`
carries the System Title explicitly and supports compression; `glo-` does not.
10. Mechanisms 3 (MD5) and 4 (SHA-1).

## 36.3 Senior engineer (10)

1. Explain exactly why nonce reuse breaks authenticity, not just confidentiality.
2. Design an invocation-counter persistence scheme for 10,000-cycle flash.
3. What is the security consequence of advancing the RX floor before tag
   verification?
4. Why does DLMS use AES key wrap for keys rather than AES-GCM?
5. When is `identified-key` not usable in `general-ciphering`, and why?
6. What forward-secrecy property does each of the three key agreement schemes
   have?
7. Why must the AAD for `general-ciphering` include field length octets?
8. How would you detect nonce reuse from a capture with no keys?
9. What ordering must a key rotation follow, and why?
10. Why is `SC = 0x00` legal in `general-ciphering` but nowhere else?

**Answers:** 1. Two tags under one (K, IV) give two equations in the GHASH
subkey H over GF(2¹²⁸); solving for H permits arbitrary tag forgery — the
"forbidden attack". 2. Reservation blocks: persist a ceiling, consume from RAM,
block size ≥ (messages × years) / cycles; ping-pong records with CRC; on
restore take the higher ceiling. 3. An attacker injecting a high-IC message with
an invalid tag desynchronises you from the legitimate peer — a denial of
service. 4. AES key wrap is deterministic: no nonce. Key installation is exactly
where counter synchronisation cannot be relied on. 5. With a third party — they
hold no GUEK/GBEK ([GB] Table 21 NOTE). 6. C(2e,0s) full; C(1e,1s) partial (U
only); C(0e,2s) none, and `Z` is constant across all transactions between the
pair. 7. **[SPEC]** [GB] Figure 84 requires it, and it prevents an attacker
shifting bytes between adjacent fields without detection. 8. Search for repeated
`(originator System Title, IC)` pairs. 9. GAK → GUEK → GBEK → KEK; the KEK
protects the transfer of the others, so it goes last. 10. It encodes "a
protection layer exists for this party but nothing is applied" — needed for the
multi-layer mirroring rule in [GB] 9.2.7.3, Example 2.

## 36.4 Expert (10)

1. A meter reproduces [GB] Table 40 but fails against a real head-end on
   `general-ciphering` only. Where do you look first?
2. Justify accepting or rejecting indefinitely-valid server certificates.
3. Design HLS mechanism 5 for a meter with no persistent counter storage.
4. What does the `transaction-id` do in C(0e,2s) that it does not do elsewhere?
5. Why does suite 2 require P-256 support as well as P-384?
6. Construct a threat model for a broadcast disconnect command.
7. An attacker can force meter reboots at will. Enumerate what they gain.
8. How would you provide forward secrecy in a suite 0 deployment?
9. Why is a two-stage protection check necessary, and what breaks with one
   stage?
10. Argue for and against deterministic ECDSA in a DLMS meter.

**Answers:** 1. AAD construction — specifically the length octets of the five
metadata fields, including empty ones. Table 40 exercises service-specific
ciphering only, which has no metadata. 2. **For:** meters have unreliable clocks
and 20-year lives; expiry causes mass field failures. **Against:** a
non-expiring certificate can only be removed by explicit operator action, and
meters do not check CRLs, so compromise persists for the field-management cycle.
3. You cannot do it safely. The counter is an IV component; without persistence
you get nonce reuse. Either add storage, or use a mechanism whose freshness
comes purely from the challenge — mechanism 6 — and accept that you still cannot
use AES-GCM for message security. 4. It supplies `Nonce_U`, the only source of
per-transaction variation in a scheme where `Z` is constant. 5. **[SPEC]** [GB]
Table 33 lists P-256 end-entity certificates signed with a P-384 CA as valid in
suite 2. 6. Assets: relay state. Adversary: anyone with the GBEK, i.e. any
compromised group member. Path: replay or forge a broadcast ACTION. Defences:
authentication bit set, invocation counter, access rights restricting the method
to a unicast high-security association. **[INFER]** Conclusion: do not expose
disconnect over broadcast at all. 7. Counter rollback if persistence is weak;
entropy-pool starvation if the RNG reseeds from scratch; a window where
`SEC_FAULT` handling may be less tested; observable IC resets for
reconnaissance. 8. Not fully — suite 0 has only static keys. You can *approximate*
it by rotating the GUEK frequently via `key_transfer` and destroying old keys,
but the KEK still recovers every transfer, so it is forward secrecy against GUEK
compromise only, not KEK compromise. 9. The security policy is
association-scoped and checkable at unprotect time; access rights are
object-scoped and require the decrypted APDU to know the target. One stage forces
you to know the object before decrypting the APDU that names it. 10. **For:**
removes the catastrophic `k` failure mode; signatures remain standard and
interoperable. **Against:** not referenced by [GB], so a companion specification
might constrain it; and it makes signatures deterministic, which leaks whether
the same message was signed twice.

## 36.5 Trick questions (5)

1. "Suite 2 uses 256-bit blocks, so buffers must double." — True or false?
2. "The authentication tag is 128 bits, like most GCM implementations." — ?
3. "ECDSA encrypts the APDU so only the holder of the public key can read it." — ?
4. "Since the dedicated key is per-session, suite 0 has forward secrecy." — ?
5. "`SC = 0x50` means suite 1 with authentication." — ?

**Answers:** 1. **False.** AES always has a 128-bit block; only the key grows.
No buffer alignment changes. 2. **False.** **[SPEC]** 96 bits in all three
suites ([GB] 9.2.3.3.7.6). 3. **False and confused.** ECDSA signs; it never
encrypts. **[SPEC]** *"Asymmetric key algorithms are not used for encryption in
DLMS/COSEM."* And a public key verifies, it does not decrypt. 4. **False.** The
dedicated key is transported under the GUEK, so GUEK compromise recovers every
dedicated key from recorded AARQs. 5. **False.** `0x50` is suite
**0**, authentication only, **broadcast** key.

---

# CHAPTER 37 — THE SME CAPSTONE

## 37.1 The brief

> Design the complete security architecture for a production smart meter
> communicating with a Head-End System. Target: 2 million meters, 15-year field
> life, mixed RF-mesh and cellular backhaul, disconnect-capable, with a
> regulatory requirement for third-party access to consumption data on customer
> consent.

Produce ten deliverables.

## 37.2 The deliverables

**1. Architecture diagram** — layer the stack from application to physical.
Mark the security boundary. Show where the security context, access rights, and
key storage sit.

**2. Key hierarchy** — every key, its size, lifetime, scope, storage location,
establishment method, and rotation strategy. Justify per-device vs fleet-wide
for each.

**3. Security state machine** — association lifecycle including the HLS states,
the `SEC_FAULT` state, and every transition with its trigger.

**4. APDU flow** — a complete annotated exchange from AARQ to release, showing
SC, IC, key, and protection at each step. Include one third-party
`general-ciphering` exchange.

**5. Key lifecycle** — manufacturing through decommissioning, with the
responsible party at each stage.

**6. Counter lifecycle** — persistence scheme with computed block size, power-
loss analysis, exhaustion handling, and the resynchronisation procedure.

**7. Threat model** — assets, adversaries with capabilities, attack paths,
defences, and residual risk. Include the physically-present adversary.

**8. Security policy** — the `security_policy` value for each association, the
access rights for at least the disconnect method and the billing registers, and
the justification.

**9. Firmware module architecture** — the layer diagram, public API, memory
budget with figures, and the secure-storage decision with its rationale.

**10. Test plan** — including the [GB] Table 40 and Table 43 self-tests, the
authentication-bypass test, the counter-persistence test across power cycles,
and negative tests for each of the twelve failure modes in Chapter 31.

## 37.3 Grading rubric

Score each dimension 0–10. A senior DLMS security architect would look for the
following.

| Dimension | What earns 8–10 | What caps you at 4 or below |
|-----------|-----------------|------------------------------|
| **Specification fidelity** | Correct clause citations; correct SC layout; correct mechanism IDs; correct tag and IV lengths | Any of the six classic specification errors reproduced |
| **Counter design** | Reservation blocks with computed size; ping-pong + CRC; fail-closed; explicit power-loss analysis; forward-only recovery | Counter reset to zero anywhere, for any reason |
| **Key storage** | KEK in OTP/SE; global keys wrapped at rest; per-device derivation from an HSM seed + System Title; honest statement of the physical-attack residual | Keys in application flash; fleet-wide keys |
| **Authentication** | HLS mech 5 minimum; `HLS_PASS2_SENT` gate; `StoC != CtoS`; abort-on-failure; timeout; constant-time compare | Any path that permits a service before pass 3 |
| **Authorization** | Separate associations for reading, configuration, and disconnect; the disconnect method reachable from exactly one high-security association | Disconnect reachable from the meter-reading association |
| **Suite choice** | Justified against the third-party and 15-year requirements, with memory and CPU figures; acknowledges the P-256+P-384 requirement | "Suite 2 because it is strongest", with no cost analysis |
| **Third-party model** | `general-ciphering` with `agreed-key`; C(1e,1s); ephemeral public key signature **verified**; broker responsibilities stated | Third party given the global keys |
| **Threat model** | Includes the physically-present adversary, counter rollback, and the broadcast-key blast radius; states residual risk honestly | Only network-level attackers considered |
| **Firmware architecture** | Key handles not key bytes; CAL knows no DLMS; two-stage protection check; concurrency addressed | Security manager holds raw keys |
| **Test plan** | Official vectors as a power-on self-test; explicit bypass test; power-cycle counter test; negative tests | "We will test interoperability" |

**Automatic fail conditions** — a design with any of these would be rejected in
review regardless of its other merits:

- Invocation counter reset to zero on boot or on NVM fault.
- Any service permitted in `HLS_PASS2_SENT` other than
  `reply_to_HLS_authentication`.
- Encryption-only (`SC = 0x20`) in the production policy.
- KEK recoverable from application flash.
- Disconnect method reachable from the routine meter-reading association.
- Unverified ephemeral public key in key agreement.

## 37.4 A worked answer sketch for deliverable 8

To calibrate what "good" looks like:

| Association | Client SAP | Mechanism | `security_policy` | Access rights summary |
|-------------|-----------|-----------|-------------------|----------------------|
| **Public** | 16 | none (0) | 0 | Read-only: LDN, firmware version, invocation counter. No billing data |
| **Reading** | 32 | HLS-GMAC (5) | authenticated + encrypted, both directions | Read billing registers and load profile. **No** SET. **No** ACTION |
| **Management** | 48 | HLS-GMAC (5), separate AK | authenticated + encrypted, both directions | Read/write configuration; `key_transfer`; `change_HLS_secret` |
| **Disconnect** | 64 | HLS-ECDSA (7) | authenticated + encrypted + **digitally signed**, both directions | ACTION on Disconnect Control only. Nothing else |
| **Third party** | via broker | — | `general-ciphering`, `agreed-key` C(1e,1s) | Read consumption data only, subject to consent record |

**Justification points a reviewer would want to see:**

- The public association exposes the invocation counter *because* counter
  resynchronisation must not itself require a valid counter.
- The reading association cannot SET or ACTION, so a compromised meter-reading
  contractor's handheld cannot alter configuration or operate the relay.
- The disconnect association uses a different mechanism *and* requires a
  signature, giving non-repudiation for a safety-critical operation.
- **[SPEC]** The signed requirement is expressible: [GB] Table 35 bit 4 is
  "digitally signed request" and bit 7 "digitally signed response".
- The third party never receives a global key — **[SPEC]** [GB] Table 21's NOTE
  makes `identified-key` unusable for them.

---

# CHAPTER 38 — GLOSSARY

Format per term: **one-line definition** · beginner · technical · DLMS meaning ·
example · common mistake.

**AARQ** — Application Association Request. · The "hello" that opens a session.
· ACSE APDU, `[APPLICATION 0]`, tag `0x60`. · Carries application context,
mechanism name, CtoS, client System Title, and the InitiateRequest. · `60 36 A1
09 06 07 60 85 74 05 08 01 03 …` · **[SPEC]** *It is not protected* — see [GB]
9.2.5.1 NOTE.

**AARE** — Application Association Response. · The meter's reply. · `[APPLICATION
1]`, tag `0x61`. · Carries result, diagnostic, StoC, server System Title. ·
`result = accepted` with diagnostic 14 during HLS. · Assuming `accepted` means
authentication is complete — under HLS it does not.

**ACSE** — Association Control Service Element. · The part of the stack that
opens and closes associations. · ISO/IEC 15954. · Produces AARQ/AARE/RLRQ/RLRE.
· — · Confusing ACSE APDUs with xDLMS APDUs; only the latter are ciphered.

**AAD** — Additional Authenticated Data. · Data that is authenticated but not
encrypted. · Input `A` to AES-GCM; feeds GHASH. · **[SPEC]** Contains `SC ‖ AK`
and, for authentication-only, the APDU too. · `30 D0D1…DEDF` · Omitting the
authentication key.

**AES** — Advanced Encryption Standard. · The block cipher everything is built
on. · FIPS PUB 197; 128-bit blocks; 128/192/256-bit keys. · **[SPEC]** DLMS uses
128 and 256. · — · Believing AES-256 has 256-bit blocks.

**AES-GCM** — AES in Galois/Counter Mode. · Encryption and authentication in one
pass. · NIST SP 800-38D. · The message protection algorithm in all three suites.
· `SC = 0x30` · Confusing it with GMAC (GMAC is GCM with empty plaintext).

**AES-WRAP** — AES key wrap, RFC 3394. · Encrypting a key with integrity. ·
Six-pass semiblock construction with a fixed `A6A6…` check value. · **[SPEC]**
Wraps keys for `key_transfer`. · 128-bit key → 24 octets. · Sizing the output at
the key length.

**AK** — Authentication Key. · The second secret that hardens the tag. ·
**[SPEC]** *"shall be part of the Additional Authenticated Data"* — [GB]
9.2.3.3.7.5. · GAK in the key hierarchy. · `D0D1…DEDF` · Using it as the GCM
block cipher key.

**CA** — Certification Authority. · The entity that vouches for public keys. ·
Signs certificates with its private key. · Root-CA is the trust anchor; Sub-CAs
issue end-entity certificates. · — · Assuming meters check CRLs — they do not.

**Ciphertext** — Encrypted data. · Unreadable output. · `C`, same length as `P`
in CTR mode. · The encrypted APDU inside a ciphered APDU. ·
`411312FF935A47566827C467BC` · Expecting it to be longer than the plaintext.

**COSEM** — Companion Specification for Energy Metering. · The object model. ·
Interface classes, attributes, methods, OBIS codes. · What the xDLMS services
act upon. · Clock, class 8, OBIS 0.0.1.0.0.255 · Using "DLMS" and "COSEM"
interchangeably; DLMS is the protocol, COSEM the data model.

**CtoS** — Challenge, client to server. · The client's random number. ·
**[SPEC]** 8–64 octets (32–64 for mechanism 7). · Sent in
`calling-authentication-value`. · `"K56iVagY"` · Treating it as a secret — it is
a nonce.

**Dedicated key** — A per-association unicast encryption key. · A session key. ·
**[SPEC]** Lifetime equals the AA's; unicast encryption only. · Carried in the
InitiateRequest, protected by the GUEK. · — · Believing it gives forward secrecy.

**DLMS** — Device Language Message Specification. · The application protocol. ·
IEC 62056-5-3 / DLMS UA 1000-2, the Green Book. · The xDLMS services and APDUs. ·
— · Swapping the Blue and Green Book IEC numbers.

**ECDH** — Elliptic Curve Diffie-Hellman. · Agreeing a key over a public
channel. · `Z = d_A · Q_B = d_B · Q_A`. · **[SPEC]** Three schemes: C(2e,0s),
C(1e,1s), C(0e,2s). · — · Confusing it with ECDSA; ECDH agrees keys, ECDSA
signs.

**ECDSA** — Elliptic Curve Digital Signature Algorithm. · Signing with a private
key. · FIPS PUB 186-4; P-256/SHA-256 or P-384/SHA-384. · **[SPEC]** Plain `R‖S`
encoding, 64 or 96 octets. · — · Using DER encoding; describing it as encryption.

**ECC** — Elliptic Curve Cryptography. · Public-key crypto on curves. · Security
from the ECDLP. · **[SPEC]** *"particularly suitable for embedded devices"* —
[GB] 9.2.3.4.1. · P-256, P-384 · Accepting curve parameters from the wire.

**GUEK (GEK)** — Global Unicast Encryption Key. · The main message key. · The
GCM block cipher key for unicast. · **[SPEC]** SC bit 6 = 0. · `000102…0E0F` ·
Calling it "GEK" in specification documents.

**GBEK** — Global Broadcast Encryption Key. · The key shared across a
population. · GCM block cipher key for broadcast. · **[SPEC]** SC bit 6 = 1. · —
· Treating broadcast content as confidential.

**GCM** — Galois/Counter Mode. · CTR encryption plus GHASH authentication. ·
NIST SP 800-38D. · The DLMS message protection mode. · — · See AES-GCM.

**GMAC** — GCM used for authentication only. · A MAC built from GCM. ·
**[SPEC]** *"If the GCM input is restricted to data that is not to be encrypted,
the resulting specialization of GCM, called GMAC"*. · HLS mechanism 5; `SC =
0x10`. · `T = GMAC(SC ‖ AK ‖ StoC)` · Putting the challenge in the plaintext
instead of the AAD.

**HLS** — High Level Security. · Mutual challenge-response authentication. ·
Four passes; ITU-T X.811 mutual authentication. · **[SPEC]** mechanism_id 2–7. ·
mechanism 5 = GMAC · Mis-numbering the mechanisms.

**HDLC** — High-level Data Link Control. · The framing layer. · Below the DLMS
security boundary. · Its FCS is a CRC, not security. · — · Believing the FCS
provides integrity against an adversary.

**IC** — Invocation Counter. · The per-message counter. · **[SPEC]** 32-bit
invocation field of the IV; separate for TX and RX. · Transmitted in the security
header. · `01234567` · Calling it "frame counter"; resetting it on boot.

**IV** — Initialization Vector. · The per-message nonce. · **[SPEC]** 96 bits =
System Title (8) ‖ IC (4). · Built from the **originator's** System Title. ·
`4D4D4D0000BC614E01234567` · Reusing one; wrong endianness on the IC.

**KEK** — Key Encrypting Key. · The key that protects other keys. · **[SPEC]**
*"In DLMS/COSEM this is the master key"* — [GB] 9.2.5.1. · Used with AES key
wrap. · — · Using it as a message key; transporting it in plaintext.

**LLS** — Low Level Security. · Password authentication. · **[SPEC]** ITU-T
X.811 unilateral authentication, class 0. · mechanism_id 1; password in the
AARQ. · `"ABCDEFGH"` · Believing message encryption protects the password — the
AARQ is not protected.

**MAC** — Message Authentication Code. · A keyed checksum. · Provides integrity
and authenticity. · **[SPEC]** DLMS uses GMAC. · The 12-octet tag. · Confusing
it with a CRC, or with HMAC.

**Nonce** — Number used once. · A value that must never repeat under one key. ·
Uniqueness, not unpredictability. · The IV. · — · Confusing the uniqueness
requirement with the unpredictability requirement for challenges.

**NVM** — Non-Volatile Memory. · Storage that survives power loss. · Flash,
EEPROM, FRAM. · Holds keys and counters. · — · Same wear domain for both.

**OBIS** — Object Identification System. · The naming scheme for metering data.
· Six-octet code. · Identifies COSEM object instances. · `0.0.1.0.0.255` = Clock
· — .

**OID** — Object Identifier. · A globally unique dotted-number name. · ASN.1
type, BER-encoded. · **[SPEC]** DLMS-UA prefix `2.16.756.5.8`. ·
`2.16.756.5.8.2.5` = HLS-GMAC · Getting the last arc wrong.

**PDU / APDU** — Protocol Data Unit / Application PDU. · A protocol message. ·
The unit of exchange. · xDLMS APDUs carry the services and are what gets
ciphered. · `C0 01 …` = get-request · Confusing ACSE and xDLMS APDUs.

**PKI** — Public Key Infrastructure. · The system that manages certificates. ·
Root-CA, Sub-CAs, end entities, CRLs. · **[SPEC]** [GB] 9.2.6.3, informative
architecture. · — · Assuming online revocation checking exists on meters.

**Plaintext** — Data before encryption. · Readable input. · `P` in AES-GCM. ·
The unprotected APDU. · `C0010000080000010000FF0200` · For GMAC, `P` is **empty**.

**SC** — Security Control byte. · One octet describing the protection applied. ·
**[SPEC]** bit 7 compression, bit 6 Key_Set, bit 5 E, bit 4 A, bits 3..0 suite. ·
First octet of the security header. · `0x30` · Wrong bit layout.

**Security Context** — Suite + policy + material. · The configuration governing
protection. · **[SPEC]** [GB] 9.2.2.3. · Managed by "Security setup" objects. ·
— · Confusing it with the application context.

**Security Policy** — The minimum protection required on every APDU in an AA. ·
The floor. · **[SPEC]** [GB] Table 34 bitmap. · `security_policy` attribute. ·
bit 2 = authenticated request · Confusing it with access rights — access rights
can require *more*.

**Security Suite** — The algorithm set and key sizes. · Which cryptography is
available. · **[SPEC]** [GB] Table 19: 0, 1, 2. · SC bits 3..0. · Suite 0 =
AES-GCM-128 · Saying "Suite 0 = AES-128" without decomposing what that means.

**SHA** — Secure Hash Algorithm. · One-way digest. · FIPS PUB 180-4. ·
**[SPEC]** SHA-256 (suite 1), SHA-384 (suite 2). · — · Using HMAC where a plain
hash is specified.

**SN / LN** — Short Name / Logical Name referencing. · Two ways to address COSEM
objects. · SN uses 16-bit names; LN uses OBIS codes. · Determines the
application context and the APDU tag set. · context_id 3 = LN with ciphering ·
Mixing tag sets between referencing modes.

**System Title** — The 8-octet device identity. · Who this device is,
cryptographically. · **[SPEC]** 3-octet FLAG manufacturer ID + 5 octets of
uniqueness. · The fixed field of the IV. · `4D4D4D0000BC614E` · Confusing it with
the Invocation Counter; duplicating it across devices.

**StoC** — Challenge, server to client. · The meter's random number. ·
**[SPEC]** 8–64 octets. · Sent in `responding-authentication-value`. ·
`"P6wRJ21F"` · Not checking `StoC != CtoS`.

**Tag** (authentication tag) — The GCM output that proves integrity. · The
cryptographic seal. · **[SPEC]** 96 bits in all suites, taken from the MSB end. ·
Last 12 octets of a ciphered APDU. · `7D825C3BE4A77C3FCC056B6B` · Using 16
octets; truncating from the wrong end. *(Distinct from an APDU tag, which is a
type identifier.)*

**Transaction ID** — A correlation field in `general-ciphering`. · Ties a
request to its response. · **[SPEC]** OCTET STRING; in C(0e,2s) it supplies
`Nonce_U`. · First field of `general-ciphering`. · `0102030405060708` · Omitting
its length octet from the AAD.

**X.509** — The certificate standard. · The format that binds a key to an
identity. · **[SPEC]** v3, per RFC 5280 and NSA Suite B. · Carries the public
key, curve OID, KeyUsage, and the System Title in `SubjectAltName`. · — ·
Ignoring critical extensions; skipping the `hwSerialNum` check.

---

## Volume 6 summary — and the manual's last word

The twenty failure modes in Chapter 31 and the eighteen attacks in Chapter 32
have one pattern in common: **almost none of them are weaknesses in DLMS/COSEM
itself.** The specification is sound. AES-GCM is sound. The invocation counter
mechanism is sound.

What fails is implementation — a counter reset on boot, a key in application
flash, a state machine that permits one service too many, a tag compared with
`memcmp`. That is why Volumes 5 and 6 are longer than the protocol chapters
deserve on page count alone, and it is why the test vectors in Volume 0 matter
more than any amount of reading.

If you take three things from this manual:

1. **Reproduce [GB] Table 40 and Table 43 in your firmware, as a power-on
   self-test.** A stack that cannot is not finished.
2. **Never let the invocation counter go backwards.** On any doubt, jump
   forward. On unrecoverable doubt, fail closed.
3. **Authentication, authorization, and message security are three separate
   things.** Getting all three right is the job; getting one right and calling
   it secure is the failure mode.

---

*End of Volume 6. End of the manual.*

---

← **Previous:** [Volume 5 — Embedded Firmware Implementation](VOL-5-Embedded-Firmware-Implementation.md)

[Back to the index](00-INDEX.md)
