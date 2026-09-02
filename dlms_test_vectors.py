"""Verify Green Book 8th Ed. official test vectors (Table 40, Table 43)."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

H = bytes.fromhex

EK = H("000102030405060708090A0B0C0D0E0F")
AK = H("D0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF")

def gcm(key, iv, aad, pt, taglen=12):
    enc = Cipher(algorithms.AES(key), modes.GCM(iv, min_tag_length=taglen)).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(pt) + enc.finalize()
    return ct, enc.tag[:taglen]

print("=" * 72)
print("TABLE 40 - glo-get-request  (Sys-T=4D4D4D0000BC614E, IC=01234567)")
print("=" * 72)
IV = H("4D4D4D0000BC614E") + H("01234567")
APDU = H("C0010000080000010000FF0200")
print("IV  =", IV.hex().upper())

# --- Authentication only, SC = 0x10
SC = H("10")
A = SC + AK + APDU
ct, T = gcm(EK, IV, A, b"")
print("\n[SC=0x10 authentication only]")
print("  AAD = SC||AK||APDU =", A.hex().upper())
print("  computed T =", T.hex().upper(), " expected 06725D910F9221D263877516",
      "-> MATCH" if T.hex().upper() == "06725D910F9221D263877516" else "-> MISMATCH")
full = H("C8") + bytes([0x1E]) + SC + H("01234567") + APDU + T
print("  APDU =", full.hex().upper())

# --- Encryption only, SC = 0x20
SC = H("20")
ct, T = gcm(EK, IV, b"", APDU)
print("\n[SC=0x20 encryption only]")
print("  computed C =", ct.hex().upper(), " expected 411312FF935A47566827C467BC",
      "-> MATCH" if ct.hex().upper() == "411312FF935A47566827C467BC" else "-> MISMATCH")
full = H("C8") + bytes([0x12]) + SC + H("01234567") + ct
print("  APDU =", full.hex().upper())

# --- Authenticated encryption, SC = 0x30
SC = H("30")
A = SC + AK
ct, T = gcm(EK, IV, A, APDU)
print("\n[SC=0x30 authenticated encryption]")
print("  AAD = SC||AK =", A.hex().upper())
print("  computed C =", ct.hex().upper(),
      "-> MATCH" if ct.hex().upper() == "411312FF935A47566827C467BC" else "-> MISMATCH")
print("  computed T =", T.hex().upper(), " expected 7D825C3BE4A77C3FCC056B6B",
      "-> MATCH" if T.hex().upper() == "7D825C3BE4A77C3FCC056B6B" else "-> MISMATCH")
full = H("C8") + bytes([0x1E]) + SC + H("01234567") + ct + T
print("  APDU =", full.hex().upper())

print()
print("=" * 72)
print("TABLE 43 - HLS mechanism 5 (GMAC)")
print("=" * 72)
SC = H("10")
CtoS = b"K56iVagY"
StoC = b"P6wRJ21F"
print("CtoS =", CtoS.hex().upper(), "StoC =", StoC.hex().upper())

# Pass 3: client processes StoC. Client Sys-T + client IC.
IV_C = H("4D4D4D0000000001") + H("00000001")
A = SC + AK + StoC
_, T = gcm(EK, IV_C, A, b"")
print("\n[Pass 3: f(StoC) computed by CLIENT]")
print("  IV  =", IV_C.hex().upper())
print("  AAD = SC||AK||StoC =", A.hex().upper())
print("  T   =", T.hex().upper(), " expected 1A52FE7DD3E72748973C1E28",
      "-> MATCH" if T.hex().upper() == "1A52FE7DD3E72748973C1E28" else "-> MISMATCH")
print("  f(StoC) = SC||IC||T =", (SC + H("00000001") + T).hex().upper())

# Pass 4: server processes CtoS. Server Sys-T + server IC.
IV_S = H("4D4D4D0000BC614E") + H("01234567")
A = SC + AK + CtoS
_, T = gcm(EK, IV_S, A, b"")
print("\n[Pass 4: f(CtoS) computed by SERVER]")
print("  IV  =", IV_S.hex().upper())
print("  AAD = SC||AK||CtoS =", A.hex().upper())
print("  T   =", T.hex().upper(), " expected FE1466AFB3DBCD4F9389E2B7",
      "-> MATCH" if T.hex().upper() == "FE1466AFB3DBCD4F9389E2B7" else "-> MISMATCH")
print("  f(CtoS) = SC||IC||T =", (SC + H("01234567") + T).hex().upper())
