"""
wpa_crypto.py — WPA / WPA2 Cryptographic Primitives (Educational)
==================================================================
WPA (Wi-Fi Protected Access) uses the 4-Way Handshake to derive
per-session keys from a shared password.

Key Hierarchy:
  Password + SSID  →  PMK  (via PBKDF2-SHA1, 4096 iterations)
  PMK + nonces + MACs  →  PTK  (via PRF-512)
  PTK[0:16]  →  KCK  (Key Confirmation Key — used for MIC)
  PTK[16:32] →  KEK  (Key Encryption Key  — used to encrypt GTK)
  PTK[32:48] →  TK   (Temporal Key        — actual data encryption)

MIC computation:
  WPA  (TKIP):  HMAC-MD5 (KCK, EAPOL_frame_with_MIC_zeroed)
  WPA2 (CCMP):  HMAC-SHA1(KCK, EAPOL_frame_with_MIC_zeroed)[0:16]

Why this is the only attack vector:
  • AES-CCMP (WPA2) has no known structural weakness
  • The only attack is guessing the password → PMK → PTK → verify MIC
  • PBKDF2 with 4096 rounds deliberately slows brute-force to ~300-2000 PMKs/s on CPU
"""

import hmac
import hashlib
import struct
import os


# ─── PMK: Pairwise Master Key ───────────────────────────────────────────────

def compute_pmk(password: str, ssid: str) -> bytes:
    """
    PMK = PBKDF2-HMAC-SHA1(password, ssid, iterations=4096, dklen=32)

    This is the expensive step — 4096 SHA1 rounds per password candidate.
    On a modern CPU in Python: ~300–800 attempts/second.
    """
    return hashlib.pbkdf2_hmac(
        'sha1',
        password.encode('utf-8'),
        ssid.encode('utf-8'),
        4096,
        dklen=32
    )


# ─── PTK: Pairwise Transient Key ─────────────────────────────────────────────

def _prf_sha1(key: bytes, label: str, data: bytes, length: int) -> bytes:
    """
    PRF (Pseudo-Random Function) based on HMAC-SHA1.
    Defined in IEEE 802.11i section 8.5.1.1.

    Generates `length` bytes of pseudo-random output.
    """
    result = b''
    i = 0
    while len(result) < length:
        msg = label.encode('ascii') + b'\x00' + data + bytes([i])
        result += hmac.new(key, msg, hashlib.sha1).digest()
        i += 1
    return result[:length]


def compute_ptk(
    pmk:    bytes,
    aa:     bytes,   # Authenticator (AP) MAC address — 6 bytes
    sa:     bytes,   # Supplicant (client) MAC address — 6 bytes
    anonce: bytes,   # AP nonce — 32 bytes
    snonce: bytes,   # Client nonce — 32 bytes
) -> bytes:
    """
    PTK = PRF-512(PMK, "Pairwise key expansion", Min(AA,SA)||Max(AA,SA)||Min(ANonce,SNonce)||Max(ANonce,SNonce))

    Returns 64 bytes split as:
      [0:16]  KCK — Key Confirmation Key
      [16:32] KEK — Key Encryption Key
      [32:48] TK  — Temporal Key
      [48:64] (optional second TK for TKIP)
    """
    assert len(aa)     == 6,  "AA must be 6 bytes (MAC address)"
    assert len(sa)     == 6,  "SA must be 6 bytes (MAC address)"
    assert len(anonce) == 32, "ANonce must be 32 bytes"
    assert len(snonce) == 32, "SNonce must be 32 bytes"

    data = (
        min(aa, sa) + max(aa, sa) +
        min(anonce, snonce) + max(anonce, snonce)
    )
    return _prf_sha1(pmk, "Pairwise key expansion", data, 64)


def ptk_split(ptk: bytes) -> tuple[bytes, bytes, bytes]:
    """Split PTK into (KCK, KEK, TK)."""
    return ptk[0:16], ptk[16:32], ptk[32:48]


# ─── MIC: Message Integrity Code ─────────────────────────────────────────────

def compute_mic_wpa(kck: bytes, eapol_frame: bytes) -> bytes:
    """MIC for WPA/TKIP: HMAC-MD5(KCK, frame_with_MIC_zeroed)."""
    return hmac.new(kck, eapol_frame, hashlib.md5).digest()


def compute_mic_wpa2(kck: bytes, eapol_frame: bytes) -> bytes:
    """MIC for WPA2/CCMP: HMAC-SHA1(KCK, frame_with_MIC_zeroed)[0:16]."""
    return hmac.new(kck, eapol_frame, hashlib.sha1).digest()[:16]


def zero_mic_in_eapol(eapol_frame: bytes) -> bytes:
    """
    Return a copy of the EAPOL key frame with the MIC field zeroed.
    MIC field is bytes [81:97] in the EAPOL key frame body.

    EAPOL Key Frame layout (simplified):
      0  Version (1)
      1  Type    (1)   — 0x03 = EAPOL-Key
      2  Length  (2)
      4  Descriptor type (1)
      5  Key Info (2)
      7  Key Length (2)
      9  Replay Counter (8)
     17  Nonce (32)
     49  EAPOL-Key IV (16)
     65  RSC (8)
     73  Reserved (8)
     81  MIC (16)   ← zero this
     97  Key Data Length (2)
     99  Key Data (variable)
    """
    frame = bytearray(eapol_frame)
    frame[81:97] = b'\x00' * 16
    return bytes(frame)


# ─── High-level verify function ──────────────────────────────────────────────

def verify_password(
    password:    str,
    ssid:        str,
    aa:          bytes,
    sa:          bytes,
    anonce:      bytes,
    snonce:      bytes,
    eapol_frame: bytes,   # Message 2 of 4-way handshake (MIC field zeroed)
    mic:         bytes,   # Captured MIC from Message 2
    protocol:    str = 'WPA2'
) -> bool:
    """
    Full password verification pipeline:
      password → PMK → PTK → KCK → MIC → compare

    This is the core of every WPA/WPA2 password cracker.
    """
    pmk       = compute_pmk(password, ssid)
    ptk       = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck, _, _ = ptk_split(ptk)

    if protocol == 'WPA2':
        computed_mic = compute_mic_wpa2(kck, eapol_frame)
    else:
        computed_mic = compute_mic_wpa(kck, eapol_frame)

    return computed_mic == mic


# ─── Self-test ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import time

    password = 'TestPassword123'
    ssid     = 'HomeNetwork'
    aa       = bytes.fromhex('aabbccddeeff')
    sa       = bytes.fromhex('112233445566')
    anonce   = os.urandom(32)
    snonce   = os.urandom(32)

    t0  = time.perf_counter()
    pmk = compute_pmk(password, ssid)
    t1  = time.perf_counter()
    ptk = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck, kek, tk = ptk_split(ptk)

    print(f"PMK:    {pmk.hex()}")
    print(f"KCK:    {kck.hex()}")
    print(f"PMK computation time: {(t1-t0)*1000:.1f} ms")
    print(f"Estimated speed: {1/(t1-t0):.0f} passwords/sec (single-threaded Python)")
