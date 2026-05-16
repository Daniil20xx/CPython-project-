"""
wep_crypto.py — WEP Cryptographic Primitives (Educational)
===========================================================
WEP (Wired Equivalent Privacy) uses:
  • RC4 stream cipher for confidentiality
  • CRC-32 as ICV (Integrity Check Value) — NOT a MAC, easily forgeable

Key structure: IV (3 bytes) || WEP_KEY (5 or 13 bytes)
Frame layout:  IV (3 B) | KeyID (1 B) | RC4(IV||Key, plaintext||ICV)

Why WEP is broken:
  1. Short 24-bit IV → repeats after ~16M frames (birthday paradox: ~5000 frames)
  2. RC4 weak keys (IVs of form (A+3, 255, X)) leak key bytes (FMS/KoreK attacks)
  3. CRC-32 is linear → bit-flipping attacks possible
"""

import struct
import zlib
import os


# ─── RC4 Stream Cipher ──────────────────────────────────────────────────────

def rc4_ksa(key: bytes) -> list[int]:
    """Key Scheduling Algorithm: initialises the permutation S."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list[int], length: int) -> bytes:
    """Pseudo-Random Generation Algorithm: produces keystream bytes."""
    i = j = 0
    keystream = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        keystream.append(S[(S[i] + S[j]) % 256])
    return bytes(keystream)


def rc4(key: bytes, data: bytes) -> bytes:
    """Full RC4: KSA → PRGA → XOR."""
    S = rc4_ksa(key)
    ks = rc4_prga(S, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ─── ICV (Integrity Check Value) ────────────────────────────────────────────

def compute_icv(plaintext: bytes) -> bytes:
    """CRC-32 of plaintext, little-endian 4 bytes."""
    crc = zlib.crc32(plaintext) & 0xFFFF_FFFF
    return struct.pack('<I', crc)


def verify_icv(plaintext: bytes, received_icv: bytes) -> bool:
    return compute_icv(plaintext) == received_icv


# ─── WEP Frame Encode / Decode ───────────────────────────────────────────────

def wep_encrypt(iv: bytes, wep_key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt one WEP MPDU payload.

    Returns: IV (3 B) | KeyID=0 (1 B) | ciphertext
    ciphertext = RC4(IV||key, plaintext||ICV)
    """
    assert len(iv) == 3, "IV must be exactly 3 bytes"
    rc4_seed = iv + wep_key
    icv = compute_icv(plaintext)
    ciphertext = rc4(rc4_seed, plaintext + icv)
    return iv + b'\x00' + ciphertext          # KeyID byte = 0


def wep_decrypt(wep_key: bytes, frame: bytes) -> tuple[bool, bytes]:
    """
    Decrypt WEP MPDU payload.

    Args:
        wep_key: candidate WEP key (5 or 13 bytes)
        frame:   raw bytes starting from IV field

    Returns:
        (valid: bool, plaintext: bytes)
        valid=True means ICV matched → correct key (with very high probability)
    """
    if len(frame) < 8:          # 3 IV + 1 KeyID + 4 ICV minimum
        return False, b''
    iv         = frame[:3]
    # frame[3] is KeyID — ignored in single-key scenario
    ciphertext = frame[4:]
    rc4_seed   = iv + wep_key
    decrypted  = rc4(rc4_seed, ciphertext)
    plaintext  = decrypted[:-4]
    recv_icv   = decrypted[-4:]
    ok = verify_icv(plaintext, recv_icv)
    return ok, plaintext


# ─── Helpers ────────────────────────────────────────────────────────────────

def random_iv() -> bytes:
    """Generate a random 3-byte IV (as a real AP would)."""
    return os.urandom(3)


def key_from_passphrase(passphrase: str) -> bytes:
    """
    Simple ASCII passphrase → bytes.
    WEP-40  = 5 ASCII chars (40 bits)
    WEP-104 = 13 ASCII chars (104 bits)
    """
    raw = passphrase.encode('latin-1')
    if len(raw) not in (5, 13):
        raise ValueError("WEP key must be 5 (40-bit) or 13 (104-bit) ASCII chars")
    return raw


if __name__ == '__main__':
    # Quick self-test
    key  = b'hello'                    # 40-bit WEP key
    iv   = bytes([0xAB, 0xCD, 0xEF])
    msg  = b'Secret WiFi payload!'

    frame = wep_encrypt(iv, key, msg)
    ok, dec = wep_decrypt(key, frame)
    print(f"Encrypted frame ({len(frame)} bytes): {frame.hex()}")
    print(f"Decryption OK: {ok}, plaintext: {dec}")

    # Wrong key test
    ok2, _ = wep_decrypt(b'wrong', frame)
    print(f"Wrong key check (should be False): {ok2}")
