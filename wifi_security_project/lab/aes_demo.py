"""
aes_demo.py — AES Internals Demonstration (Educational Lab)
============================================================
Pure-Python walkthrough of AES-128 encryption.
Shows each of the 4 core operations step-by-step.

AES (Advanced Encryption Standard):
  Block size: 128 bits (16 bytes) — fixed
  Key sizes:  128 / 192 / 256 bits (10 / 12 / 14 rounds)

WPA2 uses AES-128 in CCMP mode (Counter with CBC-MAC Protocol).

The 4 operations per round:
  1. SubBytes   — non-linear S-box substitution (confusion)
  2. ShiftRows  — byte permutation across rows (diffusion)
  3. MixColumns — linear mixing within columns (diffusion)
  4. AddRoundKey — XOR with round key (key mixing)

Why AES is not structurally broken:
  • No known algebraic attack better than brute force for ≥128-bit keys
  • Best known attack on AES-128: related-key attack, impractical (2^126.1)
  • WPA2 is broken via the PASSWORD, not via AES itself

Usage:
  python lab/aes_demo.py
  python lab/aes_demo.py --verbose  # shows each round
  python lab/aes_demo.py --test     # runs self-test against NIST vectors
"""

import os
import sys
import argparse


# ─── AES S-Box (pre-computed) ────────────────────────────────────────────────

SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Round constants
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


# ─── GF(2^8) arithmetic ──────────────────────────────────────────────────────

def _xtime(a: int) -> int:
    """Multiply by 2 in GF(2^8) with irreducible polynomial x^8+x^4+x^3+x+1."""
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF

def _gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1
    return result


# ─── State helpers ───────────────────────────────────────────────────────────

def bytes_to_state(block: bytes) -> list[list[int]]:
    """Convert 16-byte block to 4×4 state matrix (column-major)."""
    return [[block[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(state: list[list[int]]) -> bytes:
    """Convert 4×4 state matrix back to bytes."""
    return bytes(state[r][c] for c in range(4) for r in range(4))

def print_state(state: list[list[int]], label: str = '') -> None:
    if label:
        print(f"  {label}:")
    for row in state:
        print('    ' + ' '.join(f'{b:02x}' for b in row))


# ─── The 4 AES Round Operations ─────────────────────────────────────────────

def sub_bytes(state: list[list[int]]) -> list[list[int]]:
    """
    SubBytes: replace each byte with its S-box value.
    This provides non-linearity (confusion) — resistant to linear attacks.
    The S-box is constructed from the multiplicative inverse in GF(2^8).
    """
    return [[SBOX[b] for b in row] for row in state]


def shift_rows(state: list[list[int]]) -> list[list[int]]:
    """
    ShiftRows: cyclically shift row i left by i positions.
    Row 0: no shift
    Row 1: shift left 1
    Row 2: shift left 2
    Row 3: shift left 3
    Provides inter-column diffusion.
    """
    return [state[r][r:] + state[r][:r] for r in range(4)]


def mix_columns(state: list[list[int]]) -> list[list[int]]:
    """
    MixColumns: treat each column as a GF(2^8) polynomial and multiply
    by a fixed matrix. Provides diffusion within each column.
    MDS matrix: [2,3,1,1; 1,2,3,1; 1,1,2,3; 3,1,1,2]
    """
    result = [[0]*4 for _ in range(4)]
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        result[0][c] = _gmul(2,col[0])^_gmul(3,col[1])^col[2]^col[3]
        result[1][c] = col[0]^_gmul(2,col[1])^_gmul(3,col[2])^col[3]
        result[2][c] = col[0]^col[1]^_gmul(2,col[2])^_gmul(3,col[3])
        result[3][c] = _gmul(3,col[0])^col[1]^col[2]^_gmul(2,col[3])
    return result


def add_round_key(state: list[list[int]], round_key: list[list[int]]) -> list[list[int]]:
    """
    AddRoundKey: XOR state with the round key.
    This is the only operation that introduces key material.
    XOR is its own inverse: applying twice gives back the original.
    """
    return [[state[r][c] ^ round_key[r][c] for c in range(4)] for r in range(4)]


# ─── Key Expansion ───────────────────────────────────────────────────────────

def key_expansion(key: bytes) -> list[list[list[int]]]:
    """
    AES-128 Key Schedule: expand 16-byte key into 11 round keys.
    Each round key is a 4×4 matrix.
    Uses: SubBytes on rotated word, XOR with RCON.
    """
    assert len(key) == 16, "AES-128 requires 16-byte key"
    w = [list(key[4*i:4*i+4]) for i in range(4)]

    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i//4 - 1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])

    # Group into 11 round keys, each as 4×4 matrix
    round_keys = []
    for rnd in range(11):
        rk = [[w[rnd*4 + c][r] for c in range(4)] for r in range(4)]
        round_keys.append(rk)
    return round_keys


# ─── AES-128 Encrypt ─────────────────────────────────────────────────────────

def aes_encrypt_block(plaintext: bytes, key: bytes, verbose: bool = False) -> bytes:
    """
    Encrypt a single 16-byte block with AES-128.

    Args:
        plaintext: 16-byte input block
        key:       16-byte key
        verbose:   Print state after each operation

    Returns:
        16-byte ciphertext block
    """
    assert len(plaintext) == 16 and len(key) == 16

    round_keys = key_expansion(key)
    state      = bytes_to_state(plaintext)

    if verbose:
        print(f"\n{'─'*40}")
        print("  AES-128 Encryption Trace")
        print(f"{'─'*40}")
        print(f"  Plaintext: {plaintext.hex()}")
        print(f"  Key:       {key.hex()}")
        print_state(state, "Initial state")

    # Initial round key addition
    state = add_round_key(state, round_keys[0])
    if verbose:
        print_state(state, "After AddRoundKey[0]")

    # Main rounds (1–9)
    for rnd in range(1, 10):
        state = sub_bytes(state)
        if verbose: print_state(state, f"Round {rnd} — SubBytes")
        state = shift_rows(state)
        if verbose: print_state(state, f"Round {rnd} — ShiftRows")
        state = mix_columns(state)
        if verbose: print_state(state, f"Round {rnd} — MixColumns")
        state = add_round_key(state, round_keys[rnd])
        if verbose: print_state(state, f"Round {rnd} — AddRoundKey")

    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])

    ciphertext = state_to_bytes(state)
    if verbose:
        print(f"\n  Ciphertext: {ciphertext.hex()}")
        print(f"{'─'*40}\n")
    return ciphertext


# ─── NIST Test Vectors ────────────────────────────────────────────────────────

NIST_VECTORS = [
    # (key_hex, plaintext_hex, ciphertext_hex)
    (
        '000102030405060708090a0b0c0d0e0f',
        '00112233445566778899aabbccddeeff',
        '69c4e0d86a7b0430d8cdb78070b4c55a'   # verified against PyCryptodome
    ),
    (
        '2b7e151628aed2a6abf7158809cf4f3c',
        '3243f6a8885a308d313198a2e0370734',
        '3925841d02dc09fbdc118597196a0b32'
    ),
]

def run_tests() -> None:
    print("\n[*] Running NIST AES-128 test vectors...")
    all_ok = True
    for key_hex, pt_hex, expected_hex in NIST_VECTORS:
        key       = bytes.fromhex(key_hex)
        plaintext = bytes.fromhex(pt_hex)
        expected  = bytes.fromhex(expected_hex)
        result    = aes_encrypt_block(plaintext, key)
        ok        = result == expected
        status    = '\033[92mPASS\033[0m' if ok else '\033[91mFAIL\033[0m'
        print(f"  [{status}] key={key_hex[:8]}... pt={pt_hex[:8]}...")
        if not ok:
            print(f"         Expected: {expected_hex}")
            print(f"         Got:      {result.hex()}")
            all_ok = False

    if all_ok:
        print("\033[92m  All test vectors passed!\033[0m\n")
    else:
        print("\033[91m  Some tests FAILED — check implementation.\033[0m\n")


# ─── Conceptual AES-CCMP Demonstration ───────────────────────────────────────

def demonstrate_ccmp_concept() -> None:
    """
    Show conceptually how WPA2-CCMP uses AES:
    CCMP = Counter Mode Encryption + CBC-MAC Authentication
    """
    print("\n" + "="*55)
    print("  WPA2-CCMP: How AES Is Used")
    print("="*55)
    print("""
  CCMP (Counter with CBC-MAC Protocol) uses AES-128 in two modes:

  1. CBC-MAC (Authentication):
     ─ Chains AES blocks to produce an 8-byte MIC
     ─ Prevents tampering with the 802.11 frame
     ─ Key = TK (Temporal Key from 4-Way Handshake)

  2. Counter Mode (Encryption):
     ─ Generates keystream: AES(TK, Nonce || Counter)
     ─ XOR keystream with plaintext (like a stream cipher)
     ─ Counter increments for each 16-byte block

  Key flow (from password to data):
  ┌─────────────────────────────────────────────────────┐
  │  Password + SSID                                    │
  │       ↓ PBKDF2-SHA1 (4096 iterations)              │
  │  PMK (32 bytes)                                     │
  │       ↓ PRF-512 (+ Nonces + MACs)                  │
  │  PTK (64 bytes)                                     │
  │       ├─ KCK[0:16]  → MIC verification (attack!)   │
  │       ├─ KEK[16:32] → GTK encryption               │
  │       └─ TK [32:48] → AES-CCMP data encryption     │
  └─────────────────────────────────────────────────────┘

  Attack target:
    ❌ AES itself — no practical attack known
    ✅ The PASSWORD → PMK step (PBKDF2 brute force)
    ✅ Verify by checking if computed MIC matches captured MIC
""")


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='AES-128 Educational Demo')
    parser.add_argument('--verbose', action='store_true',
                        help='Show detailed round-by-round trace')
    parser.add_argument('--test',    action='store_true',
                        help='Run NIST test vectors')
    parser.add_argument('--plaintext', default='Hello, WPA2 World!',
                        help='Plaintext to encrypt (16 bytes, padded/truncated)')
    parser.add_argument('--key',     default=None,
                        help='16-byte hex key (random if not specified)')
    args = parser.parse_args()

    print("\n" + "="*55)
    print("  AES-128 Educational Demonstration")
    print("="*55)

    if args.test:
        run_tests()

    demonstrate_ccmp_concept()

    # Demo encryption
    key       = bytes.fromhex(args.key) if args.key else os.urandom(16)
    plaintext = args.plaintext.encode('utf-8')[:16].ljust(16, b'\x00')

    print("─"*55)
    print("  Single-Block Encryption Demo")
    print("─"*55)
    ciphertext = aes_encrypt_block(plaintext, key, verbose=args.verbose)
    print(f"  Plaintext:  {plaintext.hex()}  ← {plaintext!r}")
    print(f"  Key:        {key.hex()}")
    print(f"  Ciphertext: {ciphertext.hex()}")
    print(f"\n  Observation: 1 bit change in plaintext → ~50% bits change")
    print(f"  (Avalanche effect — run multiple times to see)")
    print()

    if not args.verbose:
        print("  Tip: run with --verbose to see all 10 rounds")


if __name__ == '__main__':
    main()
