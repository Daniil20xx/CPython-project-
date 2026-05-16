"""
wep_crack.py — WEP Brute-Force Cracker (Educational)
=====================================================
Attacks a WEP capture file (.wep) produced by wep_gen.py.

Attack modes:
  1. Wordlist  — try keys from a file (fastest, realistic)
  2. Numeric   — try all N-digit numeric keys (10^N combinations)
  3. Alphanum  — try short alphanumeric keys (demo, very limited keyspace)

How it works:
  For each candidate key, attempt to decrypt the first captured frame.
  If the RC4 decryption produces a valid CRC-32 ICV → key is correct.
  Probability of false positive ≈ 1/2^32 per attempt.

Usage:
  python wep_crack.py --mode wordlist --wordlist data/wordlists/passwords.txt
  python wep_crack.py --mode numeric --digits 4
  python wep_crack.py --capture data/captures/test_wep.wep --mode wordlist
"""

import os
import sys
import time
import string
import itertools
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.wep.wep_crypto import wep_decrypt
from src.wep.wep_gen import read_capture, generate_capture, key_from_passphrase

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False


# ─── Colour helpers ─────────────────────────────────────────────────────────

def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"


# ─── Core cracker ───────────────────────────────────────────────────────────

def try_key(frames: list[bytes], candidate: bytes) -> bool:
    """
    Test a single candidate key against multiple frames.
    Uses the first frame; optionally verify with a second for confidence.
    """
    ok, _ = wep_decrypt(candidate, frames[0])
    if ok and len(frames) > 1:
        ok2, _ = wep_decrypt(candidate, frames[1])
        return ok2
    return ok


def crack_wordlist(frames: list[bytes], wordlist_path: str, key_len: int) -> dict:
    """Dictionary attack: try each word from the wordlist as a WEP key."""
    if not os.path.exists(wordlist_path):
        print(red(f"[!] Wordlist not found: {wordlist_path}"))
        return {}

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        words = [w.strip() for w in f if w.strip()]

    print(f"[*] Wordlist attack: {len(words)} candidates, key_len={key_len} bytes")
    print(f"[*] Frame count: {len(frames)}")
    print("-" * 50)

    start    = time.perf_counter()
    count    = 0
    found    = None

    iter_words = tqdm(words, unit='key', desc='Trying') if HAS_TQDM else words

    for word in iter_words:
        # Pad or truncate to match expected key length
        encoded = word.encode('latin-1', errors='replace')
        if len(encoded) < key_len:
            encoded = encoded.ljust(key_len, b'\x00')
        encoded = encoded[:key_len]

        count += 1
        if try_key(frames, encoded):
            found = encoded
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed if elapsed > 0 else 0

    return _report(found, count, elapsed, speed, 'wordlist')


def crack_numeric(frames: list[bytes], key_len: int, max_digits: int = 5) -> dict:
    """
    Brute-force numeric keys.
    Keyspace: 10^max_digits for each digit position.
    """
    total = 10 ** max_digits
    print(f"[*] Numeric brute-force: {total:,} combinations ({max_digits} digits), "
          f"key_len={key_len} bytes")
    print("-" * 50)

    start   = time.perf_counter()
    count   = 0
    found   = None

    digit_chars = string.digits.encode()

    for combo in itertools.product(digit_chars, repeat=max_digits):
        # combo is a tuple of ints (because iterating bytes gives ints)
        candidate = bytes(combo).ljust(key_len, b'\x00')[:key_len]
        count += 1

        if count % 50_000 == 0:
            elapsed = time.perf_counter() - start
            speed   = count / elapsed
            print(f"\r[*] Tried {count:>8,} | Speed: {speed:>8,.0f} keys/s", end='')

        if try_key(frames, candidate):
            found = candidate
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed if elapsed > 0 else 0
    print()  # newline after progress
    return _report(found, count, elapsed, speed, 'numeric')


def crack_alphanum(frames: list[bytes], key_len: int, length: int = 3) -> dict:
    """
    Brute-force alphanumeric keys of fixed `length`.
    WARNING: 62^5 ≈ 916M — only use length ≤ 4 for demo.
    """
    charset = (string.ascii_lowercase + string.digits).encode()
    total   = len(charset) ** length
    print(f"[*] Alphanumeric brute-force: charset={len(charset)}, "
          f"length={length}, total={total:,}")
    print("-" * 50)

    start   = time.perf_counter()
    count   = 0
    found   = None

    for combo in itertools.product(charset, repeat=length):
        candidate = bytes(combo).ljust(key_len, b'\x00')[:key_len]
        count += 1
        if count % 100_000 == 0:
            elapsed = time.perf_counter() - start
            print(f"\r[*] {count:>8,}/{total:,} | {count/elapsed:>8,.0f} keys/s", end='')

        if try_key(frames, candidate):
            found = candidate
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed if elapsed > 0 else 0
    print()
    return _report(found, count, elapsed, speed, 'alphanum')


# ─── Report helper ───────────────────────────────────────────────────────────

def _report(found: bytes | None, count: int, elapsed: float, speed: float, mode: str) -> dict:
    print()
    print("=" * 50)
    if found:
        print(green(f"  [+] KEY FOUND!"))
        print(f"      Hex:    {found.hex()}")
        try:
            print(f"      ASCII:  {found.decode('latin-1')}")
        except Exception:
            pass
    else:
        print(red(f"  [-] Key not found in this attempt."))
    print(f"  Attempted:  {count:,} keys")
    print(f"  Time:       {elapsed:.3f}s")
    print(f"  Speed:      {speed:,.0f} keys/s")
    print(f"  Mode:       {mode}")
    print("=" * 50)

    return {
        'found':    found,
        'count':    count,
        'elapsed':  elapsed,
        'speed':    speed,
        'mode':     mode,
    }


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Educational WEP Brute-Force Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate test capture then crack it
  python src/wep/wep_gen.py --key hello --frames 50
  python src/wep/wep_crack.py --mode wordlist --wordlist data/wordlists/passwords.txt

  # Numeric brute force (try 4-digit numeric keys)
  python src/wep/wep_crack.py --mode numeric --digits 4

  # Alphanumeric brute force (3-char keys only — demo)
  python src/wep/wep_crack.py --mode alphanum --alength 3
        """
    )
    parser.add_argument('--capture',  default='data/captures/test_wep.wep',
                        help='Path to .wep capture file')
    parser.add_argument('--mode',     choices=['wordlist', 'numeric', 'alphanum'],
                        default='wordlist')
    parser.add_argument('--wordlist', default='data/wordlists/passwords.txt')
    parser.add_argument('--digits',   type=int, default=5,
                        help='Number of digits for numeric mode')
    parser.add_argument('--alength',  type=int, default=3,
                        help='Key length for alphanum mode')
    parser.add_argument('--gen-key',  default=None,
                        help='Auto-generate a capture with this key (5-char ASCII)')
    args = parser.parse_args()

    # Auto-generate capture if requested
    if args.gen_key:
        wep_key = key_from_passphrase(args.gen_key)
        generate_capture(wep_key, num_frames=50, output_path=args.capture)
        print()

    # Load capture
    if not os.path.exists(args.capture):
        print(red(f"[!] Capture file not found: {args.capture}"))
        print(yellow(f"    Tip: run wep_gen.py first, or use --gen-key <5-char-key>"))
        sys.exit(1)

    key_len, frames = read_capture(args.capture)
    print(bold(f"\n{'='*50}"))
    print(bold(f"  WEP Cracker — {len(frames)} frames, key={key_len*8}-bit"))
    print(bold(f"{'='*50}\n"))

    if args.mode == 'wordlist':
        crack_wordlist(frames, args.wordlist, key_len)
    elif args.mode == 'numeric':
        crack_numeric(frames, key_len, args.digits)
    elif args.mode == 'alphanum':
        crack_alphanum(frames, key_len, args.alength)


if __name__ == '__main__':
    main()
