"""
benchmark.py — WEP / WPA / WPA2 Attack Benchmarks (Educational)
================================================================
Measures and compares:
  1. WEP brute-force speed     (RC4 + CRC32 verification)
  2. WPA  dictionary speed     (HMAC-MD5 MIC verification)
  3. WPA2 dictionary speed     (PBKDF2 bottleneck)

Key insight:
  WEP : ~100,000–1,000,000 keys/s  → completely broken
  WPA : ~  10,000–  50,000 keys/s  → weak, TKIP deprecated
  WPA2: ~     300–   2,000 keys/s  → only weak passwords at risk

Usage:
  cd wifi_security_project
  python src/benchmark/benchmark.py
  python src/benchmark/benchmark.py --quick   # shorter run
  python src/benchmark/benchmark.py --full    # longer, more accurate
"""

import os
import sys
import time
import struct
import hashlib
import hmac
import zlib
import itertools
import string
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.wep.wep_crypto import rc4, compute_icv, wep_decrypt, wep_encrypt, random_iv
from src.wpa.wpa_crypto import compute_pmk, compute_ptk, ptk_split, compute_mic_wpa2, compute_mic_wpa

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


# ─── Colour helpers ─────────────────────────────────────────────────────────

def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"


# ─── Benchmark: WEP ─────────────────────────────────────────────────────────

def benchmark_wep(duration_s: float = 3.0) -> dict:
    """
    Measure WEP brute-force throughput.
    Strategy: try numeric 5-char keys against one encrypted frame.
    """
    print(cyan(f"\n[*] Benchmarking WEP (RC4 + CRC32)..."))

    # Setup: encrypt one frame with a known key
    true_key  = b'hello'
    iv        = random_iv()
    plaintext = b'\xAA\xAA\x03' + b'TEST' * 10
    frame     = wep_encrypt(iv, true_key, plaintext)

    count   = 0
    found   = False
    digits  = string.digits.encode()
    start   = time.perf_counter()
    deadline = start + duration_s

    for combo in itertools.product(digits, repeat=5):
        candidate = bytes(combo)
        ok, _     = wep_decrypt(candidate, frame)
        count    += 1
        if ok:
            found = True
        if time.perf_counter() >= deadline:
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed

    print(f"    Attempts:  {count:,}")
    print(f"    Time:      {elapsed:.2f}s")
    print(f"    Speed:     {green(f'{speed:,.0f} keys/s')}")
    print(f"    Key found: {'Yes' if found else 'No (time limit)'}")

    return {'protocol': 'WEP', 'speed': speed, 'count': count, 'elapsed': elapsed}


# ─── Benchmark: WPA (TKIP) ──────────────────────────────────────────────────

def benchmark_wpa(duration_s: float = 3.0) -> dict:
    """
    Measure WPA/TKIP dictionary speed.
    TKIP uses HMAC-MD5 for MIC — faster than WPA2's PBKDF2.
    We measure MIC computations only (skipping PBKDF2 to isolate TKIP MIC).
    """
    print(cyan(f"\n[*] Benchmarking WPA/TKIP (HMAC-MD5 MIC)..."))

    # Pre-computed KCK (skip PBKDF2 to benchmark just the MIC step)
    kck        = os.urandom(16)
    eapol_data = os.urandom(121)   # typical EAPOL frame size
    target_mic = hmac.new(kck, eapol_data, hashlib.md5).digest()

    count  = 0
    found  = False
    start  = time.perf_counter()
    deadline = start + duration_s

    while time.perf_counter() < deadline:
        mic   = hmac.new(kck, eapol_data, hashlib.md5).digest()
        count += 1
        if mic == target_mic:
            found = True

    elapsed = time.perf_counter() - start
    speed   = count / elapsed

    print(f"    Attempts:  {count:,}")
    print(f"    Time:      {elapsed:.2f}s")
    print(f"    Speed:     {green(f'{speed:,.0f} MIC-checks/s')}")
    print(f"    (Real WPA attack bottleneck is PBKDF2, not MIC)")

    return {'protocol': 'WPA', 'speed': speed, 'count': count, 'elapsed': elapsed}


# ─── Benchmark: WPA2 (Full PBKDF2 pipeline) ─────────────────────────────────

def benchmark_wpa2_full(duration_s: float = 5.0, ssid: str = 'HomeNetwork') -> dict:
    """
    Full WPA2 attack pipeline including PBKDF2 (the real bottleneck).
    This measures end-to-end passwords/second for a realistic attack.
    """
    print(cyan(f"\n[*] Benchmarking WPA2 (full PBKDF2 pipeline)..."))

    # Generate a real handshake to attack
    true_pw = 'correctpassword'
    aa      = os.urandom(6)
    sa      = os.urandom(6)
    anonce  = os.urandom(32)
    snonce  = os.urandom(32)

    pmk       = compute_pmk(true_pw, ssid)
    ptk       = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck, _, _ = ptk_split(ptk)
    eapol     = os.urandom(121)
    target_mic = compute_mic_wpa2(kck, eapol)

    # Fake wordlist: wrong passwords + one correct at the end
    fake_passwords = [f'password{i:04d}' for i in range(10000)] + [true_pw]

    count    = 0
    found    = False
    start    = time.perf_counter()
    deadline = start + duration_s

    for pw in fake_passwords:
        if time.perf_counter() >= deadline:
            break
        pmk_cand  = compute_pmk(pw, ssid)
        ptk_cand  = compute_ptk(pmk_cand, aa, sa, anonce, snonce)
        kck_cand, _, _ = ptk_split(ptk_cand)
        mic_cand  = compute_mic_wpa2(kck_cand, eapol)
        count    += 1
        if mic_cand == target_mic:
            found = True
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed

    print(f"    Attempts:  {count:,}")
    print(f"    Time:      {elapsed:.2f}s")
    print(f"    Speed:     {red(f'{speed:,.0f} passwords/s')} (PBKDF2 limited)")

    return {'protocol': 'WPA2', 'speed': speed, 'count': count, 'elapsed': elapsed}


# ─── Benchmark: WPA2 PBKDF2 alone ───────────────────────────────────────────

def benchmark_pbkdf2(duration_s: float = 3.0) -> dict:
    """Isolate PBKDF2 computation cost."""
    print(cyan(f"\n[*] Benchmarking PBKDF2-SHA1 (4096 iters) alone..."))

    ssid  = 'TestNetwork'
    count = 0
    start = time.perf_counter()
    deadline = start + duration_s

    i = 0
    while time.perf_counter() < deadline:
        hashlib.pbkdf2_hmac('sha1', f'password{i}'.encode(), ssid.encode(), 4096, 32)
        count += 1
        i     += 1

    elapsed = time.perf_counter() - start
    speed   = count / elapsed

    print(f"    Computations: {count:,}")
    print(f"    Time:         {elapsed:.2f}s")
    print(f"    Speed:        {red(f'{speed:.0f} PMKs/s')}")

    return {'protocol': 'WPA2-PBKDF2', 'speed': speed, 'count': count, 'elapsed': elapsed}


# ─── Summary table ───────────────────────────────────────────────────────────

def print_summary(results: list[dict]) -> None:
    print(bold(f"\n{'='*65}"))
    print(bold(f"  BENCHMARK SUMMARY"))
    print(bold(f"{'='*65}"))

    if HAS_TABULATE:
        rows = []
        for r in results:
            speed = r['speed']
            if r['protocol'] == 'WEP':
                risk_color, risk = green, 'CRITICAL (broken)'
            elif r['protocol'] == 'WPA':
                risk_color, risk = yellow, 'HIGH (deprecated)'
            else:
                risk_color, risk = red, 'LOW (if password strong)'

            rows.append([
                r['protocol'],
                f"{speed:>15,.0f}",
                r['elapsed'],
                risk_color(risk)
            ])

        print(tabulate(rows,
                       headers=['Protocol', 'Speed (keys/s)', 'Test time (s)', 'Risk'],
                       tablefmt='rounded_outline'))
    else:
        for r in results:
            print(f"  {r['protocol']:12s}: {r['speed']:>12,.0f} keys/s")

    print()
    print(bold("  Key takeaways:"))
    print(f"  • WEP  can be cracked in seconds — {red('completely broken')}")
    print(f"  • WPA  TKIP is deprecated, MIC-only is fast — {yellow('avoid')}")
    print(f"  • WPA2 PBKDF2 slows attacks to ~{red('300-2000/s')} — {green('use strong passwords!')}")
    print(f"  • A GPU (hashcat) is ~1000x faster than Python")
    print(f"\n  8-char lowercase password:")
    print(f"  {'26^8 = 208,827,064,576 combinations':50s}")
    wpa2_speed = next((r['speed'] for r in results if r['protocol'] == 'WPA2'), 500)
    days = 208_827_064_576 / wpa2_speed / 86400
    print(f"  At {wpa2_speed:.0f} PMKs/s: ~{days:,.0f} days in Python")
    print(f"  At 1,000,000 PMKs/s (GPU): ~{days/2000:.1f} days")
    print(bold(f"{'='*65}\n"))


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='WiFi Security Benchmarks')
    parser.add_argument('--quick', action='store_true', help='2s per test')
    parser.add_argument('--full',  action='store_true', help='10s per test')
    parser.add_argument('--wep-only',  action='store_true')
    parser.add_argument('--wpa2-only', action='store_true')
    args = parser.parse_args()

    dur = 2.0 if args.quick else (10.0 if args.full else 3.0)

    print(bold("\n" + "="*65))
    print(bold("  WiFi Security Educational Benchmarks"))
    print(bold("  WEP vs WPA vs WPA2 Attack Speed Comparison"))
    print(bold("="*65))

    results = []

    if not args.wpa2_only:
        results.append(benchmark_wep(dur))
        results.append(benchmark_wpa(dur))

    if not args.wep_only:
        results.append(benchmark_wpa2_full(dur))
        results.append(benchmark_pbkdf2(dur))

    print_summary(results)


if __name__ == '__main__':
    main()
