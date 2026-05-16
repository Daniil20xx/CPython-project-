"""
aes_crack.py — Lab: WPA2 Password Search via AES-CCMP MIC (Educational)
=========================================================================
Laboratory task: find the WiFi password by attacking the WPA2 handshake.

This script is the practical part of the AES lab.
It demonstrates that AES-128 itself cannot be broken, but
a weak password makes the whole WPA2 system vulnerable.

Usage:
  # Full lab run (generates capture + cracks it):
  python lab/aes_crack.py --auto

  # Use a custom wordlist and password:
  python lab/aes_crack.py --auto --password "dragon" --ssid "CampusWifi"

  # Measure how password length affects security:
  python lab/aes_crack.py --complexity-test
"""

import os
import sys
import time
import hashlib
import hmac
import json
import string
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.wpa.wpa_crypto import (
    compute_pmk, compute_ptk, ptk_split,
    compute_mic_wpa2, verify_password
)
from src.wpa.wpa_gen import generate_handshake, load_handshake


# ─── Colour helpers ─────────────────────────────────────────────────────────

def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"
def cyan(s):   return f"\033[96m{s}\033[0m"
def magenta(s):return f"\033[95m{s}\033[0m"


# ─── Step-by-step educational cracker ───────────────────────────────────────

def crack_step_by_step(handshake: dict, wordlist_path: str) -> dict:
    """
    Verbose, step-by-step WPA2 cracker for educational purposes.
    Shows each step of the attack pipeline.
    """
    ssid     = handshake['ssid']
    protocol = handshake['protocol']
    mic_cap  = handshake['mic']

    print(bold("\n" + "="*60))
    print(bold("  LAB: WPA2 Password Search — Step-by-Step"))
    print(bold("="*60))
    print(f"""
  Target: SSID = {cyan(ssid)}
  Captured MIC: {mic_cap.hex()}
  Protocol: {protocol}

  {bold('ATTACK PIPELINE FOR EACH PASSWORD CANDIDATE:')}
  ┌────────────────────────────────────────────────────────┐
  │  Candidate password                                    │
  │       ↓  Step 1: PBKDF2-SHA1(pwd, SSID, 4096, 32)    │
  │  PMK (32 bytes)                                        │
  │       ↓  Step 2: PRF-512(PMK, "Pairwise...", data)    │
  │  PTK (64 bytes)                                        │
  │       ↓  Step 3: KCK = PTK[0:16]                      │
  │  KCK (16 bytes)                                        │
  │       ↓  Step 4: HMAC-SHA1(KCK, EAPOL_frame)[0:16]   │
  │  Computed MIC                                          │
  │       ↓  Step 5: Compare with captured MIC             │
  │  Match? → FOUND! / No match → next candidate          │
  └────────────────────────────────────────────────────────┘
""")

    # Load wordlist
    if not os.path.exists(wordlist_path):
        print(red(f"[!] Wordlist not found: {wordlist_path}"))
        return {}

    with open(wordlist_path, encoding='utf-8', errors='ignore') as f:
        candidates = [line.strip() for line in f if line.strip()]

    print(f"  Wordlist: {len(candidates):,} passwords loaded\n")
    print(f"  {'Attempt':>7}  {'Password':25s}  {'PMK[:8]':18s}  {'MIC[:8]':18s}  Match?")
    print(f"  {'─'*7}  {'─'*25}  {'─'*18}  {'─'*18}  {'─'*6}")

    start  = time.perf_counter()
    found  = None
    count  = 0
    SHOW_N = 5   # Show first N attempts verbosely, then switch to progress

    for pw in candidates:
        count += 1

        # STEP 1: Derive PMK
        pmk = compute_pmk(pw, ssid)
        # STEP 2-3: Derive PTK, extract KCK
        ptk = compute_ptk(pmk, handshake['aa'], handshake['sa'],
                           handshake['anonce'], handshake['snonce'])
        kck, _, _ = ptk_split(ptk)
        # STEP 4: Compute MIC
        mic_calc = compute_mic_wpa2(kck, handshake['eapol_frame'])
        # STEP 5: Compare
        match = mic_calc == mic_cap

        if count <= SHOW_N:
            match_str = green('YES ✓') if match else red('no')
            print(f"  {count:>7}  {pw:25.25s}  "
                  f"{pmk.hex()[:16]}  {mic_calc.hex()[:16]}  {match_str}")
        elif count == SHOW_N + 1:
            print(f"  {'...':>7}  {'(switching to fast mode)':25s}")

        if match:
            found = pw
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed if elapsed > 0 else 0

    print(f"\n{'='*60}")
    if found:
        print(green(f"  [+] PASSWORD FOUND: {found!r}"))
    else:
        print(red(f"  [-] Password not in wordlist."))

    print(f"  Tried:  {count:,} passwords")
    print(f"  Time:   {elapsed:.2f}s")
    print(f"  Speed:  {speed:.0f} passwords/s (PBKDF2 limited)")
    print("="*60)

    return {'found': found, 'count': count, 'elapsed': elapsed, 'speed': speed}


# ─── Password complexity analysis ────────────────────────────────────────────

def complexity_test() -> None:
    """
    Show how password length/complexity affects the time to brute-force WPA2.
    """
    print(bold("\n" + "="*65))
    print(bold("  LAB ANALYSIS: Password Complexity vs. Brute-Force Time"))
    print(bold("="*65))

    # Measure actual PBKDF2 speed
    t0 = time.perf_counter()
    for _ in range(10):
        hashlib.pbkdf2_hmac('sha1', b'testpassword', b'TestNet', 4096, 32)
    t1 = time.perf_counter()
    speed_python = 10 / (t1 - t0)
    speed_gpu    = 1_000_000    # typical hashcat on mid-range GPU

    print(f"\n  Measured PBKDF2 speed (this machine): {speed_python:.0f} PMKs/s")
    print(f"  Typical GPU speed (hashcat):          {speed_gpu:,} PMKs/s\n")

    charsets = [
        ('digits only (0-9)',           10),
        ('lowercase (a-z)',             26),
        ('lower+digits',               36),
        ('lower+upper+digits',         62),
        ('full printable ASCII',       95),
    ]

    print(f"  {'Password':15s}  {'Charset':30s}  {'Keyspace':20s}  "
          f"{'Python time':15s}  {'GPU time':15s}")
    print(f"  {'─'*15}  {'─'*30}  {'─'*20}  {'─'*15}  {'─'*15}")

    for length in [6, 8, 10, 12, 16]:
        for charset_name, charset_size in charsets:
            keyspace = charset_size ** length
            t_python = keyspace / speed_python
            t_gpu    = keyspace / speed_gpu

            def fmt_time(s):
                if s < 60:    return f"{s:.1f}s"
                if s < 3600:  return f"{s/60:.1f}m"
                if s < 86400: return f"{s/3600:.1f}h"
                if s < 86400*365: return f"{s/86400:.0f}d"
                return f"{s/86400/365:.0f}y"

            risk = red('CRITICAL') if t_gpu < 3600 else \
                   yellow('HIGH') if t_gpu < 86400*30 else \
                   green('SAFE')

            print(f"  {length:<15}  {charset_name:30s}  {keyspace:>20,.0f}  "
                  f"{fmt_time(t_python):>15}  {fmt_time(t_gpu):>15}  {risk}")

        print()  # blank line between lengths

    print(f"\n  {bold('Key lesson:')} A 12-char random password with mixed case + digits")
    print(f"  has 62^12 ≈ 3.2 × 10^21 combinations.")
    print(f"  At GPU speed: {3.2e21/speed_gpu/86400/365:,.0f} years to crack.")
    print(f"  {'─'*65}")
    print(f"  SSID matters too! Rainbow tables are pre-computed per-SSID.")
    print(f"  Using a unique SSID forces per-SSID computation.\n")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Lab: WPA2 Password Search (Educational)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full auto-demo (generate + crack):
  python lab/aes_crack.py --auto

  # Use a specific target password in the wordlist:
  python lab/aes_crack.py --auto --password hunter2 --ssid CampusNet

  # Password complexity analysis table:
  python lab/aes_crack.py --complexity-test

  # Crack an existing handshake:
  python lab/aes_crack.py --capture data/captures/test_wpa2.json
        """
    )
    parser.add_argument('--auto',            action='store_true',
                        help='Auto-generate a handshake then crack it')
    parser.add_argument('--capture',         default='data/captures/test_wpa2.json')
    parser.add_argument('--wordlist',        default='data/wordlists/passwords.txt')
    parser.add_argument('--password',        default='dragon',
                        help='Target password (for --auto mode)')
    parser.add_argument('--ssid',            default='HomeNetwork')
    parser.add_argument('--complexity-test', action='store_true',
                        help='Show password complexity analysis table')
    args = parser.parse_args()

    if args.complexity_test:
        complexity_test()
        return

    if args.auto:
        print(yellow(f"\n[*] Generating WPA2 handshake (password={args.password!r}, ssid={args.ssid!r})"))
        os.makedirs('data/captures', exist_ok=True)
        generate_handshake(args.password, args.ssid, 'WPA2', args.capture)
        print()

    if not os.path.exists(args.capture):
        print(red(f"[!] No capture file found at {args.capture}"))
        print(yellow("    Use --auto to generate one, or specify --capture path"))
        sys.exit(1)

    handshake = load_handshake(args.capture)
    crack_step_by_step(handshake, args.wordlist)


if __name__ == '__main__':
    main()
