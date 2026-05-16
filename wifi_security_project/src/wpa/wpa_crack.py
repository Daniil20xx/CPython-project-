"""
wpa_crack.py — WPA/WPA2 Dictionary Cracker (Educational)
=========================================================
Performs a dictionary attack against a WPA/WPA2 handshake
captured in the JSON format produced by wpa_gen.py.

The attack:
  For each password candidate:
    1. PMK = PBKDF2-HMAC-SHA1(password, SSID, 4096)   ← bottleneck
    2. PTK = PRF-512(PMK, "Pairwise key expansion", ...)
    3. KCK = PTK[0:16]
    4. MIC = HMAC-SHA1(KCK, EAPOL)[0:16]
    5. If MIC matches captured MIC → password found!

Performance note:
  Python PBKDF2: ~300-800 passwords/s (CPU-bound)
  Hashcat (GPU): ~1,000,000+ passwords/s
  This is why long, random WPA2 passwords are secure.

Usage:
  python src/wpa/wpa_crack.py
  python src/wpa/wpa_crack.py --capture data/captures/test_wpa2.json --wordlist data/wordlists/passwords.txt
  python src/wpa/wpa_crack.py --gen-handshake --password hunter2 --ssid MyWifi
"""

import os
import sys
import time
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.wpa.wpa_crypto import verify_password
from src.wpa.wpa_gen    import generate_handshake, load_handshake

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
def cyan(s):   return f"\033[96m{s}\033[0m"


# ─── Core cracker ───────────────────────────────────────────────────────────

def crack_wpa(
    handshake:    dict,
    wordlist_path: str,
    verbose:      bool = False
) -> dict:
    """
    Dictionary attack on a WPA/WPA2 handshake.

    Args:
        handshake:     Loaded handshake dict (from load_handshake)
        wordlist_path: Path to newline-separated password list
        verbose:       Print each attempt (very slow!)

    Returns:
        Result dict with found password, stats, etc.
    """
    if not os.path.exists(wordlist_path):
        raise FileNotFoundError(f"Wordlist not found: {wordlist_path}")

    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        candidates = [line.strip() for line in f if line.strip()]

    protocol = handshake['protocol']
    ssid     = handshake['ssid']

    print(bold(f"\n{'='*55}"))
    print(bold(f"  WPA Cracker — {protocol}"))
    print(f"{'='*55}")
    print(f"  SSID:       {cyan(ssid)}")
    print(f"  Protocol:   {protocol}")
    print(f"  Wordlist:   {len(candidates):,} passwords")
    print(f"  MIC target: {handshake['mic'].hex()[:32]}...")
    print(f"{'='*55}\n")

    start   = time.perf_counter()
    found   = None
    count   = 0

    # Measure speed with first 3 passwords before starting
    if len(candidates) >= 3:
        t_s = time.perf_counter()
        for pw in candidates[:3]:
            verify_password(pw, ssid, handshake['aa'], handshake['sa'],
                            handshake['anonce'], handshake['snonce'],
                            handshake['eapol_frame'], handshake['mic'], protocol)
        t_e = time.perf_counter()
        speed_est = 3 / (t_e - t_s)
        eta_sec   = len(candidates) / speed_est
        print(f"  Estimated speed: {speed_est:.0f} passwords/s")
        print(f"  Estimated time:  {eta_sec:.1f}s for full wordlist\n")

    iter_candidates = tqdm(candidates, unit='pwd', desc='Cracking') if HAS_TQDM else candidates

    for password in iter_candidates:
        count += 1

        if verbose:
            print(f"  Trying: {password!r:30s}", end='\r')

        ok = verify_password(
            password, ssid,
            handshake['aa'],  handshake['sa'],
            handshake['anonce'], handshake['snonce'],
            handshake['eapol_frame'], handshake['mic'],
            protocol
        )

        if ok:
            found = password
            break

    elapsed = time.perf_counter() - start
    speed   = count / elapsed if elapsed > 0 else 0

    # ── Report ──
    print()
    print(f"{'='*55}")
    if found:
        print(green(f"  [+] PASSWORD FOUND!"))
        print(green(f"      → {found!r}"))
    else:
        print(red(f"  [-] Password not found in wordlist."))
        print(yellow(f"      Try a larger wordlist or different attack mode."))

    print(f"\n  Tried:    {count:,} candidates")
    print(f"  Time:     {elapsed:.2f}s")
    print(f"  Speed:    {speed:.0f} passwords/s")
    print(f"  Protocol: {protocol}")
    print(f"{'='*55}\n")

    return {
        'found':    found,
        'count':    count,
        'elapsed':  elapsed,
        'speed':    speed,
        'protocol': protocol,
    }


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Educational WPA/WPA2 Dictionary Cracker',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-generate a handshake then crack it
  python src/wpa/wpa_crack.py --gen-handshake --password hunter2 --ssid HomeNet

  # Use existing capture
  python src/wpa/wpa_crack.py --capture data/captures/test_wpa2.json

  # Crack WPA (TKIP) handshake
  python src/wpa/wpa_crack.py --gen-handshake --protocol WPA --password secret
        """
    )
    parser.add_argument('--capture',       default='data/captures/test_wpa2.json')
    parser.add_argument('--wordlist',      default='data/wordlists/passwords.txt')
    parser.add_argument('--gen-handshake', action='store_true',
                        help='Auto-generate a handshake capture before cracking')
    parser.add_argument('--password',      default='hunter2',
                        help='Password for auto-generated handshake')
    parser.add_argument('--ssid',          default='HomeNetwork')
    parser.add_argument('--protocol',      choices=['WPA2', 'WPA'], default='WPA2')
    parser.add_argument('--verbose',       action='store_true')
    args = parser.parse_args()

    if args.gen_handshake:
        print(yellow(f"[*] Generating {args.protocol} handshake..."))
        generate_handshake(args.password, args.ssid, args.protocol, args.capture)
        print()

    if not os.path.exists(args.capture):
        print(red(f"[!] Capture file not found: {args.capture}"))
        print(yellow(f"    Use --gen-handshake to create one"))
        sys.exit(1)

    handshake = load_handshake(args.capture)
    crack_wpa(handshake, args.wordlist, args.verbose)


if __name__ == '__main__':
    main()
