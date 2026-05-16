"""
wpa_gen.py — WPA/WPA2 Handshake Generator (Educational)
=========================================================
Creates a synthetic 4-Way Handshake capture as a JSON file.
This simulates what Wireshark / airodump-ng would capture when
a client connects to a WPA2-protected AP.

The 4-Way Handshake (IEEE 802.11i):
  AP → Client:  Message 1  — ANonce
  Client → AP:  Message 2  — SNonce + MIC  ← what we capture
  AP → Client:  Message 3  — GTK (encrypted) + MIC
  Client → AP:  Message 4  — ACK

The cracker only needs Message 2 (contains SNonce + MIC from client).

Output: JSON file with all parameters needed to verify a password guess.
"""

import os
import sys
import json
import struct
import hmac
import hashlib
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.wpa.wpa_crypto import (
    compute_pmk, compute_ptk, ptk_split,
    compute_mic_wpa2, compute_mic_wpa,
    zero_mic_in_eapol
)


def _build_eapol_key_frame(
    snonce: bytes,
    mic:    bytes,
    replay_counter: int = 1
) -> bytes:
    """
    Build a minimal EAPOL-Key frame (Message 2 of 4-way handshake).
    This is a simplified version for educational purposes.

    Real frames also carry RSN IE in the key data field.
    """
    version         = 1        # EAPOL version
    pkt_type        = 3        # EAPOL-Key
    descriptor_type = 2        # RSN (WPA2)

    # Key Info: bit 8 = pairwise, bit 9 = MIC present
    key_info = (0b0000_0001_0000_1010).to_bytes(2, 'big')  # 0x010A

    key_length      = (0).to_bytes(2, 'big')
    replay_ctr      = replay_counter.to_bytes(8, 'big')
    eapol_key_iv    = b'\x00' * 16
    rsc             = b'\x00' * 8
    reserved        = b'\x00' * 8
    key_data_len    = (0).to_bytes(2, 'big')
    key_data        = b''

    # Body = everything after EAPOL header
    body = (
        bytes([descriptor_type])
        + key_info
        + key_length
        + replay_ctr
        + snonce
        + eapol_key_iv
        + rsc
        + reserved
        + mic           # MIC field (16 bytes — will be zeroed for MIC calc)
        + key_data_len
        + key_data
    )

    # EAPOL header: version | type | length (big-endian)
    header = bytes([version, pkt_type]) + len(body).to_bytes(2, 'big')
    return header + body


def generate_handshake(
    password:    str,
    ssid:        str,
    protocol:    str = 'WPA2',
    output_path: str = 'data/captures/test_wpa2.json'
) -> dict:
    """
    Generate a synthetic WPA/WPA2 handshake capture.

    Args:
        password:    The WiFi password to encode into the handshake
        ssid:        Network name
        protocol:    'WPA2' (CCMP/AES) or 'WPA' (TKIP)
        output_path: Where to save the JSON capture

    Returns:
        dict with all handshake parameters
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Random nonces and MAC addresses (as a real handshake would have)
    anonce = os.urandom(32)
    snonce = os.urandom(32)
    aa     = os.urandom(6)   # AP MAC
    sa     = os.urandom(6)   # Client MAC

    # Derive keys
    pmk       = compute_pmk(password, ssid)
    ptk       = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck, _, _ = ptk_split(ptk)

    # Build EAPOL frame with zeroed MIC
    zeroed_eapol = _build_eapol_key_frame(snonce, b'\x00' * 16)

    # Compute actual MIC
    if protocol == 'WPA2':
        mic = compute_mic_wpa2(kck, zeroed_eapol)
    else:
        mic = compute_mic_wpa(kck, zeroed_eapol)

    # Save capture as JSON (hex-encoded binary fields)
    capture = {
        'protocol':    protocol,
        'ssid':        ssid,
        'aa':          aa.hex(),          # AP MAC
        'sa':          sa.hex(),          # Client MAC
        'anonce':      anonce.hex(),
        'snonce':      snonce.hex(),
        'eapol_frame': zeroed_eapol.hex(), # MIC already zeroed for cracker
        'mic':         mic.hex(),
        # NOTE: In a real scenario you would NOT have the password here!
        # The password field below is only for our educational demo to verify
        # that the cracker finds the right answer.
        '_target_password_for_testing': password,
    }

    with open(output_path, 'w') as f:
        json.dump(capture, f, indent=2)

    print(f"[+] Generated {protocol} handshake capture")
    print(f"    SSID:     {ssid}")
    print(f"    Protocol: {protocol}")
    print(f"    AP  MAC:  {':'.join(aa.hex()[i:i+2] for i in range(0,12,2))}")
    print(f"    CLI MAC:  {':'.join(sa.hex()[i:i+2] for i in range(0,12,2))}")
    print(f"    MIC:      {mic.hex()}")
    print(f"    Saved to: {output_path}")
    return capture


def load_handshake(path: str) -> dict:
    """Load a handshake JSON and decode all hex fields."""
    with open(path) as f:
        raw = json.load(f)
    return {
        'protocol':    raw['protocol'],
        'ssid':        raw['ssid'],
        'aa':          bytes.fromhex(raw['aa']),
        'sa':          bytes.fromhex(raw['sa']),
        'anonce':      bytes.fromhex(raw['anonce']),
        'snonce':      bytes.fromhex(raw['snonce']),
        'eapol_frame': bytes.fromhex(raw['eapol_frame']),
        'mic':         bytes.fromhex(raw['mic']),
    }


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Generate synthetic WPA/WPA2 handshake capture'
    )
    parser.add_argument('--password', default='hunter2',
                        help='WiFi password to embed (default: hunter2)')
    parser.add_argument('--ssid',     default='HomeNetwork',
                        help='SSID / network name (default: HomeNetwork)')
    parser.add_argument('--protocol', choices=['WPA2', 'WPA'], default='WPA2')
    parser.add_argument('--out',      default='data/captures/test_wpa2.json')
    args = parser.parse_args()

    generate_handshake(args.password, args.ssid, args.protocol, args.out)


if __name__ == '__main__':
    main()
