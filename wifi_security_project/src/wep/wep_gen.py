"""
wep_gen.py — WEP Capture Generator (Educational)
=================================================
Generates a synthetic WEP capture file (.wep) containing multiple
encrypted frames with the same key but different IVs.

Output format (binary, little-endian):
  Header: magic (4 B) | key_len (1 B) | num_frames (4 B)
  Frame:  frame_len (2 B) | frame_data

This simulates what a passive WiFi sniffer would capture.
The cracker reads this file and tries to find the key.
"""

import os
import struct
import json
import base64
import argparse
import sys

# Allow imports from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from src.wep.wep_crypto import wep_encrypt, random_iv, key_from_passphrase

MAGIC = b'WEP\x01'           # File magic bytes

# Sample plaintext payloads (simulating 802.11 data frames)
SAMPLE_PAYLOADS = [
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'Hello, WEP network! Frame #2',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'Password: topsecret123',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'DHCP Request from 192.168.1.10',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'ARP Who has 192.168.1.1? Tell 192.168.1.10',
]


def generate_capture(
    wep_key: bytes,
    num_frames: int = 100,
    output_path: str = 'data/captures/test_wep.wep'
) -> dict:
    """
    Generate a WEP capture file.

    Args:
        wep_key:     The WEP key used to encrypt frames
        num_frames:  How many encrypted frames to produce
        output_path: Output file path

    Returns:
        Metadata dict with generation parameters
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    frames = []
    for i in range(num_frames):
        iv = random_iv()
        payload = SAMPLE_PAYLOADS[i % len(SAMPLE_PAYLOADS)]
        frame = wep_encrypt(iv, wep_key, payload)
        frames.append(frame)

    with open(output_path, 'wb') as f:
        # Write header
        f.write(MAGIC)
        f.write(struct.pack('<B', len(wep_key)))   # key length
        f.write(struct.pack('<I', len(frames)))    # frame count

        # Write each frame
        for frame in frames:
            f.write(struct.pack('<H', len(frame)))
            f.write(frame)

    # Also save a JSON sidecar with metadata (for debugging)
    meta = {
        'protocol':   'WEP',
        'key_length':  len(wep_key) * 8,
        'num_frames':  num_frames,
        'key_b64':     base64.b64encode(wep_key).decode(),  # only for our test!
        'capture_file': output_path,
    }
    meta_path = output_path.replace('.wep', '_meta.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)

    print(f"[+] Generated {num_frames} WEP-encrypted frames")
    print(f"    Key (hex): {wep_key.hex()}  ({len(wep_key)*8}-bit)")
    print(f"    Saved to:  {output_path}")
    print(f"    Metadata:  {meta_path}")
    return meta


def read_capture(capture_path: str) -> tuple[int, list[bytes]]:
    """
    Read a .wep capture file.

    Returns:
        (key_len_bytes, list_of_encrypted_frames)
    """
    with open(capture_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError(f"Not a valid WEP capture file (bad magic: {magic!r})")

        key_len   = struct.unpack('<B', f.read(1))[0]
        num_frames = struct.unpack('<I', f.read(4))[0]

        frames = []
        for _ in range(num_frames):
            flen  = struct.unpack('<H', f.read(2))[0]
            frame = f.read(flen)
            frames.append(frame)

    return key_len, frames


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Generate synthetic WEP capture for educational brute-force demo'
    )
    parser.add_argument('--key',    default='hello',
                        help='WEP key (5 or 13 ASCII chars, default: hello)')
    parser.add_argument('--frames', type=int, default=100,
                        help='Number of encrypted frames (default: 100)')
    parser.add_argument('--out',    default='data/captures/test_wep.wep',
                        help='Output file path')
    args = parser.parse_args()

    try:
        wep_key = key_from_passphrase(args.key)
    except ValueError as e:
        print(f"[!] {e}")
        sys.exit(1)

    generate_capture(wep_key, args.frames, args.out)


if __name__ == '__main__':
    main()
