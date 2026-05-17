"""
crypto_utils.py — Shared Cryptographic Primitives
===================================================
Содержит реализации всех криптографических примитивов,
используемых в проекте: RC4, CRC-32, PBKDF2-цепочку WPA2.

Этот файл не запускается напрямую — он импортируется другими модулями.

Что здесь реализовано:
  ┌─ WEP ──────────────────────────────────────────────────┐
  │  RC4 KSA + PRGA   → шифрование/расшифровка фреймов    │
  │  CRC-32 ICV       → проверка целостности (слабая)      │
  └────────────────────────────────────────────────────────┘
  ┌─ WPA/WPA2 ─────────────────────────────────────────────┐
  │  PBKDF2-SHA1      → PMK из пароля + SSID (медленно!)   │
  │  PRF-512          → PTK из PMK + nonces + MAC          │
  │  HMAC-MD5/SHA1    → MIC для WPA/WPA2                   │
  └────────────────────────────────────────────────────────┘
"""

import struct
import zlib
import hmac
import hashlib
import os


# ══════════════════════════════════════════════════════════════════════
# RC4 — поточный шифр, используется в WEP
# ══════════════════════════════════════════════════════════════════════

def rc4_ksa(key: bytes) -> list[int]:
    """
    RC4 Key Scheduling Algorithm.
    Инициализирует перестановку S[0..255] на основе ключа.

    Вход:  key — произвольный байтовый ключ
    Выход: список S из 256 элементов (перемешанная перестановка)
    """
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def rc4_prga(S: list[int], length: int) -> bytes:
    """
    RC4 Pseudo-Random Generation Algorithm.
    Генерирует `length` байт псевдослучайного потока из состояния S.
    """
    i = j = 0
    out = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(S[(S[i] + S[j]) % 256])
    return bytes(out)


def rc4(key: bytes, data: bytes) -> bytes:
    """RC4: KSA → PRGA → XOR с данными."""
    S  = rc4_ksa(key)
    ks = rc4_prga(S, len(data))
    return bytes(a ^ b for a, b in zip(data, ks))


# ══════════════════════════════════════════════════════════════════════
# WEP Frame: Encrypt / Decrypt
# ══════════════════════════════════════════════════════════════════════

def wep_encrypt(iv: bytes, wep_key: bytes, plaintext: bytes) -> bytes:
    """
    Зашифровать один WEP-фрейм.

    Формула: IV(3) | KeyID=0(1) | RC4(IV||key, plaintext||CRC32)

    Вход:
      iv       — 3 байта случайного IV
      wep_key  — 5 или 13 байт ключа
      plaintext — данные для шифрования

    Выход: полный WEP-фрейм готовый к отправке / сохранению
    """
    rc4_seed  = iv + wep_key
    icv       = struct.pack('<I', zlib.crc32(plaintext) & 0xFFFFFFFF)
    encrypted = rc4(rc4_seed, plaintext + icv)
    return iv + b'\x00' + encrypted


def wep_decrypt(wep_key: bytes, frame: bytes) -> tuple[bool, bytes]:
    """
    Расшифровать WEP-фрейм и проверить CRC-32 (ICV).

    Вход:
      wep_key — кандидат на ключ
      frame   — байты фрейма начиная с IV

    Выход: (valid, plaintext)
      valid = True означает, что CRC-32 совпал → ключ верный
      Вероятность ложного срабатывания ≈ 1/2^32
    """
    if len(frame) < 8:
        return False, b''
    iv         = frame[:3]
    ciphertext = frame[4:]          # пропускаем KeyID (frame[3])
    decrypted  = rc4(iv + wep_key, ciphertext)
    plaintext  = decrypted[:-4]
    recv_icv   = decrypted[-4:]
    expected   = struct.pack('<I', zlib.crc32(plaintext) & 0xFFFFFFFF)
    return recv_icv == expected, plaintext


# ══════════════════════════════════════════════════════════════════════
# WPA2: PMK → PTK → KCK → MIC
# ══════════════════════════════════════════════════════════════════════

def compute_pmk(password: str, ssid: str) -> bytes:
    """
    PMK = PBKDF2-HMAC-SHA1(password, ssid, iterations=4096, dklen=32)

    Это самый медленный шаг: 4096 итераций SHA1 на один пароль.
    Именно он ограничивает скорость до ~300-2000 паролей/сек на CPU.

    Вход:  password — строка пароля WiFi
           ssid     — имя сети (соль для PBKDF2)
    Выход: 32-байтный Pairwise Master Key
    """
    return hashlib.pbkdf2_hmac(
        'sha1',
        password.encode('utf-8'),
        ssid.encode('utf-8'),
        4096,
        dklen=32
    )


def compute_ptk(pmk: bytes, aa: bytes, sa: bytes,
                anonce: bytes, snonce: bytes) -> bytes:
    """
    PTK = PRF-512(PMK, "Pairwise key expansion", sorted(AA,SA) || sorted(ANonce,SNonce))

    PRF здесь — HMAC-SHA1 с последовательным увеличением счётчика.
    AA = AP MAC (6 байт), SA = Client MAC (6 байт).
    Сортировка min/max гарантирует одинаковый результат у обеих сторон.

    Выход: 64 байта:
      [0:16]  KCK — Key Confirmation Key (для проверки MIC)
      [16:32] KEK — Key Encryption Key
      [32:48] TK  — Temporal Key (реальный ключ шифрования трафика)
    """
    data = min(aa, sa) + max(aa, sa) + min(anonce, snonce) + max(anonce, snonce)
    out  = b''
    for i in range(4):
        msg  = b'Pairwise key expansion\x00' + data + bytes([i])
        out += hmac.new(pmk, msg, hashlib.sha1).digest()
    return out[:64]


def compute_mic_wpa(kck: bytes, eapol: bytes) -> bytes:
    """MIC для WPA/TKIP: HMAC-MD5(KCK, EAPOL)"""
    return hmac.new(kck, eapol, hashlib.md5).digest()


def compute_mic_wpa2(kck: bytes, eapol: bytes) -> bytes:
    """MIC для WPA2/CCMP: HMAC-SHA1(KCK, EAPOL)[0:16]"""
    return hmac.new(kck, eapol, hashlib.sha1).digest()[:16]


def verify_password(password: str, ssid: str, aa: bytes, sa: bytes,
                    anonce: bytes, snonce: bytes, eapol: bytes,
                    mic_target: bytes, protocol: str = 'WPA2') -> bool:
    """
    Полная проверка пароля против захваченного handshake.
    Возвращает True если пароль верный.

    Цепочка: password → PMK → PTK → KCK → MIC → сравниваем
    """
    pmk = compute_pmk(password, ssid)
    ptk = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck = ptk[:16]
    mic = compute_mic_wpa2(kck, eapol) if protocol == 'WPA2' else compute_mic_wpa(kck, eapol)
    return mic == mic_target
