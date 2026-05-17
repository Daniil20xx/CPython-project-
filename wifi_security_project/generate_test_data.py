"""
generate_test_data.py — Генератор тестовых данных
===================================================
Создаёт все файлы-захваты, необходимые для брутфорса и лабораторной:

  data/captures/test_wep_40.wep    — 200 WEP-40 фреймов (ключ: hello)
  data/captures/test_wep_104.wep   — 200 WEP-104 фреймов (ключ: helloworld123)
  data/captures/test_wpa.json      — WPA/TKIP handshake  (пароль: dragon)
  data/captures/test_wpa2.json     — WPA2/CCMP handshake (пароль: dragon)
  data/captures/test_wpa2_hard.json— WPA2 с паролем hunter2 (для лабы)
  data/wordlists/passwords.txt     — 50 реальных паролей

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
КАК ВОСПРОИЗВЕСТИ ПОШАГОВО:

  Шаг 1. Убедитесь, что находитесь в корне проекта:
           cd wifi_lab/

  Шаг 2. Запустите генератор:
           python generate_test_data.py

  Шаг 3. Проверьте созданные файлы:
           ls -lh data/captures/
           # Ожидаемый вывод:
           # test_wep_40.wep      ~12 KB
           # test_wep_104.wep     ~12 KB
           # test_wpa.json        ~1 KB
           # test_wpa2.json       ~1 KB
           # test_wpa2_hard.json  ~1 KB

  Шаг 4. Опции командной строки:
           python generate_test_data.py --wep-key hello --wep-frames 500
           python generate_test_data.py --wpa-password mypassword
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import json
import struct
import argparse

# Импортируем свои примитивы
sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import (
    wep_encrypt, compute_pmk, compute_ptk,
    compute_mic_wpa, compute_mic_wpa2
)


# ══════════════════════════════════════════════════════════════════════
# WEP CAPTURE FORMAT
# ══════════════════════════════════════════════════════════════════════
#
#  Бинарный файл (.wep):
#
#  Заголовок (9 байт):
#    Offset 0: magic    = b'WEP\x01'  (4 байта)
#    Offset 4: key_len  = uint8       (1 байт, длина ключа в байтах)
#    Offset 5: n_frames = uint32 LE   (4 байта, кол-во фреймов)
#
#  Фреймы (повторяются n_frames раз):
#    Offset 0: frame_len = uint16 LE  (2 байта)
#    Offset 2: frame_data             (frame_len байт)
#
#  Каждый frame_data:
#    [0:3]  IV       (3 байта случайного вектора)
#    [3]    KeyID    (1 байт, всегда 0)
#    [4:]   RC4(IV || key, plaintext || CRC32)
#
# ══════════════════════════════════════════════════════════════════════

WEP_MAGIC = b'WEP\x01'

# Симулируем реальные 802.11 data payloads
_WEP_PAYLOADS = [
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'GET / HTTP/1.1\r\nHost: 192.168.1.1\r\n\r\n',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'ARP Who has 192.168.1.1? Tell 192.168.1.100',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'DHCP Request from 192.168.1.100',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'DNS Query: www.google.com type A',
    b'\xAA\xAA\x03\x00\x00\x00\x08\x00' + b'TCP SYN to 93.184.216.34:80',
]


def generate_wep_capture(
    wep_key:     bytes,
    num_frames:  int  = 200,
    output_path: str  = 'data/captures/test_wep_40.wep'
) -> None:
    """
    Создаёт .wep файл с num_frames зашифрованных фреймов.

    Каждый фрейм шифруется одним ключом, но уникальным случайным IV,
    что имитирует реальный перехват трафика WEP-сети.

    Аргументы:
      wep_key     — байтовый WEP-ключ (5 байт для WEP-40, 13 для WEP-104)
      num_frames  — сколько фреймов включить в файл
      output_path — куда сохранить
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    frames = []
    for i in range(num_frames):
        iv      = os.urandom(3)
        payload = _WEP_PAYLOADS[i % len(_WEP_PAYLOADS)]
        frame   = wep_encrypt(iv, wep_key, payload)
        frames.append(frame)

    with open(output_path, 'wb') as f:
        f.write(WEP_MAGIC)
        f.write(struct.pack('<B', len(wep_key)))
        f.write(struct.pack('<I', len(frames)))
        for frame in frames:
            f.write(struct.pack('<H', len(frame)))
            f.write(frame)

    size_kb = os.path.getsize(output_path) / 1024
    print(f"  [+] WEP-{len(wep_key)*8} capture: {output_path}  "
          f"({num_frames} frames, key={wep_key.hex()}, {size_kb:.1f} KB)")


def read_wep_capture(path: str) -> tuple[int, list[bytes]]:
    """
    Читает .wep файл.
    Возвращает (key_len_bytes, [encrypted_frame_bytes, ...])
    """
    with open(path, 'rb') as f:
        magic = f.read(4)
        if magic != WEP_MAGIC:
            raise ValueError(f"Неверный magic bytes: {magic!r}")
        key_len   = struct.unpack('<B', f.read(1))[0]
        n_frames  = struct.unpack('<I', f.read(4))[0]
        frames = []
        for _ in range(n_frames):
            flen  = struct.unpack('<H', f.read(2))[0]
            frames.append(f.read(flen))
    return key_len, frames


# ══════════════════════════════════════════════════════════════════════
# WPA/WPA2 HANDSHAKE FORMAT
# ══════════════════════════════════════════════════════════════════════
#
#  JSON-файл (.json) содержит компоненты Message 2 из 4-way handshake:
#
#  {
#    "protocol":    "WPA2",           ← WPA2 (CCMP) или WPA (TKIP)
#    "ssid":        "HomeNetwork",    ← имя сети (соль для PBKDF2)
#    "aa":          "aabbccddeeff",   ← AP MAC, hex без двоеточий
#    "sa":          "112233445566",   ← Client MAC
#    "anonce":      "...",            ← AP Nonce, 32 байта hex
#    "snonce":      "...",            ← Client Nonce, 32 байта hex
#    "eapol_frame": "...",            ← EAPOL Message 2, MIC ОБНУЛЁН
#    "mic":         "...",            ← Эталонный MIC (16 байт hex)
#    "_password":   "dragon"          ← Только для тестов! В реальности неизвестен
#  }
#
#  Почему MIC обнулён в eapol_frame:
#    При вычислении MIC отправитель сначала заполняет поле нулями,
#    считает HMAC, затем вставляет результат. Верификатор делает то же:
#    обнуляет поле → вычисляет HMAC → сравнивает с полученным MIC.
#
# ══════════════════════════════════════════════════════════════════════

def _build_eapol_frame(snonce: bytes) -> bytes:
    """
    Строит минимальный EAPOL-Key Message 2 с обнулённым MIC.

    Структура (упрощённая по IEEE 802.11i):
      [0]    version=1
      [1]    type=3 (EAPOL-Key)
      [2:4]  length (big-endian, длина тела)
      [4]    descriptor_type=2 (RSN/WPA2)
      [5:7]  key_info=0x010A
      [7:9]  key_length=0
      [9:17] replay_counter
      [17:49] nonce (snonce здесь)
      [49:65] EAPOL-Key IV = zeros
      [65:73] RSC = zeros
      [73:81] reserved = zeros
      [81:97] MIC = zeros (обнулено!)
      [97:99] key_data_len = 0
    """
    body = (
        b'\x02'              # descriptor type: RSN
        + b'\x01\x0a'        # key_info: pairwise | MIC
        + b'\x00\x00'        # key_length
        + b'\x00' * 8        # replay counter
        + snonce             # 32 байта
        + b'\x00' * 16       # EAPOL-Key IV
        + b'\x00' * 8        # RSC
        + b'\x00' * 8        # reserved
        + b'\x00' * 16       # MIC (обнулён)
        + b'\x00\x00'        # key_data_len
    )
    header = b'\x01\x03' + len(body).to_bytes(2, 'big')
    return header + body


def generate_wpa_handshake(
    password:    str,
    ssid:        str    = 'HomeNetwork',
    protocol:    str    = 'WPA2',
    output_path: str    = 'data/captures/test_wpa2.json'
) -> None:
    """
    Создаёт синтетический WPA/WPA2 handshake в JSON.

    Генерирует случайные MAC-адреса и nonces, вычисляет настоящий MIC
    по цепочке PBKDF2 → PTK → KCK → HMAC.

    Аргументы:
      password    — пароль WiFi (должен присутствовать в словаре для взлома)
      ssid        — имя сети
      protocol    — 'WPA2' или 'WPA'
      output_path — путь к JSON-файлу
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    aa     = os.urandom(6)   # AP MAC
    sa     = os.urandom(6)   # Client MAC
    anonce = os.urandom(32)
    snonce = os.urandom(32)

    pmk   = compute_pmk(password, ssid)
    ptk   = compute_ptk(pmk, aa, sa, anonce, snonce)
    kck   = ptk[:16]
    eapol = _build_eapol_frame(snonce)

    mic = compute_mic_wpa2(kck, eapol) if protocol == 'WPA2' else compute_mic_wpa(kck, eapol)

    data = {
        'protocol':    protocol,
        'ssid':        ssid,
        'aa':          aa.hex(),
        'sa':          sa.hex(),
        'anonce':      anonce.hex(),
        'snonce':      snonce.hex(),
        'eapol_frame': eapol.hex(),
        'mic':         mic.hex(),
        '_password':   password,   # только для верификации результата!
    }
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

    print(f"  [+] {protocol} handshake: {output_path}  "
          f"(ssid={ssid!r}, password={password!r}, mic={mic.hex()[:16]}...)")


def load_handshake(path: str) -> dict:
    """
    Загружает JSON-handshake и декодирует hex-поля в bytes.
    Возвращает dict с полями: protocol, ssid, aa, sa, anonce, snonce, eapol_frame, mic
    """
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


# ══════════════════════════════════════════════════════════════════════
# WORDLIST
# ══════════════════════════════════════════════════════════════════════

_PASSWORDS = [
    # Самые популярные (топ-30 из реальных утечек):
    '123456', 'password', '12345678', 'qwerty', 'abc123',
    'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
    'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
    'bailey', 'passw0rd', 'shadow', '123123', '654321',
    'superman', 'qazwsx', 'michael', 'football', 'password1',
    'batman', 'admin', 'welcome', 'login', 'hello',
    # Дополнительные:
    'hunter2', 'raspberry', 'secret', 'home123', 'wifi123',
    'internet', 'mypassword', 'test1234', 'password123', '1234567890',
    'qwerty123', 'zxcvbn', 'abcdef', 'pass1234', 'network',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'raspberry',
    'aaaaaa', 'correcthorse', 'battery', 'staple', 'hello123456',
]


def generate_wordlist(path: str = 'data/wordlists/passwords.txt') -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write('\n'.join(_PASSWORDS) + '\n')
    print(f"  [+] Wordlist: {path}  ({len(_PASSWORDS)} passwords)")


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Генератор тестовых файлов для wifi_lab',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Создать все файлы с настройками по умолчанию:
  python generate_test_data.py

  # Другой WEP-ключ и количество фреймов:
  python generate_test_data.py --wep-key hello --wep-frames 500

  # Другой пароль WPA2 (должен быть в словаре!):
  python generate_test_data.py --wpa-password hunter2
        """
    )
    parser.add_argument('--wep-key',    default='hello123456',
                        help='5-символьный WEP-40 ключ (ASCII)')
    parser.add_argument('--wep-frames', type=int, default=200,
                        help='Кол-во WEP-фреймов в capture')
    parser.add_argument('--wpa-password', default='hello123456',
                        help='Пароль для WPA/WPA2 handshake')
    parser.add_argument('--ssid',       default='HomeNetwork')
    args = parser.parse_args()

    print("\n=== Генерация тестовых данных для wifi_lab ===\n")

    # Словарь
    generate_wordlist()

    # WEP captures
    wep_key_40  = args.wep_key.encode('ascii')[:5].ljust(5, b'\x00')
    wep_key_104 = (args.wep_key * 3)[:13].encode('ascii')
    generate_wep_capture(wep_key_40,  args.wep_frames, 'data/captures/test_wep_40.wep')
    generate_wep_capture(wep_key_104, args.wep_frames, 'data/captures/test_wep_104.wep')

    # WPA/WPA2 handshakes
    generate_wpa_handshake(args.wpa_password, args.ssid, 'WPA',  'data/captures/test_wpa.json')
    generate_wpa_handshake(args.wpa_password, args.ssid, 'WPA2', 'data/captures/test_wpa2.json')
    generate_wpa_handshake('hunter2',         args.ssid, 'WPA2', 'data/captures/test_wpa2_hard.json')

    print("\n=== Готово! ===")
    print("\nТеперь запустите:")
    print("  python bruteforce_benchmark.py   ← WEP/WPA/WPA2 брутфорс + статистика")
    print("  python lab_aes_wpa2.py           ← Лабораторная по AES + статистика")


if __name__ == '__main__':
    main()
