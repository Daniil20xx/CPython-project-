"""
src/wpa/ — Пакет WPA / WPA2 (Wi-Fi Protected Access)
======================================================
Реализует полную криптографическую цепочку WPA/WPA2 и словарную атаку
на захваченный 4-way handshake.

Файлы:
  wpa_crypto.py — PMK (PBKDF2), PTK (PRF-512), MIC (HMAC-SHA1/MD5), verify_password
  wpa_gen.py    — Генератор синтетического handshake-файла (.json)
  wpa_crack.py  — Словарная атака: password → PMK → PTK → KCK → MIC → сравнение

Криптографическая цепочка:
    password + SSID  →[PBKDF2-SHA1 × 4096]→  PMK (32 B)
    PMK + nonces + MACs  →[PRF-512]→  PTK (64 B)
    PTK[0:16]  →  KCK  →[HMAC-SHA1]→  MIC (16 B)  → сравниваем с захваченным

Быстрый старт:
    from src.wpa.wpa_crypto import verify_password
    ok = verify_password('hunter2', 'HomeNetwork', aa, sa, anonce, snonce, eapol, mic)
"""
