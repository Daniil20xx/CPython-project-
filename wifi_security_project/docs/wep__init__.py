"""
src/wep/ — Пакет WEP (Wired Equivalent Privacy)
=================================================
Реализует криптографические примитивы и инструменты атаки для протокола WEP.

Файлы:
  wep_crypto.py — RC4 KSA/PRGA, CRC-32 ICV, шифрование/расшифровка фреймов
  wep_gen.py    — Генератор .wep-файлов с синтетическими зашифрованными фреймами
  wep_crack.py  — Взломщик: wordlist / numeric / alphanum перебор по CRC-верификации

Быстрый старт:
    from src.wep.wep_crypto import wep_encrypt, wep_decrypt, random_iv
    key   = b'hello'                 # 5-байтный WEP-40 ключ
    iv    = random_iv()
    frame = wep_encrypt(iv, key, b'test payload')
    ok, plaintext = wep_decrypt(key, frame)
"""
