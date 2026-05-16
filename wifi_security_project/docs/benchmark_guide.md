# Руководство по Бенчмаркам: WEP / WPA / WPA2

> **Учебное задание по Advanced Python**  
> Тема: Безопасность WiFi-сетей — атаки методом грубой силы

---

## 1. Теоретическая часть

### 1.1 WEP (Wired Equivalent Privacy)

**Принцип работы:**  
WEP использует поточный шифр RC4. Ключ RC4 составляется как:

```
RC4_key = IV (3 байта) || WEP_key (5 или 13 байт)
```

Каждый пакет содержит:
- **IV** — случайный вектор инициализации (3 байта, открытый)
- **Key ID** (1 байт)
- **Ciphertext** = RC4(IV || key, plaintext || ICV)
- **ICV** = CRC32(plaintext) — контрольная сумма

**Почему WEP сломан:**

| Уязвимость | Описание |
|---|---|
| Короткий IV (24 бита) | После 5000–16 млн пакетов IV повторяется (Birthday Paradox) |
| Слабые ключи RC4 | IVs вида `(A+3, 255, X)` утекают байты ключа (атака FMS/KoreK) |
| Линейный ICV | CRC-32 не является криптографическим MAC → bit-flipping атаки |
| Статический ключ | Один ключ для всех клиентов и пакетов |

**Статус:** Запрещён IEEE с 2004 года. Взламывается за секунды.

---

### 1.2 WPA (Wi-Fi Protected Access)

**Ключевые улучшения над WEP:**
- Протокол TKIP (Temporal Key Integrity Protocol)
- Уникальный ключ шифрования для каждого пакета
- MIC (Message Integrity Code) на HMAC-MD5
- 4-Way Handshake для согласования ключей

**4-Way Handshake:**
```
AP   →  Client : [M1] ANonce
Client → AP    : [M2] SNonce + MIC  ← именно это мы захватываем!
AP   →  Client : [M3] GTK (encrypted) + MIC  
Client → AP    : [M4] ACK
```

**Атака на WPA:**
```
Захваченные данные: SSID, ANonce, SNonce, MAC_AP, MAC_Client, MIC
Для каждого пароля-кандидата:
  PMK = PBKDF2-SHA1(password, SSID, 4096 iterations, 32 bytes)
  PTK = PRF-512(PMK, "Pairwise key expansion", MACs + Nonces)
  KCK = PTK[0:16]
  MIC_calc = HMAC-MD5(KCK, EAPOL_frame_with_zeroed_MIC)
  Если MIC_calc == MIC_captured → ПАРОЛЬ НАЙДЕН
```

---

### 1.3 WPA2 (IEEE 802.11i)

**Главное отличие:** Использует AES-CCMP вместо TKIP/RC4.

**AES-CCMP:**
- **AES-128** в режиме CTR (шифрование) + CBC-MAC (аутентификация)
- Размер блока: 16 байт
- 10 раундов (SubBytes → ShiftRows → MixColumns → AddRoundKey)

**MIC для WPA2:**
```python
MIC = HMAC-SHA1(KCK, EAPOL_frame)[0:16]
```

**Почему WPA2 стойкий:**
- AES-128 не имеет практических структурных атак
- PBKDF2 с 4096 итерациями намеренно замедляет перебор
- Атака возможна только через слабый пароль

---

## 2. Архитектура проекта

```
wifi_security_project/
├── src/
│   ├── wep/
│   │   ├── wep_crypto.py   ← RC4, ICV, encrypt/decrypt
│   │   ├── wep_gen.py      ← генератор тестового захвата (.wep)
│   │   └── wep_crack.py    ← брутфорс WEP ключа
│   ├── wpa/
│   │   ├── wpa_crypto.py   ← PMK, PTK, KCK, MIC вычисления
│   │   ├── wpa_gen.py      ← генератор handshake захвата (.json)
│   │   └── wpa_crack.py    ← словарная атака на WPA/WPA2
│   └── benchmark/
│       └── benchmark.py    ← сравнительные бенчмарки
├── lab/
│   ├── aes_demo.py         ← наглядная демонстрация AES
│   └── aes_crack.py        ← лабораторная: атака на WPA2
├── data/
│   ├── wordlists/passwords.txt
│   └── captures/           ← сгенерированные файлы захвата
└── requirements.txt
```

---

## 3. Установка и настройка

### Требования
- Python 3.10+
- pip

### Шаг 1: Клонировать / разместить проект
```bash
cd wifi_security_project
```

### Шаг 2: Установить зависимости
```bash
pip install -r requirements.txt
```

Зависимости:
| Пакет | Версия | Назначение |
|---|---|---|
| scapy | ≥2.5 | (опционально) реальные pcap файлы |
| tqdm | ≥4.65 | прогресс-бар при переборе |
| colorama | ≥0.4.6 | цветной вывод в Windows |
| tabulate | ≥0.9 | красивые таблицы в бенчмарках |

### Шаг 3: Проверить установку
```bash
python src/wep/wep_crypto.py    # самотест WEP
python src/wpa/wpa_crypto.py    # самотест WPA2
python lab/aes_demo.py --test   # NIST тест-векторы AES
```

Ожидаемый вывод:
```
[PASS] key=000102030... pt=00112233...
[PASS] key=2b7e1516... pt=3243f6a8...
All test vectors passed!
```

---

## 4. Бенчмарк WEP — пошаговый запуск

### 4.1 Генерация тестового захвата

```bash
python src/wep/wep_gen.py --key hello --frames 100
```

**Параметры:**
- `--key` — WEP-ключ (5 символов ASCII = 40-бит, или 13 = 104-бит)
- `--frames` — количество зашифрованных фреймов
- `--out` — путь для сохранения (по умолчанию: `data/captures/test_wep.wep`)

**Вывод:**
```
[+] Generated 100 WEP-encrypted frames
    Key (hex): 68656c6c6f  (40-bit)
    Saved to:  data/captures/test_wep.wep
    Metadata:  data/captures/test_wep_meta.json
```

### 4.2 Запуск брутфорса — режим wordlist

```bash
python src/wep/wep_crack.py --mode wordlist --wordlist data/wordlists/passwords.txt
```

**Ожидаемый вывод:**
```
==================================================
  WEP Cracker — 100 frames, key=40-bit
==================================================

Trying: 100%|████████████| 51/51 [00:00<00:00, 95234.2key/s]

==================================================
  [+] KEY FOUND!
      Hex:    68656c6c6f
      ASCII:  hello
  Attempted:  51 keys
  Time:       0.001s
  Speed:      89,412 keys/s
  Mode:       wordlist
==================================================
```

### 4.3 Запуск брутфорса — режим numeric (4 цифры)

```bash
python src/wep/wep_gen.py --key "12345" --frames 50
python src/wep/wep_crack.py --mode numeric --digits 5
```

Ожидаемое время: ~0.1–0.5 секунды для 5-значного числового ключа.

### 4.4 Автоматический запуск (generate + crack)

```bash
python src/wep/wep_crack.py --gen-key hello --mode wordlist
```

---

## 5. Бенчмарк WPA/WPA2 — пошаговый запуск

### 5.1 Генерация handshake захвата

```bash
python src/wpa/wpa_gen.py --password hunter2 --ssid HomeNetwork --protocol WPA2
```

Создаёт `data/captures/test_wpa2.json`:
```json
{
  "protocol": "WPA2",
  "ssid": "HomeNetwork",
  "aa": "a1b2c3d4e5f6",
  "sa": "112233445566",
  "anonce": "...",
  "snonce": "...",
  "eapol_frame": "...",
  "mic": "..."
}
```

> ⚠️ Поле `_target_password_for_testing` добавлено только для учебных целей. В реальном захвате пароль не хранится!

### 5.2 Запуск словарной атаки

```bash
python src/wpa/wpa_crack.py --capture data/captures/test_wpa2.json \
                             --wordlist data/wordlists/passwords.txt
```

**Ожидаемый вывод:**
```
=======================================================
  WPA Cracker — WPA2
=======================================================
  SSID:       HomeNetwork
  Protocol:   WPA2
  Wordlist:   51 passwords
  MIC target: 3f8a1b2c...

  Estimated speed: 420 passwords/s
  Estimated time:  0.1s for full wordlist

Cracking: 100%|████| 32/51 [00:00<00:00, 398.2pwd/s]

=======================================================
  [+] PASSWORD FOUND!
      → 'hunter2'

  Tried:    32 candidates
  Time:     0.08s
  Speed:    400 passwords/s
  Protocol: WPA2
=======================================================
```

### 5.3 Автоматический запуск (generate + crack)

```bash
python src/wpa/wpa_crack.py --gen-handshake --password hunter2 --ssid HomeNet
```

### 5.4 Тест WPA (TKIP)

```bash
python src/wpa/wpa_crack.py --gen-handshake --protocol WPA --password dragon
```

---

## 6. Сравнительный бенчмарк

### 6.1 Быстрый запуск (2 сек на тест)

```bash
python src/benchmark/benchmark.py --quick
```

### 6.2 Стандартный запуск (3 сек на тест)

```bash
python src/benchmark/benchmark.py
```

### 6.3 Полный запуск (10 сек — точные результаты)

```bash
python src/benchmark/benchmark.py --full
```

**Пример вывода:**
```
=================================================================
  WiFi Security Educational Benchmarks
  WEP vs WPA vs WPA2 Attack Speed Comparison
=================================================================

[*] Benchmarking WEP (RC4 + CRC32)...
    Attempts:  823,419
    Time:      3.00s
    Speed:     274,473 keys/s

[*] Benchmarking WPA/TKIP (HMAC-MD5 MIC)...
    Speed:     1,240,321 MIC-checks/s

[*] Benchmarking WPA2 (full PBKDF2 pipeline)...
    Speed:     412 passwords/s     ← PBKDF2 ограничивает

[*] Benchmarking PBKDF2-SHA1 alone...
    Speed:     418 PMKs/s

=================================================================
  BENCHMARK SUMMARY
╭─────────────┬────────────────┬───────────────┬──────────────────────╮
│ Protocol    │   Speed (keys/s)│ Test time (s) │ Risk                 │
├─────────────┼────────────────┼───────────────┼──────────────────────┤
│ WEP         │        274,473 │           3.0 │ CRITICAL (broken)    │
│ WPA         │      1,240,321 │           3.0 │ HIGH (deprecated)    │
│ WPA2        │            412 │           5.0 │ LOW (if pwd strong)  │
╰─────────────┴────────────────┴───────────────┴──────────────────────╯

  Key takeaways:
  • WEP  can be cracked in seconds — completely broken
  • WPA  TKIP is deprecated — avoid
  • WPA2 PBKDF2 slows attacks to ~300-2000/s — use strong passwords!
=================================================================
```

### 6.4 Только WEP или только WPA2

```bash
python src/benchmark/benchmark.py --wep-only
python src/benchmark/benchmark.py --wpa2-only
```

---

## 7. Формат входных данных

### WEP захват (.wep)
Бинарный файл с заголовком:
```
Байты 0-3:   Magic "WEP\x01"
Байт  4:     Длина ключа (5 или 13)
Байты 5-8:   Количество фреймов (uint32 LE)
Далее:       [frame_len (2 байта) | frame_data]*
```

Каждый фрейм: `IV (3 байта) | KeyID (1 байт) | RC4-ciphertext`

### WPA2 захват (.json)
```json
{
  "protocol":    "WPA2",
  "ssid":        "NetworkName",
  "aa":          "aabbccddeeff",     ← MAC точки доступа (hex)
  "sa":          "112233445566",     ← MAC клиента (hex)
  "anonce":      "...",              ← 32 байта hex (от AP)
  "snonce":      "...",              ← 32 байта hex (от клиента)
  "eapol_frame": "...",              ← EAPOL фрейм (MIC обнулён!)
  "mic":         "..."               ← захваченный MIC (16 байт hex)
}
```

---

## 8. Python-концепции в проекте

| Концепция | Где используется | Файл |
|---|---|---|
| `bytes` / `bytearray` | Вся криптография работает с байтами | wep_crypto.py |
| List comprehensions | RC4 KSA/PRGA, state matrix | wep_crypto.py, aes_demo.py |
| Generator / `itertools.product` | Брутфорс без хранения в памяти | wep_crack.py |
| `struct.pack/unpack` | Бинарный формат файла | wep_gen.py |
| `hashlib.pbkdf2_hmac` | Derivation of PMK | wpa_crypto.py |
| `hmac.new` | MIC вычисление | wpa_crypto.py |
| `time.perf_counter` | Точное измерение времени | benchmark.py |
| `argparse` | CLI для всех скриптов | все файлы |
| `os.urandom` | Криптографически стойкие случайные байты | wpa_gen.py |
| Type hints | `bytes`, `list[int]`, `tuple[bool, bytes]` | все файлы |

---

## 9. Типичные ошибки и решения

| Ошибка | Причина | Решение |
|---|---|---|
| `FileNotFoundError: test_wep.wep` | Захват не создан | Запустить `wep_gen.py` сначала |
| `ValueError: WEP key must be 5 or 13 chars` | Неверная длина ключа | Использовать ровно 5 или 13 символов |
| `ModuleNotFoundError: tqdm` | Не установлены зависимости | `pip install -r requirements.txt` |
| Очень медленно (WPA2) | PBKDF2 CPU-bound | Это нормально. GPU в 1000x быстрее |
| MIC не совпадает | Неверный SSID в атаке | SSID чувствителен к регистру! |

---

## 10. Вопросы для самопроверки

1. Почему IV длиной 24 бита недостаточна для WEP?
2. Что такое PMK и зачем нужен SSID для его вычисления?
3. Почему атака на WPA2 медленнее чем на WEP в этом проекте?
4. Как PBKDF2 защищает от brute-force атак?
5. Что произойдёт если два клиента используют один и тот же SNonce?
6. Почему WPA2-Enterprise безопаснее WPA2-Personal?
