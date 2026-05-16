# WiFi Security Educational Toolkit

> **Учебный проект** по криптографии беспроводных сетей.  
> Демонстрирует атаки на WEP, WPA и WPA2 в контролируемой среде.  
> ⚠️ Использовать **только на своих сетях** или в рамках явно разрешённого тестирования.

---

## Содержание

1. [Что делает проект](#что-делает-проект)
2. [Структура директорий](#структура-директорий)
3. [Установка](#установка)
4. [Быстрый старт](#быстрый-старт)
5. [Пошаговые сценарии](#пошаговые-сценарии)
   - [Сценарий A — WEP: генерация и взлом](#сценарий-a--wep-генерация-и-взлом)
   - [Сценарий B — WPA2: генерация и взлом](#сценарий-b--wpa2-генерация-и-взлом)
   - [Сценарий C — Бенчмарк](#сценарий-c--бенчмарк)
   - [Сценарий D — Лабораторная по AES](#сценарий-d--лабораторная-по-aes)
   - [Сценарий E — Захват с реального интерфейса](#сценарий-e--захват-с-реального-интерфейса)
6. [Описание каждого файла](#описание-каждого-файла)
7. [Что показывают графики бенчмарка](#что-показывают-графики-бенчмарка)
8. [Технические детали протоколов](#технические-детали-протоколов)

---

## Что делает проект

Проект реализует **полный цикл атак** на три поколения WiFi-шифрования:

| Протокол | Шифр | Уязвимость |
|---|---|---|
| **WEP** | RC4 + CRC-32 | Короткий IV (24 бит), слабые ключи RC4  |
| **WPA/TKIP** | RC4 + HMAC-MD5 | Устаревший, TKIP deprecated  |
| **WPA2/CCMP** | AES-128 + HMAC-SHA1 | Только слабые пароли  |

Каждый модуль содержит: **генератор** тестовых данных -> **взломщик** -> **отчёт** с метриками.  
Дополнительно: лабораторная по внутреннему устройству AES и захват фреймов с реального интерфейса.

---

## Структура директорий

```
wifi_security_project/
│
├── README.md                   <- этот файл
├── requirements.txt            <- зависимости Python
│
├── src/                        <- основные криптографические модули
│   ├── __init__.py
│   │
│   ├── wep/                    <- WEP: RC4 + CRC-32
│   │   ├── __init__.py
│   │   ├── wep_crypto.py       <- примитивы: RC4 KSA/PRGA, ICV, encrypt/decrypt
│   │   ├── wep_gen.py          <- генератор .wep-файла с зашифрованными фреймами
│   │   └── wep_crack.py        <- взломщик: wordlist / numeric / alphanum
│   │
│   ├── wpa/                    <- WPA/WPA2: PBKDF2 → PRF → HMAC
│   │   ├── __init__.py
│   │   ├── wpa_crypto.py       <- PMK, PTK, KCK, MIC, verify_password
│   │   ├── wpa_gen.py          <- генератор 4-way handshake (.json)
│   │   └── wpa_crack.py        <- словарная атака на handshake
│   │
│   └── benchmark/              <- сравнение скоростей атак
│       ├── __init__.py
│       └── benchmark.py        <- 4 бенчмарка + итоговая таблица
│
├── lab/                        <- лабораторные работы
│   ├── __init__.py
│   ├── aes_demo.py             <- AES-128 изнутри: SubBytes, ShiftRows, MixColumns
│   └── aes_crack.py            <- учебная атака WPA2 + анализ стойкости паролей
│
├── data/
│   ├── wordlists/
│   │   └── passwords.txt       <- словарь из 50 популярных паролей
│   └── captures/
│       ├── test_wep.wep        <- готовый WEP-захват (ключ: "hello")
│       ├── test_wep_meta.json  <- метаданные WEP-захвата
│       └── test_wpa2.json      <- готовый WPA2-handshake (пароль: "dragon")
│
├── docs/
│   ├── lab_guide.md            <- подробное руководство по лабораторной (RU)
│   └── benchmark_guide.md      <- руководство по бенчмарку (RU)
│
└── capture_real.py             <- захват фреймов с реального WiFi-интерфейса
```

---

## Установка

### Требования

- Python 3.10+
- Linux (для `capture_real.py` — обязательно; остальное работает на macOS/Windows)
- Для реального захвата: WiFi-адаптер с поддержкой monitor mode + права root

### Шаг 1 — Клонировать / распаковать проект
### Шаг 2 — Создать виртуальное окружение (рекомендуется)

```bash
python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS
# .venv\Scripts\activate         # Windows
```

### Шаг 3 — Установить зависимости

```bash
pip install -r requirements.txt
```

### Шаг 4 — Проверить установку

```bash
python -c "from src.wep.wep_crypto import wep_encrypt; print('OK')"
```

---

## Быстрый старт

Все команды запускать из корня `wifi_security_project/`:

```bash
# 1. Взломать готовый WEP-захват (ключ "hello" уже в словаре)
python src/wep/wep_crack.py --mode wordlist

# 2. Взломать готовый WPA2-handshake (пароль "dragon" уже в словаре)
python src/wpa/wpa_crack.py

# 3. Запустить бенчмарк
python src/benchmark/benchmark.py --quick

# 4. Запустить лабораторную по AES
python lab/aes_crack.py --auto
```

---

## Пошаговые сценарии

### Сценарий A — WEP: генерация и взлом

#### Шаг A1 — Изучить WEP-криптографию

```bash
python src/wep/wep_crypto.py
```

Запускает встроенный self-test: шифрует и дешифрует тестовое сообщение, показывает hex-дамп фрейма. Демонстрирует, что неверный ключ не проходит CRC-верификацию.

#### Шаг A2 — Сгенерировать WEP-захват

```bash
# Стандартный (ключ "hello", 100 фреймов)
python src/wep/wep_gen.py

# Свой ключ и количество фреймов
python src/wep/wep_gen.py --key hello --frames 200 --out data/captures/my_wep.wep
```

Создаёт бинарный `.wep`-файл и JSON-метаданные рядом с ним.

#### Шаг A3 — Взломать по словарю (самый быстрый способ)

```bash
python src/wep/wep_crack.py --mode wordlist --wordlist data/wordlists/passwords.txt
```

Ожидаемый вывод:
```
WEP Cracker — 100 frames, key=40-bit
══════════════════════════════════════════════════
  [+] KEY FOUND!
      Hex:    68656c6c6f
      ASCII:  hello
  Attempted:  10 keys
  Time:       0.001s
  Speed:      9,821 keys/s
```

#### Шаг A4 — Цифровой перебор

```bash
# Попробовать все 4-значные числовые ключи (10 000 комбинаций)
python src/wep/wep_crack.py --mode numeric --digits 4

# Сначала сгенерировать захват с числовым ключом, потом взломать
python src/wep/wep_gen.py --key 12345
python src/wep/wep_crack.py --mode numeric --digits 5
```

#### Шаг A5 — Алфавитно-цифровой перебор (демо, медленно)

```bash
python src/wep/wep_crack.py --mode alphanum --alength 3
```

> ⚠️ При `--alength 4` уже 62⁴ ≈ 14 млн комбинаций. Только для демо.

---

### Сценарий B — WPA2: генерация и взлом

#### Шаг B1 — Изучить криптографию WPA2

```bash
python src/wpa/wpa_crypto.py
```

Выводит вычисленные PMK, KCK и скорость (PMK/с) на вашей машине.

#### Шаг B2 — Сгенерировать handshake

```bash
# Стандартный (пароль "hunter2", SSID "HomeNetwork")
python src/wpa/wpa_gen.py

# Свой пароль (должен быть в словаре для успешного взлома)
python src/wpa/wpa_gen.py --password dragon --ssid MyNetwork --out data/captures/my_wpa2.json

# WPA (TKIP) вместо WPA2
python src/wpa/wpa_gen.py --protocol WPA --password secret
```

#### Шаг B3 — Взломать

```bash
# Использовать готовый захват
python src/wpa/wpa_crack.py

# Сгенерировать и взломать за один шаг
python src/wpa/wpa_crack.py --gen-handshake --password hunter2 --ssid HomeNetwork

# Взломать свой захват
python src/wpa/wpa_crack.py --capture data/captures/my_wpa2.json --wordlist data/wordlists/passwords.txt

# С подробным выводом каждой попытки (очень медленно!)
python src/wpa/wpa_crack.py --verbose
```

Ожидаемый вывод при успехе:
```
═══════════════════════════════════════════════════════
  WPA Cracker — WPA2
═══════════════════════════════════════════════════════
  SSID:     HomeNetwork
  Wordlist: 50 passwords
  MIC:      a8c70ee63c932f65...
  Estimated speed: 487 passwords/s

  [+] PASSWORD FOUND!
      → 'dragon'

  Tried:    10 candidates
  Time:     0.02s
  Speed:    487 passwords/s
```

---

### Сценарий C — Бенчмарк

#### Шаг C1 — Быстрый тест (2 сек на каждый протокол)

```bash
python src/benchmark/benchmark.py --quick
```

#### Шаг C2 — Стандартный тест (3 сек)

```bash
python src/benchmark/benchmark.py
```

#### Шаг C3 — Точный тест (10 сек, для отчёта)

```bash
python src/benchmark/benchmark.py --full
```

#### Шаг C4 — Тест только WEP или только WPA2

```bash
python src/benchmark/benchmark.py --wep-only
python src/benchmark/benchmark.py --wpa2-only
```

Пример итоговой таблицы:
```
╭────────────────┬───────────────────┬─────────────────╮
│ Protocol       │   Speed (keys/s)  │ Risk            │
├────────────────┼───────────────────┼─────────────────┤
│ WEP            │         523,847   │ CRITICAL        │
│ WPA            │          38,211   │ HIGH            │
│ WPA2           │             521   │ LOW (if strong) │
│ WPA2-PBKDF2    │             498   │ —               │
╰────────────────┴───────────────────┴─────────────────╯
```

---

### Сценарий D — Лабораторная по AES

#### Шаг D1 — Посмотреть AES изнутри (нормальный режим)

```bash
python lab/aes_demo.py
```

Выводит все 10 раундов AES-128 в hex: исходный State, после SubBytes, ShiftRows, MixColumns, AddRoundKey.

#### Шаг D2 — Подробный вывод каждого раунда

```bash
python lab/aes_demo.py --verbose
```

#### Шаг D3 — Проверить на NIST-векторах

```bash
python lab/aes_demo.py --test
```

Сравнивает вывод с официальными тест-векторами NIST FIPS-197. Должно быть `ALL TESTS PASSED`.

#### Шаг D4 — Учебная атака на WPA2 (пошаговый вывод)

```bash
# Автоматически: сгенерировать handshake с паролем "dragon" и взломать
python lab/aes_crack.py --auto

# Свой пароль (должен быть в словаре)
python lab/aes_crack.py --auto --password hunter2 --ssid CampusNet

# Атака на существующий захват
python lab/aes_crack.py --capture data/captures/test_wpa2.json
```

Для первых 5 кандидатов выводит таблицу с промежуточными значениями PMK и MIC — так видно, почему неверные пароли не совпадают.

#### Шаг D5 — Анализ сложности паролей

```bash
python lab/aes_crack.py --complexity-test
```

Выводит таблицу: длина пароля × набор символов → количество комбинаций → время перебора на Python и GPU.

---

### Сценарий E — Захват с реального интерфейса

> **Требуется:** Linux, root-права, WiFi-адаптер с monitor mode.  
> **Только для своих сетей!**

#### Шаг E1 — Перевести интерфейс в monitor mode

```bash
# Вариант 1 — через aircrack-ng (рекомендуется)
sudo airmon-ng start wlan0
# Интерфейс может переименоваться в wlan0mon

# Вариант 2 — вручную
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
```

#### Шаг E2 — Сканировать сети в эфире

```bash
sudo python capture_real.py scan --iface wlan0mon --duration 20
```

Выведет таблицу с SSID, BSSID, каналом и типом защиты. WEP-сети помечены красным.

#### Шаг E3а — Захватить WEP-фреймы

```bash
# Нужна активная WEP-сеть с трафиком
# Переключить на нужный канал (узнать из scan):
sudo iw dev wlan0mon set channel 6

sudo python capture_real.py wep \
    --iface wlan0mon \
    --ssid MyWepNetwork \
    --count 200 \
    --out data/captures/real_wep.wep
```

После захвата — взломать:
```bash
python src/wep/wep_crack.py \
    --capture data/captures/real_wep.wep \
    --mode wordlist \
    --wordlist data/wordlists/passwords.txt
```

#### Шаг E3б — Захватить WPA2-handshake

```bash
# Способ 1: ждать естественного подключения клиента
sudo python capture_real.py wpa \
    --iface wlan0mon \
    --ssid HomeNetwork \
    --timeout 120

# Способ 2: принудить клиента переподключиться (deauth)
# ТОЛЬКО на своей сети!
sudo python capture_real.py wpa \
    --iface wlan0mon \
    --ssid HomeNetwork \
    --deauth \
    --timeout 60
```

После захвата — взломать:
```bash
python src/wpa/wpa_crack.py \
    --capture data/captures/real_wpa2.json \
    --wordlist data/wordlists/passwords.txt
```

#### Шаг E4 — Бенчмарк на реальных данных

```bash
# Прогоняет синтетические бенчмарки + атаку на захваченный handshake
sudo python capture_real.py bench \
    --capture data/captures/real_wpa2.json \
    --wordlist data/wordlists/passwords.txt \
    --duration 5
```

#### Шаг E5 — Вернуть интерфейс в managed mode

```bash
# Если использовался airmon-ng:
sudo airmon-ng stop wlan0mon

# Если вручную:
sudo ip link set wlan0mon down
sudo iw wlan0mon set type managed
sudo ip link set wlan0mon up
```

---

## Описание каждого файла

### `src/wep/wep_crypto.py`

**Назначение:** низкоуровневые криптографические примитивы WEP.

| Функция | Что делает |
|---|---|
| `rc4_ksa(key)` | Key Scheduling Algorithm — инициализирует перестановку S[256] |
| `rc4_prga(S, length)` | Генерирует `length` байт псевдослучайного потока |
| `rc4(key, data)` | Полный RC4: KSA → PRGA → XOR с данными |
| `compute_icv(plaintext)` | CRC-32 от plaintext, little-endian 4 байта |
| `verify_icv(plaintext, icv)` | Сравнивает вычисленный CRC с полученным |
| `wep_encrypt(iv, key, plaintext)` | Возвращает `IV‖KeyID‖RC4(IV‖key, plaintext‖ICV)` |
| `wep_decrypt(key, frame)` | Расшифровывает фрейм, возвращает `(ok, plaintext)` |
| `random_iv()` | `os.urandom(3)` — как настоящая AP |
| `key_from_passphrase(s)` | ASCII → bytes, проверяет длину (5 или 13 байт) |

**Запуск:** `python src/wep/wep_crypto.py`

---

### `src/wep/wep_gen.py`

**Назначение:** генерирует `.wep`-файл — симуляцию перехваченного трафика.

**Формат файла (бинарный, little-endian):**
```
Заголовок: magic(4) | key_len(1) | num_frames(4)
Фрейм:     frame_len(2) | IV(3) | KeyID(1) | ciphertext(N)
```

| Функция | Что делает |
|---|---|
| `generate_capture(key, num_frames, path)` | Создаёт `.wep` + JSON-метаданные рядом |
| `read_capture(path)` | Читает `.wep`, возвращает `(key_len, [frames])` |

**Запуск:**
```bash
python src/wep/wep_gen.py --key hello --frames 100
python src/wep/wep_gen.py --key 12345 --frames 50 --out data/captures/numeric.wep
```

---

### `src/wep/wep_crack.py`

**Назначение:** атакует `.wep`-захват тремя методами.

**Логика проверки ключа:**
1. Взять первый (и второй для подтверждения) фрейм из захвата
2. Попробовать расшифровать кандидатом
3. Если CRC-32 совпал → ключ найден (ложное срабатывание ≈ 1/2³²)

| Режим | Команда | Keyspace |
|---|---|---|
| Wordlist | `--mode wordlist` | Все строки файла |
| Numeric | `--mode numeric --digits N` | 10ᴺ |
| Alphanum | `--mode alphanum --alength N` | 62ᴺ |

**Запуск:**
```bash
python src/wep/wep_crack.py --mode wordlist
python src/wep/wep_crack.py --mode numeric --digits 5
python src/wep/wep_crack.py --gen-key hello  # генерирует захват и сразу взламывает
```

---

### `src/wpa/wpa_crypto.py`

**Назначение:** полная криптографическая цепочка WPA/WPA2.

| Функция | Что делает |
|---|---|
| `compute_pmk(password, ssid)` | PBKDF2-HMAC-SHA1(pwd, ssid, 4096, 32) → 32 байта |
| `compute_ptk(pmk, aa, sa, anonce, snonce)` | PRF-512 → 64 байта PTK |
| `ptk_split(ptk)` | → `(KCK[0:16], KEK[16:32], TK[32:48])` |
| `compute_mic_wpa2(kck, eapol)` | HMAC-SHA1(KCK, EAPOL)[0:16] |
| `compute_mic_wpa(kck, eapol)` | HMAC-MD5(KCK, EAPOL) |
| `zero_mic_in_eapol(frame)` | Обнуляет байты [81:97] — для вычисления MIC |
| `verify_password(...)` | Полная проверка пароля за один вызов |

**Запуск:** `python src/wpa/wpa_crypto.py` (выводит скорость PMK/с)

---

### `src/wpa/wpa_gen.py`

**Назначение:** создаёт синтетический 4-way handshake в JSON.

**Что содержит JSON-файл:**
```json
{
  "protocol":    "WPA2",
  "ssid":        "HomeNetwork",
  "aa":          "<AP MAC hex>",
  "sa":          "<Client MAC hex>",
  "anonce":      "<32 байта hex>",
  "snonce":      "<32 байта hex>",
  "eapol_frame": "<EAPOL Message 2, MIC обнулён>",
  "mic":         "<16 байт hex — эталон для сравнения>"
}
```

**Запуск:**
```bash
python src/wpa/wpa_gen.py --password dragon --ssid HomeNetwork
python src/wpa/wpa_gen.py --protocol WPA --password secret
```

---

### `src/wpa/wpa_crack.py`

**Назначение:** словарная атака на WPA2-handshake.

**Алгоритм для каждого кандидата:**
```
password  →[PBKDF2]→  PMK
PMK + {aa, sa, anonce, snonce}  →[PRF-512]→  PTK
PTK[0:16]  →  KCK
KCK + eapol_frame  →[HMAC-SHA1]→  MIC_calc
MIC_calc == MIC_captured  ?  → найдено : следующий
```

**Запуск:**
```bash
python src/wpa/wpa_crack.py
python src/wpa/wpa_crack.py --gen-handshake --password hunter2
python src/wpa/wpa_crack.py --capture data/captures/test_wpa2.json --verbose
```

---

### `src/benchmark/benchmark.py`

**Назначение:** измеряет скорость четырёх атак и выводит сравнительную таблицу.

| Функция | Что измеряет | Типичная скорость |
|---|---|---|
| `benchmark_wep(duration)` | RC4 + CRC32 перебор | 100k–1M кл/с |
| `benchmark_wpa(duration)` | HMAC-MD5 MIC-проверки | 10k–50k чек/с |
| `benchmark_wpa2_full(duration)` | PBKDF2 + PTK + MIC полностью | 300–2000 пар/с |
| `benchmark_pbkdf2(duration)` | Только PBKDF2-SHA1 × 4096 | 300–800 вычислений/с |

**Запуск:**
```bash
python src/benchmark/benchmark.py
python src/benchmark/benchmark.py --quick    # 2s на тест
python src/benchmark/benchmark.py --full     # 10s на тест
python src/benchmark/benchmark.py --wep-only
python src/benchmark/benchmark.py --wpa2-only
```

---

### `lab/aes_demo.py`

**Назначение:** пошаговая демонстрация AES-128 на чистом Python.

**Реализованные операции:**

| Операция | Суть |
|---|---|
| `sub_bytes(state)` | Нелинейная подстановка через S-Box (GF(2⁸)) |
| `shift_rows(state)` | Сдвиг строк матрицы на 0/1/2/3 позиции |
| `mix_columns(state)` | Линейное перемешивание столбцов в GF(2⁸) |
| `add_round_key(state, rk)` | XOR состояния с раундовым ключом |
| `key_expansion(key)` | Расширение 128-битного ключа в 11 раундовых ключей |
| `aes_encrypt(key, block)` | Полное шифрование: 1 начальный + 9 полных + 1 финальный раунд |

**Запуск:**
```bash
python lab/aes_demo.py                # стандартный демо-прогон
python lab/aes_demo.py --verbose      # с выводом каждого раунда
python lab/aes_demo.py --test         # проверка на NIST FIPS-197 векторах
```

---

### `lab/aes_crack.py`

**Назначение:** учебная атака на WPA2 с педагогическим выводом.

**Режимы:**

| Флаг | Что делает |
|---|---|
| `--auto` | Генерирует handshake и взламывает, показывает PMK/MIC для первых 5 кандидатов |
| `--complexity-test` | Таблица: длина × charset → keyspace → время на CPU/GPU |
| `--capture PATH` | Атакует готовый JSON-файл |

**Запуск:**
```bash
python lab/aes_crack.py --auto
python lab/aes_crack.py --auto --password hunter2 --ssid CampusNet
python lab/aes_crack.py --complexity-test
```

---

### `capture_real.py`

**Назначение:** захват реальных фреймов с живого WiFi-интерфейса.

> Требует root и monitor mode. Выходные файлы полностью совместимы с `wep_crack.py` и `wpa_crack.py`.

| Режим | Команда | Что делает |
|---|---|---|
| `scan` | `sudo python capture_real.py scan --iface wlan0mon` | Сканирует AP, показывает тип защиты |
| `wep` | `sudo python capture_real.py wep --iface wlan0mon --ssid X` | Перехватывает Data-фреймы WEP → `.wep` |
| `wpa` | `sudo python capture_real.py wpa --iface wlan0mon --ssid X` | Захватывает 4-way handshake → `.json` |
| `bench` | `sudo python capture_real.py bench --capture FILE` | Бенчмарки + атака на захват |

**Ключевые опции:**
- `--count N` — сколько WEP-фреймов собрать (по умолчанию 200)
- `--timeout N` — максимальное время ожидания в секундах
- `--deauth` — отправить deauth-пакеты для принудительного переподключения клиента
- `--key-len 5|13` — ожидаемая длина WEP-ключа (WEP-40 или WEP-104)

---

## Что показывают графики бенчмарка

Бенчмарк выводит **количество проверенных ключей/паролей в секунду** — это главная метрика практической стойкости к перебору.

### Почему WEP в 1000× быстрее WPA2

**WEP:** проверка одного ключа = одно RC4-расшифрование + один CRC-32.  
RC4 и CRC — простые операции, выполняемые за микросекунды.

**WPA2:** проверка одного пароля = PBKDF2-HMAC-SHA1 с **4096 итерациями**.  
4096 итераций — не ошибка, а намеренное замедление (key stretching).  
Каждая итерация — SHA1-вычисление. Итого ~4096 SHA1 на один пароль.

### Интерпретация чисел

```
WEP:  500 000 кл/с  → 10^8 keyspace перебирается за 3 минуты
WPA2:     500 пар/с  → 10^8 keyspace — 231 день на Python
                      → 100 секунд на GPU (hashcat, 10^6 пар/с)
```

### Вывод для практики

| Длина пароля WPA2 | Charset | GPU-время (1M пар/с) |
|---|---|---|
| 8 символов | строчные | ~2 часа |
| 8 символов | строчные+цифры | ~27 часов |
| 12 символов | строчные+цифры | ~3 700 лет |
| 16 символов | любой | тепловая смерть Вселенной |

**Итог:** WPA2 безопасен если пароль ≥12 случайных символов из смешанного набора. Длина важнее сложности набора.

---

## Технические детали протоколов

### WEP — почему сломан

```
Фрейм: [ IV (3B) | KeyID (1B) | RC4(IV‖Key, Plaintext‖ICV) ]
```

1. **24-битный IV** → 2²⁴ = 16 777 216 уникальных IV. При активной сети повторяются через ~5000 фреймов (парадокс дней рождения).
2. **Слабые ключи RC4:** IV вида `(A+3, 255, X)` приводят к тому, что первые байты keystream коррелируют с байтами ключа → атака FMS/KoreK восстанавливает ключ из ~40 000 фреймов.
3. **CRC-32 линеен:** зная plaintext-XOR-маску, можно изменить ciphertext так, чтобы ICV остался верным → bit-flipping атаки.

### WPA2 — почему устойчив структурно

```
Password + SSID  →[PBKDF2-SHA1 × 4096]→  PMK (32B)
PMK + ANonce + SNonce + AP_MAC + Client_MAC  →[PRF-512]→  PTK (64B)
PTK[0:16] = KCK  →[HMAC-SHA1(KCK, EAPOL_msg2)]→  MIC (16B)
```

- AES-128 в режиме CCMP не имеет известных практических атак.
- PBKDF2 с 4096 итерациями намеренно замедляет брутфорс.
- Единственный вектор: угадать **пароль** → пересчитать PMK → PTK → MIC → сравнить.
- Защита: длинный случайный пароль + уникальный SSID.
