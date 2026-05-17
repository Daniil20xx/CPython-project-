# WiFi Security Lab

Учебный проект по безопасности WiFi-сетей.  
Демонстрирует атаки на WEP, WPA и WPA2, анализ AES и сравнительный брутфорс.

> ⚠️ **Только для своих сетей и учебных целей. Перехват чужого трафика — уголовно наказуемо.**

---

## Состав проекта

```
wifi_lab/
│
├── README.md                     ← этот файл
│
├── crypto_utils.py               ← криптографические примитивы (RC4, WEP, PBKDF2, WPA2)
├── generate_test_data.py         ← генератор тестовых .wep и .json файлов
├── capture_traffic.py            ← захват реального трафика с WiFi-интерфейса
├── bruteforce_benchmark.py       ← брутфорс WEP/WPA/WPA2 + 4 метрики + графики
├── lab_aes_wpa2.py               ← лабораторная по AES + статистика + графики
│
└── data/
    ├── wordlists/
    │   └── passwords.txt         ← 50 реальных паролей
    └── captures/
        ├── test_wep_40.wep       ← WEP-40 захват (ключ: hello)
        ├── test_wep_104.wep      ← WEP-104 захват
        ├── test_wpa.json         ← WPA/TKIP handshake (пароль: dragon)
        ├── test_wpa2.json        ← WPA2/CCMP handshake (пароль: dragon)
        └── test_wpa2_hard.json   ← WPA2 handshake (пароль: hunter2)
```

---

## Установка

**Требования:** Python 3.10+

```bash
# Обязательные (для брутфорса и лабораторной):
pip install matplotlib numpy

# Опционально (для захвата с реального интерфейса):
pip install scapy

# Опционально (для AES-шифрования в lab_aes_wpa2.py):
pip install cryptography
```

---

## Быстрый старт — 3 команды

```bash
# 1. Сгенерировать тестовые файлы
python generate_test_data.py

# 2. Брутфорс WEP/WPA/WPA2 + графики
python bruteforce_benchmark.py

# 3. Лабораторная по AES + графики
python lab_aes_wpa2.py
```

После запуска появятся:
- `benchmark_results.png` — 4 сравнительных графика WEP vs WPA vs WPA2
- `lab_aes_results.png` — 4 графика анализа AES и сложности паролей

---

## Описание файлов

---

### `crypto_utils.py`

**Назначение:** общие криптографические примитивы. Импортируется всеми остальными модулями. Самостоятельно не запускается.

**Что реализовано:**

| Функция | Что делает |
|---|---|
| `rc4_ksa(key)` | Key Scheduling Algorithm — перемешивает S[256] по ключу |
| `rc4_prga(S, length)` | Генерирует псевдослучайный поток байт |
| `rc4(key, data)` | Полный RC4: KSA → PRGA → XOR |
| `wep_encrypt(iv, key, plaintext)` | Шифрует WEP-фрейм: `IV‖KeyID‖RC4(IV‖key, data‖CRC32)` |
| `wep_decrypt(key, frame)` | Расшифровывает фрейм, проверяет CRC-32 |
| `compute_pmk(password, ssid)` | PBKDF2-SHA1(pwd, ssid, 4096, 32) → PMK |
| `compute_ptk(pmk, aa, sa, anonce, snonce)` | PRF-512 → PTK (64 байта) |
| `compute_mic_wpa(kck, eapol)` | HMAC-MD5(KCK, EAPOL) → MIC |
| `compute_mic_wpa2(kck, eapol)` | HMAC-SHA1(KCK, EAPOL)[0:16] → MIC |
| `verify_password(...)` | Полная цепочка: пароль → сравнение MIC |

---

### `generate_test_data.py`

**Назначение:** генерирует все тестовые файлы для брутфорса и лабораторной.

**Формат WEP-файла (бинарный, .wep):**
```
[magic=WEP\x01][key_len:uint8][n_frames:uint32]
  для каждого фрейма: [frame_len:uint16][IV(3)][KeyID(1)][RC4-ciphertext]
```

**Формат handshake-файла (JSON, .json):**
```json
{
  "protocol":    "WPA2",
  "ssid":        "HomeNetwork",
  "aa":          "aabbccddeeff",     // AP MAC hex
  "sa":          "112233445566",     // Client MAC hex
  "anonce":      "...",              // 32 байта hex (AP nonce)
  "snonce":      "...",              // 32 байта hex (Client nonce)
  "eapol_frame": "...",              // EAPOL Message 2, MIC=0000...
  "mic":         "...",              // эталонный MIC для сравнения
  "_password":   "dragon"            // только для тестов!
}
```

**Пошаговое воспроизведение:**

```bash
# Шаг 1. Сгенерировать всё с настройками по умолчанию:
python generate_test_data.py

# Шаг 2. Другой WEP-ключ и количество фреймов:
python generate_test_data.py --wep-key hello --wep-frames 500

# Шаг 3. Другой пароль WPA2 (должен быть в passwords.txt!):
python generate_test_data.py --wpa-password hunter2 --ssid MyNetwork

# Шаг 4. Проверить созданные файлы:
ls -lh data/captures/
# test_wep_40.wep      ~10 KB (200 фреймов)
# test_wep_104.wep     ~10 KB
# test_wpa.json        ~1 KB
# test_wpa2.json       ~1 KB
# test_wpa2_hard.json  ~1 KB
```

---

### `capture_traffic.py`

**Назначение:** захват реального WiFi-трафика через Scapy. Сохраняет в форматы, совместимые с брутфорсом и лабораторной.

> Требует: Linux + root + WiFi-адаптер с monitor mode + `pip install scapy`

**Пошаговое воспроизведение:**

```bash
# Шаг 1. Включить monitor mode:
sudo ip link set wlan0 down
sudo iw wlan0 set monitor none
sudo ip link set wlan0 up
# ИЛИ через aircrack-ng:
sudo airmon-ng start wlan0

# Шаг 2. Сканировать сети:
sudo python capture_traffic.py scan --iface wlan0mon --duration 20
# Выводит таблицу: SSID | BSSID | CH | Тип защиты | RSSI
# WEP-сети подсвечиваются красным

# Шаг 3а. Перехватить WEP-фреймы (нужна WEP-сеть с активным трафиком):
sudo iw dev wlan0mon set channel 6     # установить правильный канал
sudo python capture_traffic.py wep \
    --iface wlan0mon \
    --ssid MyWEPNetwork \
    --count 200 \
    --out data/captures/real_wep.wep

# Шаг 3б. Захватить WPA2-handshake (ждём подключения клиента):
sudo python capture_traffic.py wpa \
    --iface wlan0mon \
    --ssid HomeNetwork \
    --timeout 120 \
    --out data/captures/real_wpa2.json

# Шаг 3в. С принудительным переподключением клиента (ТОЛЬКО своя сеть!):
sudo python capture_traffic.py wpa \
    --iface wlan0mon \
    --ssid HomeNetwork \
    --deauth

# Шаг 4. Взломать захваченный трафик:
python bruteforce_benchmark.py --wep-capture data/captures/real_wep.wep
python lab_aes_wpa2.py --capture data/captures/real_wpa2.json

# Шаг 5. Вернуть интерфейс:
sudo ip link set wlan0mon down
sudo iw wlan0mon set type managed
sudo ip link set wlan0mon up
```

**Как работает захват WEP:**
1. Scapy слушает все фреймы в monitor mode
2. Фильтруем: тип фрейма = 2 (Data) + FC Protected bit = 1
3. Из `Dot11WEP` layer: `iv[0:3]` + `keyid[0]` + `wepdata`
4. Собираем: `IV(3) ‖ KeyID(1) ‖ ciphertext` → записываем в `.wep`

**Как работает захват WPA2-handshake:**
1. Слушаем EAPOL-Key фреймы (тип 0x03, дескриптор 0x02=RSN)
2. Парсим Key Information bitmap: `ack_flag` (бит 7), `mic_flag` (бит 8)
3. Message 1 (от AP): `ack=1, mic=0` → берём ANonce (bytes[17:49])
4. Message 2 (от клиента): `ack=0, mic=1, has_mic=True` → берём SNonce + MIC
5. Нулируем байты [81:97] в копии EAPOL (для верификации)
6. Сохраняем в JSON

---

### `bruteforce_benchmark.py`

**Назначение:** проводит брутфорс-атаки на WEP, WPA и WPA2, измеряет 4 метрики и строит сравнительные графики.

**Пошаговое воспроизведение:**

```bash
# Шаг 1. Стандартный запуск (3 секунды на протокол):
python bruteforce_benchmark.py

# Шаг 2. Быстрый запуск (1.5 секунды на протокол):
python bruteforce_benchmark.py --quick

# Шаг 3. Без графиков (только таблица в терминале):
python bruteforce_benchmark.py --no-plots

# Шаг 4. С реальными захватами:
python bruteforce_benchmark.py \
    --wep-capture  data/captures/real_wep.wep \
    --wpa2-capture data/captures/real_wpa2.json

# Шаг 5. Своя длительность (10 секунд на протокол для точности):
python bruteforce_benchmark.py --duration 10
```

**Алгоритм WEP-атаки:**
```
Читаем .wep → список фреймов
Генерируем кандидатов: словарь, затем числовой перебор
  for candidate in candidates:
      ok, _ = wep_decrypt(candidate, frames[0])   # RC4 + CRC32
      if ok: → НАЙДЕНО
```

**Алгоритм WPA2-атаки:**
```
Читаем .json → {aa, sa, anonce, snonce, eapol, mic}
  for password in wordlist:
      pmk = PBKDF2(password, ssid, 4096)          ← медленно (2 мс)
      ptk = PRF-512(pmk, aa, sa, anonce, snonce)
      kck = ptk[0:16]
      mic = HMAC-SHA1(kck, eapol)[0:16]
      if mic == mic_captured: → НАЙДЕНО
```

**Четыре метрики:**

| Метрика | Что показывает |
|---|---|
| **1. Скорость (попыток/сек)** | Сколько кандидатов проверяется в секунду. WEP: ~30k-1M, WPA2: ~300-800 |
| **2. Цена попытки (мс)** | Время на одну проверку. WEP: ~0.001мс, WPA2: ~2мс. Именно это защищает WPA2 |
| **3. Время до взлома (сек)** | Реальное время нахождения пароля из словаря. Показывает практическую скорость атаки |
| **4. log₁₀(скорость)** | "Шкала опасности": WEP≈5-6, WPA≈4, WPA2≈2-3. Каждый пункт = в 10 раз быстрее |

**Что показывают графики:**
- **График 1 (log-шкала скоростей):** WEP в 100-1000× быстрее WPA2 — видно благодаря логарифмической оси
- **График 2 (стоимость попытки):** PBKDF2 стоит ~2мс vs ~0.001мс для RC4 — именно это делает WPA2 медленным для атакующего
- **График 3 (время взлома):** реальные секунды на нашем словаре из 50 паролей
- **График 4 (шкала опасности):** горизонтальный bar chart с зонами "безопасно/внимание/опасно"

---

### `lab_aes_wpa2.py`

**Назначение:** лабораторная работа — показывает, почему атакуют пароль, а не AES; пошаговая WPA2-атака; анализ сложности паролей.

**Пошаговое воспроизведение:**

```bash
# Шаг 1. Полный запуск (атака + анализ + графики):
python lab_aes_wpa2.py

# Шаг 2. Только анализ сложности паролей без атаки:
python lab_aes_wpa2.py --complexity-only

# Шаг 3. Другой пароль/SSID:
python lab_aes_wpa2.py --password hunter2 --ssid CampusNet

# Шаг 4. С реальным захватом:
python lab_aes_wpa2.py --capture data/captures/real_wpa2.json

# Шаг 5. Без графиков:
python lab_aes_wpa2.py --no-plots
```

**Что происходит в пошаговой атаке:**

Для первых 5 кандидатов скрипт выводит таблицу с промежуточными значениями. Это ключевой момент лабораторной: видно, что каждый пароль даёт уникальный PMK → уникальный KCK → уникальный MIC, и только правильный пароль совпадает с захваченным.

```
#  Пароль              PMK[:8]           KCK[:8]           MIC_calc[:8]  ==эталон?
1  123456              652080c2c8cf2980  838c2ddd48f02716  6c2d3c5bd178  нет
2  password            98ed031fd517354e  4f7c9e354a10686b  4e663ed29a37  нет
...
10 dragon              a4c72d97eb56b321  c3f19a8e2b4d7f01  b0e0ac67c156  ДА ✓
```

**Четыре метрики для AES-статистики:**

| Метрика | Что показывает |
|---|---|
| **1. PBKDF2-время/попытка** | Стабильно ~2мс на попытку независимо от пароля. Линия = намеренное замедление |
| **2. Keyspace vs длина (log₁₀)** | Линии для разных charset + пунктир AES-128. Пароли слабее ключа на 50+ бит |
| **3. GPU-время heatmap** | Матрица длина×charset: красный=секунды, зелёный=годы. Наглядно показывает "безопасную зону" |
| **4. Энтропия vs AES-128** | Bar chart: 12-символьный пароль даёт ~71 бит, AES — 128 бит. Разрыв очевиден |

**Вопросы для отчёта (Q1-Q5):**

**Q1. Почему нельзя атаковать AES-128 напрямую?**  
AES-128 keyspace = 2¹²⁸ ≈ 3.4×10³⁸. При GPU 10¹³ операций/сек — 10²⁵ лет. Никаких известных практических атак нет. Атакуют пароль, потому что keyspace пароля несравнимо меньше.

**Q2. Роль PBKDF2 в WPA2?**  
Key stretching: намеренно замедляет вычисление PMK до ~500 паролей/сек на CPU. Без PBKDF2 WPA2 был бы так же уязвим, как WPA/TKIP с его голым HMAC.

**Q3. Сколько лет GPU взламывает 12-симв. пароль (строч+проп+цифры)?**  
62¹² / 10⁶ / 86400 / 365 ≈ **102 000 000 лет**. Смотри Метрику 3, heatmap.

**Q4. WPA2-Personal vs WPA2-Enterprise?**  
Personal: один PSK на всю сеть. Enterprise: каждый пользователь проходит 802.1X/RADIUS, PSK не существует — словарная атака принципиально невозможна.

**Q5. Почему SSID влияет на безопасность?**  
PMK = PBKDF2(password, **SSID**). SSID — соль для PBKDF2. Rainbow-таблицы предвычисляются под конкретный SSID. Стандартные SSID (HomeNetwork, linksys) имеют готовые таблицы. Уникальный SSID делает их бесполезными.

---

## Полная последовательность воспроизведения

```bash
# 1. Перейти в директорию проекта
cd wifi_lab/

# 2. Установить зависимости
pip install matplotlib numpy

# 3. Сгенерировать тестовые данные
python generate_test_data.py
# Создаёт: data/wordlists/passwords.txt
#          data/captures/test_wep_40.wep
#          data/captures/test_wep_104.wep
#          data/captures/test_wpa.json
#          data/captures/test_wpa2.json
#          data/captures/test_wpa2_hard.json

# 4. Запустить брутфорс-бенчмарк
python bruteforce_benchmark.py
# Ожидаемый вывод в терминале:
#   WEP найден: 'hello',  26k+ ключей/сек
#   WPA найден: 'dragon', ~480 паролей/сек
#   WPA2 найден: 'dragon', ~480 паролей/сек
# Ожидаемые файлы:
#   benchmark_results.png
#   benchmark_results.json

# 5. Запустить лабораторную по AES
python lab_aes_wpa2.py
# Ожидаемый вывод:
#   Пошаговая таблица PMK/KCK/MIC для первых 5 кандидатов
#   Анализ сложности паролей — таблица длина×charset×время
#   Вопросы Q1-Q5
# Ожидаемые файлы:
#   lab_aes_results.png
#   lab_aes_results.json

# 6. (Опционально) Захват с реального интерфейса
pip install scapy
sudo airmon-ng start wlan0
sudo python capture_traffic.py scan --iface wlan0mon
sudo python capture_traffic.py wpa  --iface wlan0mon --ssid MyNet --deauth
python lab_aes_wpa2.py --capture data/captures/real_wpa2.json
```

---

## Технический справочник

### Почему WEP сломан

```
Фрейм: [IV(3)] [KeyID(1)] [RC4(IV‖Key, Plaintext‖CRC32)]
```

1. **24-битный IV** → 16 777 216 значений. При активном трафике повторяются через ~5 000 фреймов (парадокс дней рождения).
2. **Слабые ключи RC4** (IV вида `A+3, 255, X`) приводят к корреляции первых байт keystream с байтами ключа → атака FMS/KoreK.
3. **CRC-32 линеен** → bit-flipping: изменить ciphertext так, чтобы CRC остался верным.

### Почему WPA2 структурно устойчив

```
password + SSID  →[PBKDF2-SHA1 × 4096]→  PMK(32B)
PMK + AA + SA + ANonce + SNonce  →[PRF-512]→  PTK(64B)
PTK[0:16]=KCK  →[HMAC-SHA1(KCK, EAPOL_msg2)]→  MIC(16B)
```

- AES-128-CCMP: нет известных практических атак
- Единственный вектор: угадать пароль → пересчитать цепочку → сравнить MIC
- PBKDF2 × 4096: ~500 паролей/сек на CPU, ~1 000 000 на GPU
- Защита: пароль ≥12 случайных символов из mixed charset

### Сравнение скоростей атак

| Протокол | Шифр | Скорость CPU | Скорость GPU |
|---|---|---|---|
| WEP | RC4 + CRC32 | ~30k–1M/сек | ~100M+/сек |
| WPA/TKIP | RC4 + HMAC-MD5 | ~500/сек | ~1M/сек |
| WPA2/CCMP | AES + HMAC-SHA1 | ~500/сек | ~1M/сек |

Разница WEP↔WPA2 ~1000× — следствие PBKDF2, а не самого шифра.
