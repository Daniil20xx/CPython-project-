"""
bruteforce_benchmark.py — Брутфорс WEP / WPA / WPA2 + Сравнительная статистика
================================================================================
Проводит атаки перебора на WEP, WPA и WPA2, измеряет 4 метрики и строит графики.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
КАК ВОСПРОИЗВЕСТИ ПОШАГОВО:

  Шаг 1. Сгенерировать тестовые файлы (если ещё не сделано):
           python generate_test_data.py

  Шаг 2. Запустить брутфорс и получить графики:
           python bruteforce_benchmark.py

  Шаг 3. Только атака без графиков:
           python bruteforce_benchmark.py --no-plots

  Шаг 4. Быстрый режим (меньше итераций, быстрее завершается):
           python bruteforce_benchmark.py --quick

  Шаг 5. Использовать реальный захват:
           python bruteforce_benchmark.py --wep-capture data/captures/real_wep.wep
           python bruteforce_benchmark.py --wpa2-capture data/captures/real_wpa2.json

  Выходные файлы:
    benchmark_results.png   — 4 графика сравнения протоколов
    benchmark_results.json  — числовые результаты в JSON

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Четыре метрики сравнения:
  1. Скорость (attempts/sec)   — сколько кандидатов проверяется в секунду
  2. Стоимость одной проверки (ms) — время на одну попытку
  3. Время до взлома (сек)     — реальное время нахождения пароля/ключа
  4. Эффективный keyspace/сек  — сколько битов ключевого пространства 
                                 закрывается за секунду (log10)
"""

import os
import sys
import time
import json
import hmac
import hashlib
import struct
import zlib
import string
import itertools
import argparse

sys.path.insert(0, os.path.dirname(__file__))
from crypto_utils import wep_decrypt, verify_password
from generate_test_data import (
    generate_wep_capture, generate_wpa_handshake,
    generate_wordlist, read_wep_capture, load_handshake,
    WEP_MAGIC
)

# matplotlib опционально
try:
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MPL = True
except ImportError:
    HAS_MPL = False

# Цвета
def _c(code, s): return f"\033[{code}m{s}\033[0m"
def green(s):   return _c('92', s)
def red(s):     return _c('91', s)
def yellow(s):  return _c('93', s)
def bold(s):    return _c('1',  s)
def cyan(s):    return _c('96', s)


# ══════════════════════════════════════════════════════════════════════
# АТАКИ
# ══════════════════════════════════════════════════════════════════════

def attack_wep(capture_path: str, wordlist_path: str,
               duration_s: float = 3.0) -> dict:
    """
    Брутфорс WEP: перебор числовых 5-символьных ключей.

    Алгоритм:
      1. Читаем .wep файл → список зашифрованных фреймов
      2. Генерируем кандидатов: "00000", "00001", ..., "99999"
      3. Для каждого кандидата: wep_decrypt(key, frame[0])
         → если CRC-32 совпал → ключ найден
      4. Фиксируем время, счётчик, итоговую скорость

    Почему быстро: RC4 + CRC-32 = ~15 CPU-инструкций на байт.
    На Python: ~300k-1M попыток/сек.
    """
    print(cyan(f"\n[*] WEP брутфорс (RC4+CRC32)..."))
    key_len, frames = read_wep_capture(capture_path)

    # Словарный проход сначала
    found_key = None
    count = 0
    t_start = time.perf_counter()
    deadline = t_start + duration_s

    # Словарная атака
    if os.path.exists(wordlist_path):
        with open(wordlist_path) as f:
            words = [w.strip() for w in f if w.strip()]
        for w in words:
            enc = w.encode('latin-1', 'replace')[:key_len].ljust(key_len, b'\x00')
            ok, _ = wep_decrypt(enc, frames[0])
            count += 1
            if ok:
                found_key = enc
                break
            if time.perf_counter() >= deadline:
                break

    # Числовой перебор (до лимита по времени)
    if not found_key:
        digits = string.digits.encode()
        for combo in itertools.product(digits, repeat=key_len):
            candidate = bytes(combo)[:key_len]
            ok, _ = wep_decrypt(candidate, frames[0])
            count += 1
            if ok:
                found_key = candidate
                break
            if time.perf_counter() >= deadline:
                break

    elapsed = time.perf_counter() - t_start
    speed   = count / elapsed

    _print_result('WEP', found_key, count, elapsed, speed)
    return {
        'protocol':     'WEP',
        'found':        found_key.decode('latin-1') if found_key else None,
        'attempts':     count,
        'elapsed_s':    round(elapsed, 4),
        'speed':        round(speed, 1),
        'cost_ms':      round(1000 / speed, 4) if speed > 0 else 0,
        'time_to_crack': round(elapsed, 4) if found_key else None,
        'key_bits':     key_len * 8,
    }


def attack_wpa(capture_path: str, wordlist_path: str,
               duration_s: float = 3.0) -> dict:
    """
    Брутфорс WPA/TKIP: словарная атака, MIC = HMAC-MD5.

    Алгоритм:
      1. Загружаем JSON-handshake
      2. Для каждого пароля из словаря:
         a. PMK = PBKDF2-SHA1(pwd, ssid, 4096)
         b. PTK = PRF-512(PMK, ...)
         c. KCK = PTK[0:16]
         d. MIC = HMAC-MD5(KCK, eapol)[0:16]   ← TKIP использует MD5
         e. Сравниваем с захваченным MIC
      3. Измеряем скорость

    Узкое место: PBKDF2 с 4096 итерациями SHA1.
    """
    print(cyan(f"\n[*] WPA/TKIP брутфорс (PBKDF2+HMAC-MD5)..."))
    hs = load_handshake(capture_path)

    with open(wordlist_path) as f:
        candidates = [w.strip() for w in f if w.strip()]

    found_pwd = None
    count = 0
    t_start = time.perf_counter()
    deadline = t_start + duration_s

    for pwd in candidates:
        ok = verify_password(pwd, hs['ssid'], hs['aa'], hs['sa'],
                             hs['anonce'], hs['snonce'],
                             hs['eapol_frame'], hs['mic'], 'WPA')
        count += 1
        if ok:
            found_pwd = pwd
            break
        if time.perf_counter() >= deadline:
            break

    elapsed = time.perf_counter() - t_start
    speed   = count / elapsed

    _print_result('WPA', found_pwd, count, elapsed, speed, unit='pwd/s')
    return {
        'protocol':     'WPA',
        'found':        found_pwd,
        'attempts':     count,
        'elapsed_s':    round(elapsed, 4),
        'speed':        round(speed, 1),
        'cost_ms':      round(1000 / speed, 4) if speed > 0 else 0,
        'time_to_crack': round(elapsed, 4) if found_pwd else None,
        'key_bits':     128,
    }


def attack_wpa2(capture_path: str, wordlist_path: str,
                duration_s: float = 5.0) -> dict:
    """
    Брутфорс WPA2/CCMP: полный PBKDF2-pipeline, MIC = HMAC-SHA1.

    Алгоритм:
      1. Загружаем JSON-handshake
      2. Для каждого пароля из словаря:
         a. PMK = PBKDF2-SHA1(pwd, ssid, 4096)       ← 4096 итераций!
         b. PTK = PRF-512(PMK, ...)
         c. KCK = PTK[0:16]
         d. MIC = HMAC-SHA1(KCK, eapol)[0:16]         ← SHA1 (сильнее MD5)
         e. Сравниваем с захваченным MIC
      3. Измеряем скорость

    Разница с WPA:
      • HMAC-SHA1 вместо HMAC-MD5 (незначительно медленнее)
      • Та же цепочка PBKDF2 → оба одинаково медленны на практике
    """
    print(cyan(f"\n[*] WPA2/CCMP брутфорс (PBKDF2+HMAC-SHA1)..."))
    hs = load_handshake(capture_path)

    with open(wordlist_path) as f:
        candidates = [w.strip() for w in f if w.strip()]

    found_pwd = None
    count = 0
    t_start = time.perf_counter()
    deadline = t_start + duration_s

    for pwd in candidates:
        ok = verify_password(pwd, hs['ssid'], hs['aa'], hs['sa'],
                             hs['anonce'], hs['snonce'],
                             hs['eapol_frame'], hs['mic'], 'WPA2')
        count += 1
        if ok:
            found_pwd = pwd
            break
        if time.perf_counter() >= deadline:
            break

    elapsed = time.perf_counter() - t_start
    speed   = count / elapsed

    _print_result('WPA2', found_pwd, count, elapsed, speed, unit='pwd/s')
    return {
        'protocol':     'WPA2',
        'found':        found_pwd,
        'attempts':     count,
        'elapsed_s':    round(elapsed, 4),
        'speed':        round(speed, 1),
        'cost_ms':      round(1000 / speed, 4) if speed > 0 else 0,
        'time_to_crack': round(elapsed, 4) if found_pwd else None,
        'key_bits':     128,
    }


def _print_result(proto, found, count, elapsed, speed, unit='key/s'):
    print(f"  Протокол:  {proto}")
    print(f"  Попыток:   {count:,}")
    print(f"  Время:     {elapsed:.3f}s")
    print(f"  Скорость:  {speed:,.0f} {unit}")
    if found:
        val = found.decode('latin-1') if isinstance(found, bytes) else found
        print(green(f"  Найдено:   {val!r}"))
    else:
        print(yellow(f"  Не найдено (лимит времени)"))


# ══════════════════════════════════════════════════════════════════════
# СТАТИСТИКА И ГРАФИКИ
# ══════════════════════════════════════════════════════════════════════

def print_stats_table(results: list[dict]) -> None:
    """Выводит сравнительную таблицу 4 метрик."""
    import math
    print(bold(f"\n{'═'*72}"))
    print(bold(f"  СРАВНЕНИЕ ПРОТОКОЛОВ — 4 МЕТРИКИ"))
    print(bold(f"{'═'*72}"))
    print(f"  {'Метрика':<30} {'WEP':>12} {'WPA':>12} {'WPA2':>12}")
    print(f"  {'─'*30} {'─'*12} {'─'*12} {'─'*12}")

    r = {d['protocol']: d for d in results}
    wep  = r.get('WEP',  {})
    wpa  = r.get('WPA',  {})
    wpa2 = r.get('WPA2', {})

    def fmt(d, key, suffix='', fmt_fn=None):
        v = d.get(key)
        if v is None: return '—'
        if fmt_fn: return fmt_fn(v) + suffix
        return f"{v:,.1f}{suffix}"

    # Метрика 1: Скорость
    s_wep  = wep.get('speed', 0)
    s_wpa  = wpa.get('speed', 0)
    s_wpa2 = wpa2.get('speed', 0)
    print(f"  {'1. Скорость (попыток/сек)':<30} "
          f"{s_wep:>11,.0f} {s_wpa:>11,.0f} {s_wpa2:>11,.0f}")

    # Метрика 2: Стоимость одной проверки (мс)
    c_wep  = wep.get('cost_ms', 0)
    c_wpa  = wpa.get('cost_ms', 0)
    c_wpa2 = wpa2.get('cost_ms', 0)
    print(f"  {'2. Цена одной попытки (мс)':<30} "
          f"{c_wep:>11.4f} {c_wpa:>11.4f} {c_wpa2:>11.4f}")

    # Метрика 3: Время до взлома
    t_wep  = wep.get('time_to_crack')
    t_wpa  = wpa.get('time_to_crack')
    t_wpa2 = wpa2.get('time_to_crack')
    def fmt_t(v): return f"{v:.3f}s" if v is not None else "—"
    print(f"  {'3. Время до взлома':<30} "
          f"{fmt_t(t_wep):>12} {fmt_t(t_wpa):>12} {fmt_t(t_wpa2):>12}")

    # Метрика 4: log10(попыток/сек) — "log-скорость"
    import math
    def log_s(s): return f"{math.log10(max(s,1)):.2f}" if s else "—"
    print(f"  {'4. log10(скорость)':<30} "
          f"{log_s(s_wep):>12} {log_s(s_wpa):>12} {log_s(s_wpa2):>12}")

    print(bold(f"{'═'*72}"))

    # Интерпретация
    if s_wep > 0 and s_wpa2 > 0:
        ratio = s_wep / s_wpa2
        print(f"\n  WEP в {ratio:,.0f}× быстрее WPA2 → "
              f"WEP взламывается за секунды, WPA2 за годы (при сильном пароле)")
    print()


import math

def plot_benchmark(results: list[dict], out_path: str = 'benchmark_results.png') -> None:
    """
    Строит 4 графика на одном рисунке:

    1. Bar chart: Скорость (попыток/сек), логарифмическая ось Y
       Показывает: насколько WEP быстрее WPA2 на порядки
       Ось Y в log-scale чтобы видеть все три значения одновременно

    2. Bar chart: Стоимость одной попытки (мс)
       Показывает: насколько дорога одна проверка PBKDF2 vs RC4
       Чем выше — тем лучше для защитника

    3. Bar chart: Реальное время до взлома (сек)
       Показывает: сколько секунд ушло на нахождение пароля из словаря
       Все три нашли в словаре → видим именно время вычислений

    4. Horizontal bar: log10(скорость) — "шкала опасности"
       WEP ≈ 5-6, WPA ≈ 4-5, WPA2 ≈ 2-3
       Наглядная шкала: каждый пункт = в 10 раз быстрее
    """
    if not HAS_MPL:
        print(yellow("[!] matplotlib не установлен. Установите: pip install matplotlib"))
        print(yellow("    Числовые результаты сохранены в benchmark_results.json"))
        return

    protocols = [r['protocol'] for r in results]
    colors    = {'WEP': '#e74c3c', 'WPA': '#e67e22', 'WPA2': '#27ae60'}
    c_list    = [colors.get(p, '#3498db') for p in protocols]

    speeds    = [r['speed']    for r in results]
    costs     = [r['cost_ms']  for r in results]
    cracks    = [r.get('time_to_crack') or 0 for r in results]
    log_sp    = [math.log10(max(s, 1)) for s in speeds]

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('WiFi Security Benchmark: WEP vs WPA vs WPA2',
                 fontsize=16, fontweight='bold', y=0.98)
    fig.patch.set_facecolor('#1a1a2e')
    for ax in axes.flat:
        ax.set_facecolor('#16213e')
        ax.tick_params(colors='white')
        ax.title.set_color('white')
        ax.xaxis.label.set_color('white')
        ax.yaxis.label.set_color('white')
        for spine in ax.spines.values():
            spine.set_edgecolor('#444')

    # ── График 1: Скорость (log-шкала) ────────────────────────────────
    ax1 = axes[0, 0]
    bars1 = ax1.bar(protocols, speeds, color=c_list, edgecolor='white', linewidth=0.8)
    ax1.set_yscale('log')
    ax1.set_title('Метрика 1: Скорость перебора (попыток/сек)', fontsize=11)
    ax1.set_ylabel('попыток/сек (log scale)')
    for bar, v in zip(bars1, speeds):
        ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() * 1.2,
                 f'{v:,.0f}', ha='center', va='bottom', color='white',
                 fontsize=9, fontweight='bold')
    ax1.set_ylim(1, max(speeds) * 20)
    ax1.yaxis.set_tick_params(which='both', labelcolor='white')
    ax1.grid(axis='y', alpha=0.2, color='white')

    # ── График 2: Стоимость одной попытки ─────────────────────────────
    ax2 = axes[0, 1]
    bars2 = ax2.bar(protocols, costs, color=c_list, edgecolor='white', linewidth=0.8)
    ax2.set_title('Метрика 2: Стоимость одной попытки (мс)', fontsize=11)
    ax2.set_ylabel('миллисекунды')
    for bar, v in zip(bars2, costs):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(costs)*0.01,
                 f'{v:.4f}', ha='center', va='bottom', color='white',
                 fontsize=9, fontweight='bold')
    ax2.grid(axis='y', alpha=0.2, color='white')

    # ── График 3: Время до взлома ─────────────────────────────────────
    ax3 = axes[1, 0]
    bars3 = ax3.bar(protocols, cracks, color=c_list, edgecolor='white', linewidth=0.8)
    ax3.set_title('Метрика 3: Время до взлома из словаря (сек)', fontsize=11)
    ax3.set_ylabel('секунды')
    for bar, v in zip(bars3, cracks):
        label = f'{v:.3f}s' if v > 0 else 'не найден'
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(cracks)*0.01,
                 label, ha='center', va='bottom', color='white',
                 fontsize=9, fontweight='bold')
    ax3.grid(axis='y', alpha=0.2, color='white')

    # ── График 4: Log-шкала опасности ────────────────────────────────
    ax4 = axes[1, 1]
    bars4 = ax4.barh(protocols, log_sp, color=c_list, edgecolor='white', linewidth=0.8)
    ax4.set_title('Метрика 4: log₁₀(скорость) — шкала опасности', fontsize=11)
    ax4.set_xlabel('log₁₀(попыток/сек)')

    # Зоны опасности
    ax4.axvspan(0, 2,   alpha=0.08, color='green',  label='Безопасно (<100/s)')
    ax4.axvspan(2, 4,   alpha=0.08, color='orange', label='Внимание (100-10k/s)')
    ax4.axvspan(4, 7,   alpha=0.08, color='red',    label='Опасно (>10k/s)')
    for bar, v, label in zip(bars4, log_sp, protocols):
        ax4.text(v + 0.05, bar.get_y() + bar.get_height()/2,
                 f'{v:.2f}  (10^{v:.1f} ≈ {10**v:,.0f}/s)',
                 va='center', color='white', fontsize=9)
    ax4.set_xlim(0, max(log_sp) * 1.3)
    ax4.legend(loc='lower right', fontsize=8,
               facecolor='#1a1a2e', labelcolor='white', framealpha=0.8)
    ax4.grid(axis='x', alpha=0.2, color='white')

    plt.tight_layout(rect=[0, 0, 1, 0.96])
    plt.savefig(out_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(green(f"\n[+] Графики сохранены: {out_path}"))


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description='Брутфорс WEP/WPA/WPA2 + сравнительная статистика',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--wep-capture',  default='data/captures/test_wep_40.wep')
    parser.add_argument('--wpa-capture',  default='data/captures/test_wpa.json')
    parser.add_argument('--wpa2-capture', default='data/captures/test_wpa2.json')
    parser.add_argument('--wordlist',     default='data/wordlists/passwords.txt')
    parser.add_argument('--duration',     type=float, default=3.0,
                        help='Максимальное время на каждый протокол (сек)')
    parser.add_argument('--quick',  action='store_true', help='duration=1.5s')
    parser.add_argument('--no-plots', action='store_true', help='Не строить графики')
    parser.add_argument('--out-plot', default='benchmark_results.png')
    args = parser.parse_args()

    dur = 1.5 if args.quick else args.duration

    # Проверяем наличие файлов, генерируем если нет
    need_gen = not all(os.path.exists(p) for p in [
        args.wep_capture, args.wpa_capture, args.wpa2_capture, args.wordlist
    ])
    if need_gen:
        print(yellow("[*] Тестовые файлы не найдены, генерирую..."))
        generate_wordlist()
        from crypto_utils import wep_encrypt
        key_40 = b'hello'
        generate_wep_capture(key_40, 200, 'data/captures/test_wep_40.wep')
        generate_wpa_handshake('dragon', 'HomeNetwork', 'WPA',  'data/captures/test_wpa.json')
        generate_wpa_handshake('dragon', 'HomeNetwork', 'WPA2', 'data/captures/test_wpa2.json')
        print()

    print(bold("\n" + "═"*65))
    print(bold("  WiFi Брутфорс Бенчмарк: WEP / WPA / WPA2"))
    print(bold("═"*65))

    results = []
    results.append(attack_wep( args.wep_capture,  args.wordlist, dur))
    results.append(attack_wpa( args.wpa_capture,  args.wordlist, dur))
    results.append(attack_wpa2(args.wpa2_capture, args.wordlist, dur))

    print_stats_table(results)

    # Сохраняем JSON
    with open('benchmark_results.json', 'w') as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[+] Результаты: benchmark_results.json")

    # Графики
    if not args.no_plots:
        plot_benchmark(results, args.out_plot)


if __name__ == '__main__':
    main()
