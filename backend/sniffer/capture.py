"""
╔══════════════════════════════════════════════════════════════════╗
║       PACKET CAPTURE — 100% Python thuần                        ║
║  Raw socket (AF_PACKET) + PCAP file reader/writer               ║
║  KHÔNG dùng Scapy                                               ║
╚══════════════════════════════════════════════════════════════════╝
"""

import socket
import struct
import os
import time
import threading
import fcntl
from datetime import datetime
from typing import Callable, List, Optional


class PacketCapture:
    """
    Class quản lý việc bắt gói tin bằng raw socket.

    Trên Linux (WSL), sử dụng AF_PACKET + SOCK_RAW để nhận
    toàn bộ raw Ethernet frame.
    """

    def __init__(self):
        self.captured_packets: List[bytes] = []
        self.is_running = False
        self._sock = None

    # ─── 1. Liệt kê interfaces ────────────────────────────────────────

    @staticmethod
    def list_interfaces() -> list:
        """Liệt kê network interfaces từ /sys/class/net/"""
        try:
            interfaces = []
            net_dir = "/sys/class/net/"
            for iface in os.listdir(net_dir):
                ip_addr = PacketCapture._get_iface_ip(iface)
                interfaces.append({
                    "name":        iface,
                    "description": iface,
                    "ip":          ip_addr,
                    "mac":         PacketCapture._get_iface_mac(iface)
                })
            return interfaces
        except Exception as e:
            print(f"[!] Lỗi liệt kê interfaces: {e}")
            return []

    


    @staticmethod
    def _get_iface_ip(iface_name):
        """Lấy IP address của interface bằng ioctl"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', iface_name.encode('utf-8')[:15])
            )[20:24])
            s.close()
            return ip
        except Exception:
            return "N/A"

    @staticmethod
    def _get_iface_mac(iface_name):
        """Lấy MAC address từ /sys/class/net/"""
        try:
            with open(f"/sys/class/net/{iface_name}/address") as f:
                return f.read().strip()
        except Exception:
            return "N/A"

    # ─── 2. Bắt gói tin trực tiếp (Raw Socket) ────────────────────────

    def start_live_capture(
        self,
        interface: str = None,
        bpf_filter: str = "",
        count: int = 0,
        callback: Callable = None
    ):
        """
        Bắt gói tin trực tiếp bằng raw socket AF_PACKET.

        AF_PACKET + SOCK_RAW nhận toàn bộ Ethernet frame,
        bao gồm cả MAC header — đầy đủ nhất có thể.

        Cần chạy với quyền root (sudo).
        """
        self.is_running = True
        self.captured_packets = []

        try:
            # ETH_P_ALL = 0x0003 → nhận mọi loại gói tin
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003)
            )

            if interface:
                self._sock.bind((interface, 0))

            self._sock.settimeout(1.0)  # timeout để kiểm tra is_running

            print(f"[*] Bắt đầu capture (Raw Socket)")
            print(f"    Interface : {interface or 'tất cả'}")
            print(f"    Nhấn Ctrl+C để dừng\n")

            packet_count = 0

            while self.is_running:
                try:
                    raw_data, addr = self._sock.recvfrom(65535)

                    self.captured_packets.append(raw_data)
                    packet_count += 1

                    if callback:
                        callback(raw_data)

                    if count > 0 and packet_count >= count:
                        break

                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\n[!] Người dùng dừng capture.")
                    break

        except PermissionError:
            print("[!] Cần quyền root. Chạy: sudo python server.py")
        except Exception as e:
            print(f"[!] Lỗi capture: {e}")
        finally:
            self.is_running = False
            if self._sock:
                self._sock.close()
                self._sock = None

    def stop(self):
        """Dừng capture"""
        self.is_running = False

    # ─── 3. Đọc file PCAP ─────────────────────────────────────────────
    @staticmethod
    def load_from_pcap(filepath, callback=None) -> list:
        """
        Đọc file .pcap hoặc .pcapng
        - .pcap  → tự parse bằng struct (Python thuần)
        - .pcapng → dùng dpkt
        """
        if not os.path.exists(filepath):
            print(f"[!] Không tìm thấy file: {filepath}")
            return []

        # Phân biệt pcap vs pcapng bằng magic number
        with open(filepath, 'rb') as f:
            magic = f.read(4)

        # pcapng magic: 0x0A0D0D0A
        if magic == b'\x0a\x0d\x0d\x0a':
            return PacketCapture._load_pcapng(filepath, callback)
        else:
            return PacketCapture._load_pcap(filepath, callback)

    @staticmethod
    def _load_pcapng(filepath, callback=None) -> list:
        """Đọc file .pcapng bằng dpkt"""
        try:
            import dpkt
        except ImportError:
            print("[!] Cần cài dpkt: pip install dpkt")
            return []

        packets = []
        try:
            with open(filepath, 'rb') as f:
                scanner = dpkt.pcapng.Scanner(f)
                for ts, buf, datalink in scanner:
                    packets.append(buf)
                    if callback:
                        callback(buf)
            print(f"[+] Đọc được {len(packets)} gói tin từ {filepath} (pcapng)")
        except Exception as e:
            print(f"[!] Lỗi đọc pcapng: {e}")

        return packets

    
    @staticmethod
    def load_from_pcap(filepath, callback=None) -> list:
        """
        Đọc file .pcap bằng Python thuần.

        PCAP file format:
        ┌────────────────────────┐
        │ Global Header (24B)    │
        ├────────────────────────┤
        │ Packet Header (16B)    │
        │ Packet Data            │
        ├────────────────────────┤
        │ Packet Header (16B)    │
        │ Packet Data            │
        ├────────────────────────┤
        │ ...                    │
        └────────────────────────┘
        """
        if not os.path.exists(filepath):
            print(f"[!] Không tìm thấy file: {filepath}")
            return []

        packets = []

        with open(filepath, 'rb') as f:
            # ── Global Header (24 bytes) ──────────────────────────
            global_header = f.read(24)
            if len(global_header) < 24:
                print("[!] File PCAP không hợp lệ (quá ngắn)")
                return []

            magic = struct.unpack('<I', global_header[:4])[0]

            # Xác định byte order từ magic number
            if magic == 0xa1b2c3d4:
                endian = '<'  # Little-endian
            elif magic == 0xd4c3b2a1:
                endian = '>'  # Big-endian
            else:
                print(f"[!] File không phải PCAP (magic: {hex(magic)})")
                return []

            # ── Đọc từng packet ──────────────────────────────────
            idx = 0
            while True:
                # Packet header (16 bytes)
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = \
                    struct.unpack(f'{endian}IIII', pkt_header)

                # Packet data
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                packets.append(pkt_data)
                idx += 1

                if callback:
                    callback(pkt_data)

        print(f"[+] Đọc được {len(packets)} gói tin từ {filepath}")
        return packets

    # ─── 4. Ghi file PCAP ──────────────────────────────────────────────

    @staticmethod
    def save_to_pcap(packets, filepath=None) -> str:
        """
        Ghi danh sách raw packets ra file .pcap

        PCAP Global Header:
          magic_number  = 0xa1b2c3d4
          version_major = 2
          version_minor = 4
          thiszone      = 0
          sigfigs       = 0
          snaplen       = 65535
          network       = 1 (LINKTYPE_ETHERNET)
        """
        if not packets:
            print("[!] Không có gói tin nào để lưu.")
            return ""

        os.makedirs("captures", exist_ok=True)

        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H-%M-%S")
            filepath = f"captures/capture_{timestamp}.pcap"

        with open(filepath, 'wb') as f:
            # Global Header
            f.write(struct.pack('<IHHIIII',
                0xa1b2c3d4,  # magic
                2,            # version major
                4,            # version minor
                0,            # thiszone
                0,            # sigfigs
                65535,        # snaplen
                1             # LINKTYPE_ETHERNET
            ))

            # Packet records
            now = int(time.time())
            for pkt in packets:
                pkt_len = len(pkt)
                # Packet header: ts_sec, ts_usec, incl_len, orig_len
                f.write(struct.pack('<IIII', now, 0, pkt_len, pkt_len))
                f.write(pkt)

        print(f"[+] Đã lưu {len(packets)} gói tin → {filepath}")
        return filepath

    # ─── 5. Thống kê nhanh ─────────────────────────────────────────────

    def get_summary(self) -> dict:
        return {
            "total":      len(self.captured_packets),
            "is_running": self.is_running
        }