from scapy.all import sniff, get_if_list, rdpcap, wrpcap, Packet
from typing import Callable, List, Optional
from datetime import datetime
import os

class PacketCapture:
    """
    Class quản lý việc bắt gói tin.
    
    Tại sao dùng Class thay vì hàm đơn lẻ?
    → Vì cần lưu trạng thái: danh sách gói đã bắt, 
      đang chạy hay đã dừng, callback hiện tại là gì...
    """

    def __init__(self):
        self.captured_packets: List[Packet] = []  # danh sách gói tin đã bắt
        self.is_running = False

    # ─── 1. Liệt kê interface ─────────────────────────────────────────────

    @staticmethod
    def list_interfaces() -> List[str]:
        """Trả về danh sách tất cả network interface trên máy"""
        return get_if_list()

    # ─── 2. Bắt gói tin trực tiếp (Live Capture) ─────────────────────────

    def start_live_capture(
        self,
        interface: str        = None,
        bpf_filter: str       = "",
        count: int            = 0,
        callback: Callable    = None
    ):
        """
        Bắt gói tin trực tiếp từ card mạng.

        Tham số:
        - interface : tên card mạng (None = tự chọn cái đầu tiên)
        - bpf_filter: chuỗi lọc BPF, ví dụ "tcp port 80"
        - count     : bắt bao nhiêu gói (0 = chạy mãi đến khi dừng)
        - callback  : hàm xử lý mỗi khi có gói tin mới đến
        """
        self.is_running = True
        self.captured_packets = []

        def _internal_callback(packet):
            # Lưu vào danh sách nội bộ
            self.captured_packets.append(packet)
            # Gọi hàm xử lý bên ngoài (ví dụ: analyze_packet)
            if callback:
                callback(packet)

        print(f"[*] Bắt đầu live capture")
        print(f"    Interface : {interface or 'auto'}")
        print(f"    BPF Filter: '{bpf_filter}' " if bpf_filter else "    BPF Filter: (không có)")
        print(f"    Count     : {count if count > 0 else 'không giới hạn'}")
        print(f"    Nhấn Ctrl+C để dừng\n")

        try:
            sniff(
                iface=interface,
                filter=bpf_filter,      # BPF filter truyền thẳng vào kernel
                count=count,
                prn=_internal_callback,
                store=False             # không lưu trong bộ nhớ Scapy (đã tự lưu)
            )
        except KeyboardInterrupt:
            print("\n[!] Người dùng dừng capture.")
        finally:
            self.is_running = False

    # ─── 3. Lưu gói tin ra file PCAP ──────────────────────────────────────

    def save_to_pcap(self, filepath: str = None) -> str:
        """
        Lưu danh sách gói đã bắt ra file .pcap
        
        Nếu không truyền filepath → tự tạo tên theo timestamp
        Ví dụ: captures/capture_14-32-01.pcap
        """
        if not self.captured_packets:
            print("[!] Không có gói tin nào để lưu.")
            return ""

        # Tạo thư mục captures nếu chưa có
        os.makedirs("captures", exist_ok=True)

        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H-%M-%S")
            filepath = f"captures/capture_{timestamp}.pcap"

        wrpcap(filepath, self.captured_packets)
        print(f"[+] Đã lưu {len(self.captured_packets)} gói tin → {filepath}")
        return filepath

    # ─── 4. Đọc file PCAP có sẵn ──────────────────────────────────────────

    def load_from_pcap(
        self,
        filepath: str,
        callback: Callable = None
    ) -> List[Packet]:
        """
        Đọc file .pcap và phân tích từng gói tin.
        
        Tại sao cần tính năng này?
        → Cho phép phân tích OFFLINE — không cần mạng.
          Ví dụ: thầy giáo cho file pcap mẫu, bạn load vào phân tích.
          Hoặc bắt gói lúc sáng, tối về ngồi phân tích lại.
        """
        if not os.path.exists(filepath):
            print(f"[!] Không tìm thấy file: {filepath}")
            return []

        print(f"[*] Đang đọc file: {filepath}")
        packets = rdpcap(filepath)
        self.captured_packets = list(packets)

        print(f"[+] Đọc được {len(packets)} gói tin từ file.\n")

        # Nếu có callback thì xử lý từng gói
        if callback:
            for i, packet in enumerate(packets):
                print(f"[{i+1}/{len(packets)}] ", end="")
                callback(packet)

        return self.captured_packets

    # ─── 5. Thống kê nhanh ────────────────────────────────────────────────


    def get_summary(self) -> dict:
        """Thống kê nhanh về số gói đã bắt"""
        return {
            "total":      len(self.captured_packets),
            "is_running": self.is_running
        }