#!/usr/bin/env python3
# """
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NSM — Network Security Monitor CLI                 ║
# ║  Công cụ giám sát an ninh mạng — Bắt & Phân tích gói tin       ║
# ╚══════════════════════════════════════════════════════════════════╝

# Sử dụng:
#     python main.py <lệnh> [tùy chọn]

# Ví dụ:
#     python main.py interfaces
#     python main.py capture --count 20 --filter "tcp port 80"
#     python main.py read captures/demo.pcap --detail
#     python main.py help
# """

import argparse
import json
import sys
import os
from datetime import datetime

from sniffer.capture import PacketCapture
from analyzer.protocol import analyze_packet, hex_dump


# ═══════════════════════════════════════════════════════════════════
#  TIỆN ÍCH HIỂN THỊ (Display Helpers)
# ═══════════════════════════════════════════════════════════════════

class Colors:
    """ANSI color codes cho terminal"""
    HEADER  = "\033[95m"
    BLUE    = "\033[94m"
    CYAN    = "\033[96m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    RED     = "\033[91m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"


def banner():
    """In logo ứng dụng"""
    print(f"""{Colors.CYAN}{Colors.BOLD}
    {Colors.RESET}""")


def print_header(text):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'═'*60}")
    print(f"  {text}")
    print(f"{'═'*60}{Colors.RESET}\n")


def print_success(text):
    print(f"  {Colors.GREEN}✔ {text}{Colors.RESET}")


def print_warning(text):
    print(f"  [CANH BAO] {text}")


def print_error(text):
    print(f"  {Colors.RED}✘ {text}{Colors.RESET}")


def print_info(text):
    print(f"  {Colors.CYAN}ℹ {text}{Colors.RESET}")


# ═══════════════════════════════════════════════════════════════════
#  CALLBACK: XỬ LÝ TỪNG GÓI TIN
# ═══════════════════════════════════════════════════════════════════

# Bộ đếm gói tin toàn cục
_packet_counter = {"count": 0}


def _make_callback(detail=False, show_hex=False, show_json=False):
    """
    Tạo callback function dùng cho live capture và đọc PCAP.

    Các chế độ hiển thị:
    - Mặc định : dòng tóm tắt ngắn gọn
    - --detail  : hiển thị chi tiết từng tầng (Ethernet, IP, Transport, App)
    - --hex     : hiển thị hex dump raw bytes
    - --json    : xuất JSON đầy đủ
    """

    def callback(packet):
        _packet_counter["count"] += 1
        n = _packet_counter["count"]
        result = analyze_packet(packet)

        proto = result.get("transport_proto", "?")
        summary = result.get("summary", "")

        # ── Chế độ JSON ──────────────────────────────────────────
        if show_json:
            # Loại bỏ các trường không serialize được
            safe = _safe_json(result)
            print(json.dumps(safe, indent=2, ensure_ascii=False))
            print()
            return

        # ── Dòng tóm tắt (luôn hiển thị) ────────────────────────
        proto_color = {
            "TCP": Colors.GREEN,
            "UDP": Colors.BLUE,
            "DNS": Colors.CYAN,
            "HTTP": Colors.YELLOW,
            "ICMP": Colors.DIM,
            "ARP": Colors.RED,
        }.get(proto, Colors.RESET)

        print(f"  {Colors.DIM}#{n:<5}{Colors.RESET}"
              f" [{result.get('time', '')}]"
              f" {proto_color}{proto:<5}{Colors.RESET}"
              f" {summary}")

        # ── Chế độ chi tiết ──────────────────────────────────────
        if detail:
            _print_detail(result)

        # ── Chế độ hex dump ──────────────────────────────────────
        if show_hex:
            print(f"\n{Colors.DIM}{hex_dump(packet)}{Colors.RESET}\n")

        # ── Cảnh báo bất thường ──────────────────────────────────
        app = result.get("app_layer", {})
        dns = app.get("dns", {})
        if dns.get("is_suspicious"):
            print_warning(f"DNS đáng ngờ: {dns.get('suspicious_reason', '')}")

        http = app.get("http", {})
        if http.get("credentials_found"):
            print_warning(f"PHÁT HIỆN CREDENTIALS: {http.get('credentials', [])}")

    return callback


def _print_detail(result):
    """In chi tiết từng tầng giao thức"""

    # Ethernet
    eth = result.get("ethernet", {})
    if eth:
        print(f"      {Colors.DIM}├─ Ethernet: "
              f"{eth.get('src_mac','?')} → {eth.get('dst_mac','?')} "
              f"[{eth.get('ethertype_name', '')}]{Colors.RESET}")

    # IP
    ip = result.get("ip", {})
    if ip:
        print(f"      {Colors.DIM}├─ IP: "
              f"v{ip.get('version','')} | "
              f"TTL={ip.get('ttl','?')} ({ip.get('os_guess','')}) | "
              f"proto={ip.get('protocol_name','')} | "
              f"len={ip.get('total_length','')}B{Colors.RESET}")

    # Transport
    tr = result.get("transport", {})
    proto = result.get("transport_proto", "")
    if proto == "TCP" and tr:
        print(f"      {Colors.DIM}├─ TCP: "
              f"flags={tr.get('flags_active',[])} | "
              f"window={tr.get('window_size','')} | "
              f"seq={tr.get('seq','')}{Colors.RESET}")
    elif proto == "UDP" and tr:
        print(f"      {Colors.DIM}├─ UDP: "
              f"len={tr.get('length','')}{Colors.RESET}")
    elif proto == "ICMP" and tr:
        print(f"      {Colors.DIM}├─ ICMP: "
              f"type={tr.get('type','')} — {tr.get('meaning','')}{Colors.RESET}")
    elif proto == "ARP" and tr:
        print(f"      {Colors.DIM}├─ ARP: "
              f"{tr.get('op','')} "
              f"{tr.get('src_mac','?')} ({tr.get('src_ip','?')}) → "
              f"{tr.get('dst_mac','?')} ({tr.get('dst_ip','?')}){Colors.RESET}")

    # App Layer
    app = result.get("app_layer", {})
    dns = app.get("dns", {})
    if dns:
        for q in dns.get("queries", []):
            print(f"      {Colors.DIM}└─ DNS Query: "
                  f"{q.get('name','')} ({q.get('type','')}){Colors.RESET}")
        for a in dns.get("answers", []):
            print(f"      {Colors.DIM}└─ DNS Answer: "
                  f"{a.get('name','')} → {a.get('rdata','')}{Colors.RESET}")

    http = app.get("http", {})
    if http:
        if http.get("direction") == "request":
            print(f"      {Colors.DIM}└─ HTTP: "
                  f"{http.get('method','')} {http.get('host','')}"
                  f"{http.get('uri','')}{Colors.RESET}")
        elif http.get("direction") == "response":
            print(f"      {Colors.DIM}└─ HTTP: "
                  f"{http.get('status_code','')} "
                  f"{http.get('status_text','')}{Colors.RESET}")

    # Payload
    payload = result.get("payload", {})
    if payload:
        print(f"      {Colors.DIM}└─ Payload: "
              f"{payload.get('payload_length', 0)} bytes{Colors.RESET}")


def _safe_json(obj):
    """Chuyển result dict sang dạng JSON-serializable"""
    if isinstance(obj, dict):
        return {k: _safe_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_safe_json(i) for i in obj]
    elif isinstance(obj, bytes):
        return obj.hex()
    else:
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)


# ═══════════════════════════════════════════════════════════════════
#  CÁC LỆNH CLI (Commands)
# ═══════════════════════════════════════════════════════════════════

def cmd_interfaces(args):
    """Liệt kê tất cả network interfaces trên máy"""
    from scapy.all import conf

    print_header("NETWORK INTERFACES")

    # Lấy thông tin chi tiết từ Scapy's interface database
    iface_data = conf.ifaces

    if not iface_data:
        print_error("Không tìm thấy interface nào.")
        return

    for i, (dev_name, iface_obj) in enumerate(iface_data.items(), 1):
        # Lấy tên thân thiện, IP, MAC
        name = getattr(iface_obj, "description", "") or getattr(iface_obj, "name", dev_name)
        ip   = getattr(iface_obj, "ip", "N/A") or "N/A"
        mac  = getattr(iface_obj, "mac", "N/A") or "N/A"

        print(f"  {Colors.GREEN}{i:>3}.{Colors.RESET} {Colors.BOLD}{name}{Colors.RESET}")
        print(f"       {Colors.DIM}Device : {dev_name}{Colors.RESET}")
        print(f"       {Colors.DIM}IP     : {ip}{Colors.RESET}")
        print(f"       {Colors.DIM}MAC    : {mac}{Colors.RESET}")
        print()

    print(f"  {Colors.DIM}Tổng cộng: {len(iface_data)} interface(s){Colors.RESET}")
    print(f"  {Colors.DIM}Sử dụng: python main.py capture -i <tên device hoặc tên card>{Colors.RESET}\n")


def cmd_capture(args):
    """Bắt gói tin trực tiếp từ card mạng (Live Capture)"""
    print_header("LIVE CAPTURE")

    capture = PacketCapture()

    # Hiển thị cấu hình
    print_info(f"Interface : {args.interface or 'auto (mặc định)'}")
    print_info(f"BPF Filter: {args.filter or '(không có — bắt tất cả)'}")
    print_info(f"Số gói    : {args.count if args.count > 0 else 'không giới hạn'}")
    print_info(f"Chi tiết  : {'Có' if args.detail else 'Không'}")
    print_info(f"Hex dump  : {'Có' if args.hex else 'Không'}")
    print_info(f"JSON      : {'Có' if args.json else 'Không'}")
    if args.output:
        print_info(f"Lưu file  : {args.output}")
    print()

    # Reset bộ đếm
    _packet_counter["count"] = 0

    # Tạo callback
    cb = _make_callback(
        detail=args.detail,
        show_hex=args.hex,
        show_json=args.json,
    )

    # Bắt đầu capture
    capture.start_live_capture(
        interface=args.interface,
        bpf_filter=args.filter or "",
        count=args.count,
        callback=cb,
    )

    # Lưu file PCAP nếu yêu cầu
    if args.output:
        if capture.captured_packets:
            capture.save_to_pcap(args.output)
            print_success(f"Đã lưu {len(capture.captured_packets)} gói → {args.output}")
        else:
            print_warning("Không có gói tin nào để lưu.")
    elif args.save:
        if capture.captured_packets:
            filepath = capture.save_to_pcap()
            print_success(f"Đã tự động lưu → {filepath}")

    # Thống kê
    total = _packet_counter["count"]
    print(f"\n  {Colors.DIM}Tổng cộng: {total} gói tin đã xử lý{Colors.RESET}\n")


def cmd_read(args):
    """Đọc và phân tích file PCAP"""
    filepath = args.file
    print_header(f"ĐỌC FILE PCAP: {filepath}")

    if not os.path.exists(filepath):
        print_error(f"Không tìm thấy file: {filepath}")
        sys.exit(1)

    capture = PacketCapture()

    # Reset bộ đếm
    _packet_counter["count"] = 0

    cb = _make_callback(
        detail=args.detail,
        show_hex=args.hex,
        show_json=args.json,
    )

    packets = capture.load_from_pcap(filepath, callback=cb)

    # Thống kê
    total = len(packets)
    print(f"\n  {Colors.DIM}Tổng cộng: {total} gói tin từ file{Colors.RESET}\n")


def cmd_stats(args):
    """Đọc file PCAP và hiển thị thống kê tổng hợp"""
    filepath = args.file
    print_header(f"THỐNG KÊ FILE: {filepath}")

    if not os.path.exists(filepath):
        print_error(f"Không tìm thấy file: {filepath}")
        sys.exit(1)

    capture = PacketCapture()
    packets = capture.load_from_pcap(filepath)

    if not packets:
        print_warning("File không chứa gói tin nào.")
        return

    # Thu thập thống kê
    proto_count = {}
    ip_src_count = {}
    ip_dst_count = {}
    service_count = {}
    suspicious_dns = []
    credentials = []

    for pkt in packets:
        result = analyze_packet(pkt)
        proto = result.get("transport_proto", "OTHER")
        proto_count[proto] = proto_count.get(proto, 0) + 1

        ip = result.get("ip", {})
        src = ip.get("src_ip", "?")
        dst = ip.get("dst_ip", "?")
        ip_src_count[src] = ip_src_count.get(src, 0) + 1
        ip_dst_count[dst] = ip_dst_count.get(dst, 0) + 1

        tr = result.get("transport", {})
        svc = tr.get("service")
        if svc:
            service_count[svc] = service_count.get(svc, 0) + 1

        app = result.get("app_layer", {})
        dns = app.get("dns", {})
        if dns.get("is_suspicious"):
            for q in dns.get("queries", []):
                suspicious_dns.append(q.get("name", ""))

        http = app.get("http", {})
        if http.get("credentials_found"):
            credentials.extend(http.get("credentials", []))

    # Hiển thị kết quả
    total = len(packets)

    # Giao thức
    print(f"  {Colors.BOLD} Phân bố giao thức ({total} gói):{Colors.RESET}")
    for proto, count in sorted(proto_count.items(), key=lambda x: -x[1]):
        pct = count / total * 100
        bar = "█" * int(pct / 2)
        print(f"     {proto:<8} {count:>5}  ({pct:5.1f}%)")

    # Top IP nguồn
    print(f"\n  {Colors.BOLD} Top 10 IP nguồn:{Colors.RESET}")
    for ip, count in sorted(ip_src_count.items(), key=lambda x: -x[1])[:10]:
        print(f"     {ip:<20} {count:>5} gói")

    # Top IP đích
    print(f"\n  {Colors.BOLD} Top 10 IP đích:{Colors.RESET}")
    for ip, count in sorted(ip_dst_count.items(), key=lambda x: -x[1])[:10]:
        print(f"     {ip:<20} {count:>5} gói")

    # Dịch vụ
    if service_count:
        print(f"\n  {Colors.BOLD}🔌 Dịch vụ phát hiện:{Colors.RESET}")
        for svc, count in sorted(service_count.items(), key=lambda x: -x[1]):
            print(f"     {svc:<12} {count:>5} gói")

    # Cảnh báo
    if suspicious_dns:
        print(f"\n  {Colors.RED}{Colors.BOLD}⚠  DNS đáng ngờ:{Colors.RESET}")
        for domain in suspicious_dns:
            print(f"     {Colors.RED}• {domain}{Colors.RESET}")

    if credentials:
        print(f"\n  {Colors.RED}{Colors.BOLD}⚠  Credentials bắt được:{Colors.RESET}")
        for cred in credentials:
            print(f"     {Colors.RED}• [{cred['type']}] {cred['value']}{Colors.RESET}")

    print()


def cmd_help(args=None):
    """Hiển thị hướng dẫn sử dụng chi tiết"""
    banner()
    print(f"""{Colors.BOLD}HƯỚNG DẪN SỬ DỤNG{Colors.RESET}

  NSM (Network Security Monitor) là công cụ CLI để bắt, phân tích
  và giám sát gói tin mạng. Công cụ hỗ trợ phân tích đa tầng từ
  Ethernet → IP → TCP/UDP/ICMP/ARP → DNS/HTTP.

{Colors.BOLD}CÁC LỆNH:{Colors.RESET}

  {Colors.GREEN}interfaces{Colors.RESET}     Liệt kê tất cả network interfaces trên máy

  {Colors.GREEN}capture{Colors.RESET}        Bắt gói tin trực tiếp (Live Capture)
    -i, --interface   Tên interface (mặc định: auto)
    -f, --filter      BPF filter (vd: "tcp port 80")
    -c, --count       Số gói cần bắt (0 = vô hạn)
    -o, --output      Lưu ra file PCAP chỉ định
    -s, --save        Tự động lưu ra file PCAP (tên theo timestamp)
    -d, --detail      Hiển thị chi tiết từng tầng giao thức
    -x, --hex         Hiển thị hex dump
    -j, --json        Xuất kết quả dạng JSON

  {Colors.GREEN}read{Colors.RESET}           Đọc và phân tích file PCAP
    FILE              Đường dẫn file .pcap
    -d, --detail      Hiển thị chi tiết
    -x, --hex         Hiển thị hex dump
    -j, --json        Xuất dạng JSON

  {Colors.GREEN}stats{Colors.RESET}          Thống kê tổng hợp từ file PCAP
    FILE              Đường dẫn file .pcap

{Colors.BOLD}TÍNH NĂNG:{Colors.RESET}

  {Colors.CYAN}🔍 Bắt gói tin (Sniffer){Colors.RESET}
     • Live capture trên bất kỳ interface nào
     • Hỗ trợ BPF filter (Berkeley Packet Filter)
     • Lưu/đọc file PCAP để phân tích offline

  {Colors.CYAN}📋 Phân tích đa tầng (Protocol Analyzer){Colors.RESET}
     • Tầng 2 — Ethernet: MAC nguồn/đích, EtherType
     • Tầng 3 — IP: địa chỉ IP, TTL, OS fingerprinting
     • Tầng 4 — TCP: flags (SYN/ACK/FIN/RST), ports, service
     • Tầng 4 — UDP: ports, service detection
     • ICMP: type/code giải nghĩa (ping, unreachable...)
     • ARP: request/reply, mapping MAC ↔ IP

  {Colors.CYAN}🌐 Phân tích tầng ứng dụng (Application Layer){Colors.RESET}
     • DNS: query/response, phát hiện DNS Tunneling
     • HTTP: method, URL, headers, response code
     • Tự động phát hiện credentials trong HTTP

  {Colors.CYAN}📊 Thống kê & Cảnh báo{Colors.RESET}
     • Phân bố giao thức
     • Top IP nguồn/đích
     • Dịch vụ phát hiện
     • Cảnh báo DNS đáng ngờ
     • Cảnh báo credentials bị lộ

  {Colors.CYAN}🛠️  Tiện ích{Colors.RESET}
     • Hex dump hiển thị raw bytes
     • Xuất JSON cho tích hợp hệ thống
     • Passive OS fingerprinting từ TTL

{Colors.BOLD}VÍ DỤ SỬ DỤNG:{Colors.RESET}

  {Colors.DIM}# Xem danh sách interfaces{Colors.RESET}
  python main.py interfaces

  {Colors.DIM}# Bắt 20 gói TCP trên port 80, hiện chi tiết{Colors.RESET}
  python main.py capture -f "tcp port 80" -c 20 -d

  {Colors.DIM}# Bắt tất cả gói DNS, lưu ra file{Colors.RESET}
  python main.py capture -f "port 53" -c 50 -o dns_traffic.pcap

  {Colors.DIM}# Bắt không giới hạn, tự lưu file{Colors.RESET}
  python main.py capture -s

  {Colors.DIM}# Phân tích file PCAP với hex dump{Colors.RESET}
  python main.py read captures/demo.pcap -d -x

  {Colors.DIM}# Xuất JSON từ file PCAP{Colors.RESET}
  python main.py read captures/demo.pcap -j

  {Colors.DIM}# Xem thống kê tổng hợp{Colors.RESET}
  python main.py stats captures/demo.pcap

{Colors.BOLD}LƯU Ý:{Colors.RESET}
  • Cần quyền Administrator (Windows) hoặc root (Linux) để bắt gói tin
  • Cài đặt: pip install -r requirement.txt
  • Npcap (Windows) hoặc libpcap (Linux) phải được cài sẵn
""")


# ═══════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER — Xây dựng CLI
# ═══════════════════════════════════════════════════════════════════

def build_parser():
    """Tạo argument parser cho CLI"""

    parser = argparse.ArgumentParser(
        prog="nsm",
        description="NSM — Network Security Monitor: Công cụ bắt & phân tích gói tin mạng",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Sử dụng 'python main.py help' để xem hướng dẫn chi tiết."
    )

    subparsers = parser.add_subparsers(dest="command", help="Lệnh cần thực thi")

    # ── interfaces ────────────────────────────────────────────────
    sub_iface = subparsers.add_parser(
        "interfaces",
        aliases=["ifaces", "if"],
        help="Liệt kê tất cả network interfaces"
    )
    sub_iface.set_defaults(func=cmd_interfaces)

    # ── capture ───────────────────────────────────────────────────
    sub_cap = subparsers.add_parser(
        "capture",
        aliases=["cap", "sniff"],
        help="Bắt gói tin trực tiếp (Live Capture)"
    )
    sub_cap.add_argument("-i", "--interface", default=None,
                         help="Tên interface (mặc định: auto)")
    sub_cap.add_argument("-f", "--filter", default="",
                         help="BPF filter, vd: 'tcp port 80'")
    sub_cap.add_argument("-c", "--count", type=int, default=0,
                         help="Số gói cần bắt (0 = vô hạn)")
    sub_cap.add_argument("-o", "--output", default=None,
                         help="Lưu ra file PCAP chỉ định")
    sub_cap.add_argument("-s", "--save", action="store_true",
                         help="Tự động lưu file PCAP (tên theo timestamp)")
    sub_cap.add_argument("-d", "--detail", action="store_true",
                         help="Hiển thị chi tiết từng tầng giao thức")
    sub_cap.add_argument("-x", "--hex", action="store_true",
                         help="Hiển thị hex dump (raw bytes)")
    sub_cap.add_argument("-j", "--json", action="store_true",
                         help="Xuất kết quả dạng JSON")
    sub_cap.set_defaults(func=cmd_capture)

    # ── read ──────────────────────────────────────────────────────
    sub_read = subparsers.add_parser(
        "read",
        aliases=["pcap", "load"],
        help="Đọc và phân tích file PCAP"
    )
    sub_read.add_argument("file", help="Đường dẫn file .pcap")
    sub_read.add_argument("-d", "--detail", action="store_true",
                          help="Hiển thị chi tiết")
    sub_read.add_argument("-x", "--hex", action="store_true",
                          help="Hiển thị hex dump")
    sub_read.add_argument("-j", "--json", action="store_true",
                          help="Xuất dạng JSON")
    sub_read.set_defaults(func=cmd_read)

    # ── stats ─────────────────────────────────────────────────────
    sub_stats = subparsers.add_parser(
        "stats",
        aliases=["stat", "summary"],
        help="Thống kê tổng hợp từ file PCAP"
    )
    sub_stats.add_argument("file", help="Đường dẫn file .pcap")
    sub_stats.set_defaults(func=cmd_stats)

    # ── help ──────────────────────────────────────────────────────
    sub_help = subparsers.add_parser(
        "help",
        help="Hiển thị hướng dẫn sử dụng chi tiết"
    )
    sub_help.set_defaults(func=cmd_help)

    return parser


# ═══════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Nếu không có lệnh nào → hiển thị help
    if not args.command:
        banner()
        parser.print_help()
        print()
        return

    # Chạy lệnh tương ứng
    banner()
    args.func(args)


if __name__ == "__main__":
    main()
