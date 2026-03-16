#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              NSM — Network Security Monitor CLI                 ║
║  Công cụ giám sát an ninh mạng — Bắt & Phân tích gói tin       ║
║  100% Python thuần — KHÔNG dùng Scapy                           ║
╚══════════════════════════════════════════════════════════════════╝
"""

import argparse
import json
import sys
import os
from datetime import datetime

from sniffer.capture import PacketCapture
from analyzer.protocol import analyze_packet
from analyzer.raw_parser import hex_dump


# ═══════════════════════════════════════════════════════════════════
#  TIỆN ÍCH HIỂN THỊ
# ═══════════════════════════════════════════════════════════════════

class Colors:
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
    print(f"""{Colors.CYAN}{Colors.BOLD}
    ╔══════════════════════════════════════╗
    ║   NSM — Network Security Monitor    ║
    ║   100% Pure Python (Raw Socket)     ║
    ╚══════════════════════════════════════╝
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
#  CALLBACK
# ═══════════════════════════════════════════════════════════════════

_packet_counter = {"count": 0}


def _make_callback(detail=False, show_hex=False, show_json=False):
    def callback(raw_bytes):
        _packet_counter["count"] += 1
        n = _packet_counter["count"]
        result = analyze_packet(raw_bytes)

        proto = result.get("transport_proto", "?")
        summary = result.get("summary", "")

        if show_json:
            safe = _safe_json(result)
            print(json.dumps(safe, indent=2, ensure_ascii=False))
            print()
            return

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

        if detail:
            _print_detail(result)

        if show_hex:
            print(f"\n{Colors.DIM}{hex_dump(raw_bytes)}{Colors.RESET}\n")

        app = result.get("app_layer", {})
        dns = app.get("dns", {})
        if dns.get("is_suspicious"):
            print_warning(f"DNS đáng ngờ: {dns.get('suspicious_reason', '')}")

        http = app.get("http", {})
        if http.get("credentials_found"):
            print_warning(f"PHÁT HIỆN CREDENTIALS: {http.get('credentials', [])}")

    return callback


def _print_detail(result):
    eth = result.get("ethernet", {})
    if eth:
        print(f"      {Colors.DIM}├─ Ethernet: "
              f"{eth.get('src_mac','?')} → {eth.get('dst_mac','?')} "
              f"[{eth.get('ethertype_name', '')}]{Colors.RESET}")

    ip = result.get("ip", {})
    if ip:
        print(f"      {Colors.DIM}├─ IP: "
              f"v{ip.get('version','')} | "
              f"TTL={ip.get('ttl','?')} ({ip.get('os_guess','')}) | "
              f"proto={ip.get('protocol_name','')} | "
              f"len={ip.get('total_length','')}B{Colors.RESET}")

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

    payload = result.get("payload", {})
    if payload:
        print(f"      {Colors.DIM}└─ Payload: "
              f"{payload.get('payload_length', 0)} bytes{Colors.RESET}")


def _safe_json(obj):
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
#  CÁC LỆNH CLI
# ═══════════════════════════════════════════════════════════════════

def cmd_interfaces(args):
    print_header("NETWORK INTERFACES")
    interfaces = PacketCapture.list_interfaces()

    if not interfaces:
        print_error("Không tìm thấy interface nào.")
        return

    for i, iface in enumerate(interfaces, 1):
        print(f"  {Colors.GREEN}{i:>3}.{Colors.RESET} {Colors.BOLD}{iface['name']}{Colors.RESET}")
        print(f"       {Colors.DIM}IP  : {iface.get('ip', 'N/A')}{Colors.RESET}")
        print(f"       {Colors.DIM}MAC : {iface.get('mac', 'N/A')}{Colors.RESET}")
        print()

    print(f"  {Colors.DIM}Tổng cộng: {len(interfaces)} interface(s){Colors.RESET}")
    print(f"  {Colors.DIM}Sử dụng: sudo python main.py capture -i <tên interface>{Colors.RESET}\n")


def cmd_capture(args):
    print_header("LIVE CAPTURE (Raw Socket)")

    print_info(f"Interface : {args.interface or 'tất cả'}")
    print_info(f"Số gói    : {args.count if args.count > 0 else 'không giới hạn'}")
    print_info(f"Chi tiết  : {'Có' if args.detail else 'Không'}")
    print()

    _packet_counter["count"] = 0

    cb = _make_callback(
        detail=args.detail,
        show_hex=args.hex,
        show_json=args.json,
    )

    cap = PacketCapture()
    cap.start_live_capture(
        interface=args.interface,
        count=args.count,
        callback=cb,
    )

    if args.output and cap.captured_packets:
        PacketCapture.save_to_pcap(cap.captured_packets, args.output)
        print_success(f"Đã lưu {len(cap.captured_packets)} gói → {args.output}")
    elif args.save and cap.captured_packets:
        filepath = PacketCapture.save_to_pcap(cap.captured_packets)
        print_success(f"Đã tự động lưu → {filepath}")

    total = _packet_counter["count"]
    print(f"\n  {Colors.DIM}Tổng cộng: {total} gói tin đã xử lý{Colors.RESET}\n")


def cmd_read(args):
    filepath = args.file
    print_header(f"ĐỌC FILE PCAP: {filepath}")

    if not os.path.exists(filepath):
        print_error(f"Không tìm thấy file: {filepath}")
        sys.exit(1)

    _packet_counter["count"] = 0

    cb = _make_callback(
        detail=args.detail,
        show_hex=args.hex,
        show_json=args.json,
    )

    packets = PacketCapture.load_from_pcap(filepath, callback=cb)
    total = len(packets)
    print(f"\n  {Colors.DIM}Tổng cộng: {total} gói tin từ file{Colors.RESET}\n")


def cmd_stats(args):
    filepath = args.file
    print_header(f"THỐNG KÊ FILE: {filepath}")

    if not os.path.exists(filepath):
        print_error(f"Không tìm thấy file: {filepath}")
        sys.exit(1)

    packets = PacketCapture.load_from_pcap(filepath)

    if not packets:
        print_warning("File không chứa gói tin nào.")
        return

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

    total = len(packets)

    print(f"  {Colors.BOLD}Phân bố giao thức ({total} gói):{Colors.RESET}")
    for proto, count in sorted(proto_count.items(), key=lambda x: -x[1]):
        pct = count / total * 100
        print(f"     {proto:<8} {count:>5}  ({pct:5.1f}%)")

    print(f"\n  {Colors.BOLD}Top 10 IP nguồn:{Colors.RESET}")
    for ip, count in sorted(ip_src_count.items(), key=lambda x: -x[1])[:10]:
        print(f"     {ip:<20} {count:>5} gói")

    print(f"\n  {Colors.BOLD}Top 10 IP đích:{Colors.RESET}")
    for ip, count in sorted(ip_dst_count.items(), key=lambda x: -x[1])[:10]:
        print(f"     {ip:<20} {count:>5} gói")

    if suspicious_dns:
        print(f"\n  {Colors.RED}{Colors.BOLD}DNS đáng ngờ:{Colors.RESET}")
        for domain in suspicious_dns:
            print(f"     {Colors.RED}• {domain}{Colors.RESET}")

    if credentials:
        print(f"\n  {Colors.RED}{Colors.BOLD}Credentials bắt được:{Colors.RESET}")
        for cred in credentials:
            print(f"     {Colors.RED}• [{cred['type']}] {cred['value']}{Colors.RESET}")

    print()


def cmd_help(args=None):
    banner()
    print(f"""{Colors.BOLD}HƯỚNG DẪN SỬ DỤNG{Colors.RESET}

  NSM sử dụng Raw Socket (AF_PACKET) để bắt gói tin
  và struct.unpack để phân tích header — 100% Python thuần.

{Colors.BOLD}CÁC LỆNH:{Colors.RESET}

  {Colors.GREEN}interfaces{Colors.RESET}     Liệt kê tất cả network interfaces
  {Colors.GREEN}capture{Colors.RESET}        Bắt gói tin trực tiếp (cần sudo)
  {Colors.GREEN}read{Colors.RESET}           Đọc và phân tích file PCAP
  {Colors.GREEN}stats{Colors.RESET}          Thống kê tổng hợp từ file PCAP
  {Colors.GREEN}help{Colors.RESET}           Hiển thị hướng dẫn này

{Colors.BOLD}VÍ DỤ:{Colors.RESET}

  sudo python main.py interfaces
  sudo python main.py capture -i eth0 -c 20 -d
  python main.py read captures/demo.pcap -d
  python main.py stats captures/demo.pcap

{Colors.BOLD}LƯU Ý:{Colors.RESET}
  Cần quyền root (sudo) cho live capture
""")


# ═══════════════════════════════════════════════════════════════════
#  ARGUMENT PARSER
# ═══════════════════════════════════════════════════════════════════

def build_parser():
    parser = argparse.ArgumentParser(
        prog="nsm",
        description="NSM — Network Security Monitor (100% Pure Python)",
    )

    subparsers = parser.add_subparsers(dest="command")

    sub_iface = subparsers.add_parser("interfaces", aliases=["ifaces", "if"])
    sub_iface.set_defaults(func=cmd_interfaces)

    sub_cap = subparsers.add_parser("capture", aliases=["cap", "sniff"])
    sub_cap.add_argument("-i", "--interface", default=None)
    sub_cap.add_argument("-c", "--count", type=int, default=0)
    sub_cap.add_argument("-o", "--output", default=None)
    sub_cap.add_argument("-s", "--save", action="store_true")
    sub_cap.add_argument("-d", "--detail", action="store_true")
    sub_cap.add_argument("-x", "--hex", action="store_true")
    sub_cap.add_argument("-j", "--json", action="store_true")
    sub_cap.set_defaults(func=cmd_capture)

    sub_read = subparsers.add_parser("read", aliases=["pcap", "load"])
    sub_read.add_argument("file")
    sub_read.add_argument("-d", "--detail", action="store_true")
    sub_read.add_argument("-x", "--hex", action="store_true")
    sub_read.add_argument("-j", "--json", action="store_true")
    sub_read.set_defaults(func=cmd_read)

    sub_stats = subparsers.add_parser("stats", aliases=["stat", "summary"])
    sub_stats.add_argument("file")
    sub_stats.set_defaults(func=cmd_stats)

    sub_help = subparsers.add_parser("help")
    sub_help.set_defaults(func=cmd_help)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        banner()
        parser.print_help()
        return

    banner()
    args.func(args)


if __name__ == "__main__":
    main()
