"""
Protocol Analyzer — Phân tích gói tin đa tầng
Sử dụng raw_parser (Python thuần) thay vì Scapy.
"""

from datetime import datetime
from analyzer.raw_parser import (
    parse_ethernet, parse_ip, parse_tcp, parse_udp,
    parse_icmp, parse_arp, parse_dns, hex_dump,
    _guess_service, _guess_os
)
from analyzer.app_layer import analyze_dns_raw, analyze_http_raw


def analyze_packet(raw_bytes, timestamp=None):
    """
    Hàm chính — parse raw bytes thành dict chứa đầy đủ thông tin.

    Input: raw_bytes (bytes) — raw frame từ AF_PACKET hoặc PCAP file
    Output: dict giống format cũ để frontend không cần thay đổi
    """
    if timestamp is not None:
        time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
    else:
        time_str = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    result = {
        "time":            time_str,
        "ethernet":        {},
        "ip":              {},
        "transport":       {},
        "transport_proto": "OTHER",
        "app_layer":       {},
        "payload":         {},
        "summary":         ""
    }

    remaining = raw_bytes

    # ── Ethernet ──────────────────────────────────────────────────
    eth_info, remaining = parse_ethernet(raw_bytes)
    if eth_info:
        result["ethernet"] = eth_info
    else:
        return result

    ethertype = int(eth_info["ethertype"], 16) if isinstance(eth_info["ethertype"], str) else eth_info["ethertype"]

    # ── ARP ───────────────────────────────────────────────────────
    if ethertype == 0x0806:
        arp_info = parse_arp(remaining)
        if arp_info:
            result["transport_proto"] = "ARP"
            result["transport"] = arp_info
            result["summary"] = (
                f"ARP {arp_info.get('op', '')} "
                f"{arp_info.get('src_ip', '?')} → {arp_info.get('dst_ip', '?')}"
            )
        return result

    # ── IPv4 ──────────────────────────────────────────────────────
    if ethertype != 0x0800:
        return result

    ip_info, remaining = parse_ip(remaining)
    if not ip_info:
        return result
    result["ip"] = ip_info

    protocol = ip_info["protocol"]

    # ── TCP ────────────────────────────────────────────────────────
    if protocol == 6:
        tcp_info, payload = parse_tcp(remaining)
        if tcp_info:
            result["transport_proto"] = "TCP"
            result["transport"] = tcp_info

            # Payload info
            if payload:
                result["payload"] = {
                    "payload_length": len(payload),
                    "hex_dump":       hex_dump(payload[:256])  # Giới hạn 256 bytes
                }

            # App Layer: HTTP
            http = analyze_http_raw(payload, tcp_info["src_port"], tcp_info["dst_port"])
            if http:
                result["app_layer"]["http"] = http
                result["transport_proto"] = "HTTP"

    # ── UDP ────────────────────────────────────────────────────────
    elif protocol == 17:
        udp_info, payload = parse_udp(remaining)
        if udp_info:
            result["transport_proto"] = "UDP"
            result["transport"] = udp_info

            if payload:
                result["payload"] = {
                    "payload_length": len(payload),
                    "hex_dump":       hex_dump(payload[:256])
                }

            # App Layer: DNS (port 53)
            if udp_info["src_port"] == 53 or udp_info["dst_port"] == 53:
                dns = analyze_dns_raw(payload)
                if dns:
                    result["app_layer"]["dns"] = dns
                    result["transport_proto"] = "DNS"

    # ── ICMP ───────────────────────────────────────────────────────
    elif protocol == 1:
        icmp_info, payload = parse_icmp(remaining)
        if icmp_info:
            result["transport_proto"] = "ICMP"
            result["transport"] = icmp_info

    # ── Summary ────────────────────────────────────────────────────
    ip  = result["ip"]
    tr  = result["transport"]
    proto = result["transport_proto"]

    if proto in ("TCP", "UDP", "HTTP"):
        result["summary"] = (
            f"{ip.get('src_ip', '?')}:{tr.get('src_port', '?')} → "
            f"{ip.get('dst_ip', '?')}:{tr.get('dst_port', '?')} "
            f"[{tr.get('service', '')}]"
        )
    elif proto == "DNS":
        dns = result["app_layer"].get("dns", {})
        queries = dns.get("queries", [])
        qname = queries[0]["name"] if queries else "?"
        result["summary"] = (
            f"{ip.get('src_ip', '?')} → {ip.get('dst_ip', '?')} "
            f"DNS {dns.get('type', '')} {qname}"
        )
    elif proto == "ICMP":
        result["summary"] = (
            f"{ip.get('src_ip', '?')} → {ip.get('dst_ip', '?')} "
            f"ICMP {tr.get('meaning', '')}"
        )

    return result