"""
╔══════════════════════════════════════════════════════════════════╗
║       RAW PACKET PARSER — 100% Python thuần                     ║
║  Parse Ethernet / IP / TCP / UDP / ICMP / ARP / DNS             ║
║  bằng struct.unpack — KHÔNG dùng Scapy                          ║
╚══════════════════════════════════════════════════════════════════╝
"""

import struct
import socket


# ═══════════════════════════════════════════════════════════════════
#  ETHERNET HEADER (14 bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_ethernet(data):
    """
    Parse Ethernet II frame header.

    Cấu trúc (14 bytes):
    ┌──────────────┬──────────────┬────────────┐
    │ Dst MAC (6B) │ Src MAC (6B) │ Type (2B)  │
    └──────────────┴──────────────┴────────────┘

    EtherType phổ biến:
      0x0800 = IPv4
      0x0806 = ARP
      0x86DD = IPv6
    """
    if len(data) < 14:
        return None, data

    dst_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])

    ethertype_map = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "VLAN"
    }

    return {
        "src_mac":        _format_mac(src_mac),
        "dst_mac":        _format_mac(dst_mac),
        "ethertype":      hex(ethertype),
        "ethertype_name": ethertype_map.get(ethertype, "Unknown")
    }, data[14:]


# ═══════════════════════════════════════════════════════════════════
#  IPv4 HEADER (20+ bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_ip(data):
    """
    Parse IPv4 header.

    Cấu trúc (20 bytes tối thiểu):
    ┌─────────┬─────┬──────┬────────────────┐
    │ Ver+IHL │ TOS │ Len  │ ID             │
    ├─────────┴─────┴──────┼────────────────┤
    │ Flags + Offset       │ TTL │Proto│Chk │
    ├──────────────────────┴─────┴─────┴────┤
    │ Source IP (4 bytes)                    │
    ├───────────────────────────────────────┤
    │ Destination IP (4 bytes)              │
    └───────────────────────────────────────┘
    """
    if len(data) < 20:
        return None, data

    # Byte đầu tiên chứa cả Version (4 bit cao) và IHL (4 bit thấp)
    version_ihl = data[0]
    version     = version_ihl >> 4
    ihl         = (version_ihl & 0x0F) * 4  # IHL tính bằng 32-bit words → nhân 4 ra bytes

    if len(data) < ihl:
        return None, data

    tos, total_length, identification, flags_offset, ttl, protocol, checksum = \
        struct.unpack('!BHHHBBH', data[1:12])

    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])

    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 89: "OSPF"}

    return {
        "version":       version,
        "ihl":           ihl,
        "tos":           tos,
        "total_length":  total_length,
        "ttl":           ttl,
        "protocol":      protocol,
        "protocol_name": proto_map.get(protocol, f"Unknown({protocol})"),
        "checksum":      hex(checksum),
        "src_ip":        src_ip,
        "dst_ip":        dst_ip,
        "os_guess":      _guess_os(ttl)
    }, data[ihl:]


# ═══════════════════════════════════════════════════════════════════
#  TCP HEADER (20+ bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_tcp(data):
    """
    Parse TCP header.

    Cấu trúc (20 bytes tối thiểu):
    ┌──────────┬──────────┐
    │ SrcPort  │ DstPort  │
    ├──────────┴──────────┤
    │ Sequence Number     │
    ├─────────────────────┤
    │ Ack Number          │
    ├────┬────┬───────────┤
    │Off │Flg │ Window    │
    ├────┴────┼───────────┤
    │Checksum │ Urgent    │
    └─────────┴───────────┘
    """
    if len(data) < 20:
        return None, b""

    src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = \
        struct.unpack('!HHIIHHH H', data[:20])

    # Data offset: 4 bit cao của offset_flags → số lượng 32-bit words
    data_offset = ((offset_flags >> 12) & 0x0F) * 4
    flags_raw   = offset_flags & 0x3F

    flag_details = {
        "SYN": bool(flags_raw & 0x02),
        "ACK": bool(flags_raw & 0x10),
        "FIN": bool(flags_raw & 0x01),
        "RST": bool(flags_raw & 0x04),
        "PSH": bool(flags_raw & 0x08),
        "URG": bool(flags_raw & 0x20),
    }
    active_flags = [name for name, val in flag_details.items() if val]

    payload = data[data_offset:] if data_offset <= len(data) else b""

    return {
        "src_port":     src_port,
        "dst_port":     dst_port,
        "service":      _guess_service(src_port, dst_port),
        "seq":          seq,
        "ack":          ack,
        "data_offset":  data_offset,
        "flags_raw":    str(flags_raw),
        "flags":        flag_details,
        "flags_active": active_flags,
        "window_size":  window,
        "checksum":     hex(checksum),
        "urgent_ptr":   urgent
    }, payload


# ═══════════════════════════════════════════════════════════════════
#  UDP HEADER (8 bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_udp(data):
    """
    Parse UDP header.

    Cấu trúc (8 bytes):
    ┌──────────┬──────────┐
    │ SrcPort  │ DstPort  │
    ├──────────┼──────────┤
    │ Length   │ Checksum │
    └──────────┴──────────┘
    """
    if len(data) < 8:
        return None, b""

    src_port, dst_port, length, checksum = struct.unpack('!HHHH', data[:8])

    return {
        "src_port": src_port,
        "dst_port": dst_port,
        "service":  _guess_service(src_port, dst_port),
        "length":   length,
        "checksum": hex(checksum)
    }, data[8:]


# ═══════════════════════════════════════════════════════════════════
#  ICMP HEADER (8 bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_icmp(data):
    """
    Parse ICMP header.

    Cấu trúc (8 bytes):
    ┌──────┬──────┬──────────┐
    │ Type │ Code │ Checksum │
    ├──────┴──────┼──────────┤
    │ Rest of Header         │
    └────────────────────────┘
    """
    if len(data) < 4:
        return None, b""

    icmp_type, code, checksum = struct.unpack('!BBH', data[:4])

    meanings = {
        0:  "Echo Reply (ping trả lời)",
        3:  "Destination Unreachable (không đến được đích)",
        8:  "Echo Request (ping)",
        11: "Time Exceeded (TTL hết, gói bị hủy)"
    }

    return {
        "type":    icmp_type,
        "code":    code,
        "meaning": meanings.get(icmp_type, f"Type {icmp_type}")
    }, data[8:]


# ═══════════════════════════════════════════════════════════════════
#  ARP HEADER (28 bytes)
# ═══════════════════════════════════════════════════════════════════

def parse_arp(data):
    """
    Parse ARP header.

    Cấu trúc (28 bytes cho Ethernet+IPv4):
    ┌──────────┬──────────┬───┬───┬──────┐
    │ HW Type  │Proto Type│HWL│PL │ Op   │
    ├──────────┴──────────┴───┴───┴──────┤
    │ Sender MAC (6B) │ Sender IP (4B)   │
    ├──────────────────┼─────────────────┤
    │ Target MAC (6B)  │ Target IP (4B)  │
    └──────────────────┴─────────────────┘
    """
    if len(data) < 28:
        return None

    hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack('!HHBBH', data[:8])

    src_mac = _format_mac(data[8:14])
    src_ip  = socket.inet_ntoa(data[14:18])
    dst_mac = _format_mac(data[18:24])
    dst_ip  = socket.inet_ntoa(data[24:28])

    return {
        "op":      "Request" if opcode == 1 else "Reply",
        "src_mac": src_mac,
        "src_ip":  src_ip,
        "dst_mac": dst_mac,
        "dst_ip":  dst_ip
    }


# ═══════════════════════════════════════════════════════════════════
#  DNS MESSAGE PARSER
# ═══════════════════════════════════════════════════════════════════

def parse_dns(data):
    """
    Parse DNS message từ raw bytes (UDP payload).

    Cấu trúc DNS header (12 bytes):
    ┌────────────────────┐
    │ Transaction ID (2B)│
    ├────────────────────┤
    │ Flags (2B)         │
    ├────────────────────┤
    │ Questions (2B)     │
    ├────────────────────┤
    │ Answer RRs (2B)    │
    ├────────────────────┤
    │ Authority RRs (2B) │
    ├────────────────────┤
    │ Additional RRs (2B)│
    └────────────────────┘
    Sau đó là Question Section, Answer Section,...
    """
    if len(data) < 12:
        return None

    tx_id, flags, qd_count, an_count, ns_count, ar_count = \
        struct.unpack('!HHHHHH', data[:12])

    is_response = bool(flags & 0x8000)

    result = {
        "type":              "response" if is_response else "query",
        "tx_id":             tx_id,
        "queries":           [],
        "answers":           [],
        "is_suspicious":     False,
        "suspicious_reason": ""
    }

    offset = 12

    # ── Parse Question Section ─────────────────────────────────────
    for _ in range(qd_count):
        name, offset = _parse_dns_name(data, offset)
        if offset + 4 > len(data):
            break
        qtype, qclass = struct.unpack('!HH', data[offset:offset+4])
        offset += 4

        query_type_map = {1: "A", 2: "NS", 5: "CNAME", 15: "MX", 16: "TXT", 28: "AAAA"}
        result["queries"].append({
            "name": name,
            "type": query_type_map.get(qtype, f"TYPE{qtype}")
        })

    # ── Parse Answer Section ───────────────────────────────────────
    for _ in range(an_count):
        name, offset = _parse_dns_name(data, offset)
        if offset + 10 > len(data):
            break

        rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', data[offset:offset+10])
        offset += 10

        if offset + rdlength > len(data):
            break

        rdata_raw = data[offset:offset+rdlength]
        offset += rdlength

        # Giải mã rdata tùy loại record
        if rtype == 1 and rdlength == 4:        # A record
            rdata = socket.inet_ntoa(rdata_raw)
        elif rtype == 28 and rdlength == 16:    # AAAA record
            rdata = socket.inet_ntop(socket.AF_INET6, rdata_raw)
        elif rtype == 5:                         # CNAME
            rdata, _ = _parse_dns_name(data, offset - rdlength)
        else:
            rdata = rdata_raw.hex()

        result["answers"].append({
            "name":  name,
            "rdata": str(rdata),
            "ttl":   ttl
        })

    # ── Kiểm tra DNS đáng ngờ ─────────────────────────────────────
    if result["queries"]:
        query_name = result["queries"][0]["name"]
        result["is_suspicious"], result["suspicious_reason"] = \
            _check_dns_suspicious(query_name)

    return result


def _parse_dns_name(data, offset):
    """
    Parse DNS domain name từ tin nhắn.

    DNS sử dụng Label Encoding:
      - Mỗi label bắt đầu bằng 1 byte length, theo sau là các ký tự
      - Label kết thúc bằng byte 0x00
      - Hoặc DNS Compression: 2 byte pointer (bit cao = 11xxxxxx)

    Ví dụ: \\x06google\\x03com\\x00 → "google.com"
    """
    labels = []
    jumped = False
    max_jumps = 20  # Chống infinite loop
    jumps = 0
    original_offset = offset

    while offset < len(data) and jumps < max_jumps:
        length = data[offset]

        if length == 0:
            # Kết thúc tên miền
            if not jumped:
                original_offset = offset + 1
            break

        # DNS Compression pointer (2 bit cao = 11)
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            jumps += 1
            continue

        # Label bình thường
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
        offset += length

    return ".".join(labels), original_offset


# ═══════════════════════════════════════════════════════════════════
#  HÀM TIỆN ÍCH
# ═══════════════════════════════════════════════════════════════════

def _format_mac(mac_bytes):
    """Chuyển 6 bytes MAC address thành chuỗi 'aa:bb:cc:dd:ee:ff'"""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def _guess_os(ttl):
    """Đoán hệ điều hành dựa vào TTL — kỹ thuật passive fingerprinting"""
    if ttl <= 64:
        return "Linux/macOS"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device"


def _guess_service(sport, dport):
    """Đoán dịch vụ từ số cổng"""
    port_map = {
        80:   "HTTP",
        443:  "HTTPS",
        22:   "SSH",
        21:   "FTP",
        25:   "SMTP",
        53:   "DNS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Alt"
    }
    return port_map.get(dport) or port_map.get(sport) or f"port {dport}"


def _check_dns_suspicious(domain):
    """
    Phát hiện DNS đáng ngờ (DNS Tunneling).

    Dấu hiệu:
    1. Tên miền quá dài (>20 ký tự)
    2. Quá nhiều subdomain (>2 cấp)
    3. Subdomain chứa toàn ký tự hex/base64
    """
    reasons = []
    parts = domain.split(".")

    if len(domain) > 20:
        reasons.append(f"Ten mien qua dai ({len(domain)} ky tu)")

    if len(parts) > 2:
        reasons.append(f"Qua nhieu subdomain ({len(parts)} cap)")

    if len(parts) > 2:
        subdomain = parts[0]
        hex_ratio = sum(1 for c in subdomain if c in "0123456789abcdef") / max(len(subdomain), 1)
        if len(subdomain) > 20 and hex_ratio > 0.8:
            reasons.append("Subdomain co ve la du lieu ma hoa")

    if reasons:
        return True, " | ".join(reasons)
    return False, ""


def hex_dump(raw_data, width=16):
    """
    Tạo hex dump như tcpdump -X
    Ví dụ:
    0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
    """
    lines = []
    for i in range(0, len(raw_data), width):
        chunk = raw_data[i:i+width]
        offset = f"{i:04x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset}  {hex_part}  {ascii_part}")
    return "\n".join(lines)
