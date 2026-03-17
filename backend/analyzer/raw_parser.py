import struct
import socket

def parse_ethernet(data):
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
        "src_mac": _format_mac(src_mac),
        "dst_mac":  _format_mac(dst_mac),
        "ethertype": hex(ethertype),
        "ethertype_name": ethertype_map.get(ethertype, "Unknown")
    }, data[14:]

def parse_ip(data):
    if len(data) < 20:
        return None, data
    version_ihl = data[0]
    version     = version_ihl >> 4
    ihl         = (version_ihl & 0x0F) * 4 
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

def parse_tcp(data):
    if len(data) < 20:
        return None, b""
    src_port, dst_port, seq, ack, offset_flags, window, checksum, urgent = \
        struct.unpack('!HHIIHHH H', data[:20])
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
        "src_port": src_port,
        "dst_port": dst_port,
        "service": _guess_service(src_port, dst_port),
        "seq": seq,
        "ack": ack,
        "data_offset": data_offset,
        "flags_raw": str(flags_raw),
        "flags": flag_details,
        "flags_active": active_flags,
        "window_size": window,
        "checksum": hex(checksum),
        "urgent_ptr": urgent
    }, payload

def parse_udp(data):
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

def parse_icmp(data):
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

def parse_arp(data):
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

def parse_dns(data):
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
        if rtype == 1 and rdlength == 4:
            rdata = socket.inet_ntoa(rdata_raw)
        elif rtype == 28 and rdlength == 16:
            rdata = socket.inet_ntop(socket.AF_INET6, rdata_raw)
        elif rtype == 5:
            rdata, _ = _parse_dns_name(data, offset - rdlength)
        else:
            rdata = rdata_raw.hex()
        result["answers"].append({
            "name":  name,
            "rdata": str(rdata),
            "ttl":   ttl
        })
    if result["queries"]:
        query_name = result["queries"][0]["name"]
        result["is_suspicious"], result["suspicious_reason"] = \
            _check_dns_suspicious(query_name)
    return result

def _parse_dns_name(data, offset):
    labels = []
    jumped = False
    max_jumps = 20  
    jumps = 0
    original_offset = offset
    while offset < len(data) and jumps < max_jumps:
        length = data[offset]
        if length == 0:
            if not jumped:
                original_offset = offset + 1
            break
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
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset+length].decode('utf-8', errors='replace'))
        offset += length
    return ".".join(labels), original_offset

def _format_mac(mac_bytes):
    return ":".join(f"{b:02x}" for b in mac_bytes)

def _guess_os(ttl):
    if ttl <= 64:
        return "Linux/macOS"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device"

def _guess_service(sport, dport):
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
    lines = []
    for i in range(0, len(raw_data), width):
        chunk = raw_data[i:i+width]
        offset = f"{i:04x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(width * 3)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {offset}  {hex_part}  {ascii_part}")
    return "\n".join(lines)
