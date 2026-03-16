from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether, Raw
from datetime import datetime
from analyzer.app_layer import analyze_dns, analyze_http

def analyze_ethernet(packet):
    """
    Tầng 1: Ethernet Header
    - Mỗi thiết bị mạng có 1 địa chỉ MAC duy nhất (như số serial của card mạng)
    - EtherType cho biết bên trong đang dùng giao thức gì (IP, ARP,...)
    """
    if Ether not in packet:
        return {}

    ether = packet[Ether]

    # EtherType phổ biến
    ethertype_map = {
        0x0800: "IPv4",
        0x0806: "ARP",
        0x86DD: "IPv6",
        0x8100: "VLAN"
    }

    return {
        "src_mac":   ether.src,              # địa chỉ MAC máy gửi
        "dst_mac":   ether.dst,              # địa chỉ MAC máy nhận
        "ethertype": hex(ether.type),        # kiểu giao thức bên trong
        "ethertype_name": ethertype_map.get(ether.type, "Unknown")
    }


def analyze_ip(packet):
    """
    Tầng 2: IP Header
    - version: IPv4 hay IPv6
    - ihl: độ dài header tính bằng byte (quan trọng để tìm TCP header tiếp theo)
    - ttl: Time To Live — mỗi router giảm 1, về 0 thì gói bị hủy
           TTL=64 thường là Linux, TTL=128 thường là Windows
    - proto: giao thức bên trong (6=TCP, 17=UDP, 1=ICMP)
    - checksum: mã kiểm tra lỗi header
    """
    if IP not in packet:
        return {}

    ip = packet[IP]

    # Mapping số protocol → tên
    proto_map = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 89: "OSPF"}

    return {
        "version":       ip.version,
        "ihl":           ip.ihl * 4,           # nhân 4 để ra byte (như Chương 4 giải thích)
        "tos":           ip.tos,               # Type of Service — độ ưu tiên gói tin
        "total_length":  ip.len,               # tổng kích thước gói (header + payload)
        "ttl":           ip.ttl,               # Time To Live
        "protocol":      ip.proto,
        "protocol_name": proto_map.get(ip.proto, f"Unknown({ip.proto})"),
        "checksum":      hex(ip.chksum),       # kiểm tra lỗi
        "src_ip":        ip.src,
        "dst_ip":        ip.dst,
        # Đoán hệ điều hành từ TTL (kỹ thuật passive OS fingerprinting)
        "os_guess":      _guess_os(ip.ttl)
    }


def analyze_tcp(packet):
    """
    Tầng 3: TCP Header
    - sport/dport: cổng nguồn và đích (80=HTTP, 443=HTTPS, 22=SSH...)
    - seq/ack: số thứ tự — dùng để ghép lại dữ liệu đúng thứ tự
    - data_offset: độ dài TCP header (giống IHL của IP)
    - flags: trạng thái kết nối
        S  = SYN  → đang bắt đầu kết nối
        A  = ACK  → xác nhận đã nhận
        F  = FIN  → đang đóng kết nối
        R  = RST  → đóng kết nối ngay lập tức (có thể là lỗi/tấn công)
        SA = SYN-ACK → phản hồi kết nối
    - window: buffer size — lượng dữ liệu có thể nhận trước khi cần ACK
    """
    if TCP not in packet:
        return {}

    tcp = packet[TCP]

    # Giải nghĩa từng flag
    flags = tcp.flags
    flag_details = {
        "SYN": bool(flags & 0x02),   # bắt đầu kết nối
        "ACK": bool(flags & 0x10),   # xác nhận
        "FIN": bool(flags & 0x01),   # đóng kết nối
        "RST": bool(flags & 0x04),   # reset kết nối
        "PSH": bool(flags & 0x08),   # đẩy dữ liệu ngay
        "URG": bool(flags & 0x20),   # dữ liệu khẩn cấp
    }

    active_flags = [name for name, val in flag_details.items() if val]

    return {
        "src_port":    tcp.sport,
        "dst_port":    tcp.dport,
        "service":     _guess_service(tcp.sport, tcp.dport),
        "seq":         tcp.seq,
        "ack":         tcp.ack,
        "data_offset": tcp.dataofs * 4,    # nhân 4 ra byte
        "flags_raw":   str(flags),
        "flags":       flag_details,
        "flags_active": active_flags,       # ví dụ: ["SYN"] hoặc ["SYN","ACK"]
        "window_size": tcp.window,
        "checksum":    hex(tcp.chksum),
        "urgent_ptr":  tcp.urgptr
    }


def analyze_udp(packet):
    """UDP đơn giản hơn TCP — không có kết nối, không đảm bảo thứ tự"""
    if UDP not in packet:
        return {}
    udp = packet[UDP]
    return {
        "src_port": udp.sport,
        "dst_port": udp.dport,
        "service":  _guess_service(udp.sport, udp.dport),
        "length":   udp.len,
        "checksum": hex(udp.chksum)
    }


def analyze_payload(packet):
    """
    Lấy raw payload (nội dung thực sự của gói tin)
    và hiển thị dạng HEX + ASCII như tcpdump -X
    """
    if Raw not in packet:
        return {}

    raw_data = bytes(packet[Raw])
    hex_dump = _format_hex_dump(raw_data)

    return {
        "payload_length": len(raw_data),
        "hex_dump":       hex_dump,
    }


# ─── Hàm phân tích tổng hợp ───────────────────────────────────────────────

def analyze_packet(packet):
    """
    Hàm chính — gọi toàn bộ các hàm phân tích ở trên
    Trả về 1 dict chứa đầy đủ thông tin của gói tin
    """
    result = {
        "time":      datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "ethernet":  analyze_ethernet(packet),
        "ip":        analyze_ip(packet),
        "transport": {},
        "payload":   analyze_payload(packet),
        "summary":   ""
    }

    # Xác định giao thức tầng transport
    if TCP in packet:
        result["transport_proto"] = "TCP"
        result["transport"]       = analyze_tcp(packet)
    elif UDP in packet:
        result["transport_proto"] = "UDP"
        result["transport"]       = analyze_udp(packet)
    elif ICMP in packet:
        result["transport_proto"] = "ICMP"
        result["transport"]       = {
            "type": packet[ICMP].type,
            "code": packet[ICMP].code,
            "meaning": _icmp_meaning(packet[ICMP].type)
        }
    elif ARP in packet:
        result["transport_proto"] = "ARP"
        result["transport"]       = {
            "op":      "Request" if packet[ARP].op == 1 else "Reply",
            "src_ip":  packet[ARP].psrc,
            "dst_ip":  packet[ARP].pdst,
            "src_mac": packet[ARP].hwsrc,
            "dst_mac": packet[ARP].hwdst
        }
    else:
        result["transport_proto"] = "OTHER"

    result["app_layer"] = {}

    if DNS in packet:
        result["app_layer"]["dns"] = analyze_dns(packet)
        result["transport_proto"]  = "DNS"

    http = analyze_http(packet)
    if http:
        result["app_layer"]["http"] = http
        result["transport_proto"]   = "HTTP"

    # Tạo dòng tóm tắt ngắn gọn (hiển thị trên bảng)
    ip   = result["ip"]
    tr   = result["transport"]
    proto = result["transport_proto"]

    if proto in ("TCP", "UDP"):
        result["summary"] = (
            f"{ip.get('src_ip','?')}:{tr.get('src_port','?')} → "
            f"{ip.get('dst_ip','?')}:{tr.get('dst_port','?')} "
            f"[{tr.get('service','')}]"
        )
    elif proto == "ICMP":
        result["summary"] = (
            f"{ip.get('src_ip','?')} → {ip.get('dst_ip','?')} "
            f"ICMP {tr.get('meaning','')}"
        )
    elif proto == "ARP":
        result["summary"] = (
            f"ARP {tr.get('op','')} "
            f"{tr.get('src_ip','?')} → {tr.get('dst_ip','?')}"
        )

    return result


# ─── Hàm tiện ích nội bộ ──────────────────────────────────────────────────

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


def _icmp_meaning(icmp_type):
    """Giải nghĩa ICMP type"""
    meanings = {
        0: "Echo Reply (ping trả lời)",
        3: "Destination Unreachable (không đến được đích)",
        8: "Echo Request (ping)",
        11: "Time Exceeded (TTL hết, gói bị hủy)"
    }
    return meanings.get(icmp_type, f"Type {icmp_type}")


def _format_hex_dump(data, width=16):
    """
    Tạo hex dump như tcpdump -X
    Ví dụ:
    0000  47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a  GET / HTTP/1.1..
    """
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i+width]

        # Phần HEX
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        # Căn đều 2 cột
        hex_part = hex_part.ljust(width * 3)

        # Phần ASCII (ký tự không in được thay bằng dấu chấm)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)

        lines.append(f"{i:04x}  {hex_part}  {ascii_part}")

    return "\n".join(lines)

# ─────────────────────────────────────────
# HEX DUMP — hiển thị raw bytes như tcpdump
# ─────────────────────────────────────────
def hex_dump(packet):
    """
    Chương 4.1.3 — hiển thị gói tin dạng:
    0000  45 00 00 3c 1c 46 40 00  40 06 ...  E..<.F@.@.
    """
    raw = bytes(packet)
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        
        # Cột offset
        offset = f"{i:04x}"
        
        # Cột hex (từng byte cách nhau bởi dấu cách)
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)   # căn đều 16 bytes
        
        # Cột ASCII (ký tự in được, còn lại thay bằng dấu chấm)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        
        lines.append(f"  {offset}  {hex_part}  {ascii_part}")
    
    return "\n".join(lines)


# ─────────────────────────────────────────
# HEX DUMP — hiển thị raw bytes như tcpdump
# ─────────────────────────────────────────
def hex_dump(packet):
    """
    Chương 4.1.3 — hiển thị gói tin dạng:
    0000  45 00 00 3c 1c 46 40 00  40 06 ...  E..<.F@.@.
    """
    raw = bytes(packet)
    lines = []
    for i in range(0, len(raw), 16):
        chunk = raw[i:i+16]
        
        # Cột offset
        offset = f"{i:04x}"
        
        # Cột hex (từng byte cách nhau bởi dấu cách)
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = hex_part.ljust(47)   # căn đều 16 bytes
        
        # Cột ASCII (ký tự in được, còn lại thay bằng dấu chấm)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        
        lines.append(f"  {offset}  {hex_part}  {ascii_part}")
    
    return "\n".join(lines)