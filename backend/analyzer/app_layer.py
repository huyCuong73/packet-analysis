from scapy.all import TCP, UDP, DNS, DNSQR, DNSRR, Raw
import re

# ─── PHÂN TÍCH DNS ────────────────────────────────────────────────────────

def analyze_dns(packet):
    """
    Phân tích gói tin DNS.
    
    DNS có 2 loại gói:
    - Query (hỏi)   : máy tính hỏi "IP của google.com là gì?"
    - Response (trả lời): DNS server trả lời "142.250.1.1"
    
    Tại sao NSM quan tâm DNS?
    → Mọi kết nối ra internet đều bắt đầu bằng DNS query
    → Phát hiện tên miền lạ = phát hiện sớm malware/C&C
    """
    if DNS not in packet:
        return {}

    dns = packet[DNS]
    result = {
        "type":    "response" if dns.qr == 1 else "query",
        "tx_id":   dns.id,       # transaction ID — để ghép query với response
        "queries":   [],
        "answers":   [],
        "is_suspicious": False,
        "suspicious_reason": ""
    }

    # ── Phần câu hỏi (query) ─────────────────────────────────────────────
    if dns.qd:
        try:
            # Scapy mới dùng 'qname', cũ dùng 'name' — thử cả hai
            raw_name = getattr(dns.qd, 'qname', None) or getattr(dns.qd, 'name', b'')
            if isinstance(raw_name, bytes):
                query_name = raw_name.decode(errors="replace").rstrip(".")
            else:
                query_name = str(raw_name).rstrip(".")
        except Exception:
            query_name = "unknown"
        
        query_type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT"}
        try:
            query_type = query_type_map.get(dns.qd.qtype, f"TYPE{dns.qd.qtype}")
        except Exception:
            query_type = "UNKNOWN"
        
        result["queries"].append({
            "name": query_name,
            "type": query_type
        })

        # Kiểm tra dấu hiệu đáng ngờ
        suspicious, reason = _check_dns_suspicious(query_name)
        result["is_suspicious"]     = suspicious
        result["suspicious_reason"] = reason

    # ── Phần câu trả lời (response) ───────────────────────────────────────
    if dns.an:
        answer = dns.an
        while answer:
            try:
                raw_name = getattr(answer, 'rrname', None) or getattr(answer, 'name', b'')
                if isinstance(raw_name, bytes):
                    answer_name = raw_name.decode(errors="replace").rstrip(".")
                else:
                    answer_name = str(raw_name).rstrip(".")
            except Exception:
                answer_name = "unknown"
            
            # Lấy giá trị tùy loại record
            if hasattr(answer, "rdata"):
                rdata = str(answer.rdata)
            else:
                rdata = "N/A"

            try:
                ttl = answer.ttl
            except Exception:
                ttl = 0

            result["answers"].append({
                "name":  answer_name,
                "rdata": rdata,
                "ttl":   ttl
            })
            answer = answer.payload if hasattr(answer, "payload") else None
            # Dừng nếu không còn record nào nữa
            if answer is None or not (hasattr(answer, "rrname") or hasattr(answer, "name")):
                break

    return result


def _check_dns_suspicious(domain: str):
    """
    Phát hiện DNS đáng ngờ dựa trên đặc điểm của tên miền.
    
    Các dấu hiệu DNS Tunneling (dùng DNS để rò dữ liệu):
    1. Tên miền quá dài (>50 ký tự)
    2. Quá nhiều subdomain (>5 cấp)
    3. Chứa nhiều ký tự lạ (base64, hex)
    
    Trả về: (is_suspicious: bool, reasons: list[str])
    """
    reasons = []
    parts = domain.split(".")

    # Dấu hiệu 1: tên miền quá dài
    if len(domain) > 20:
        reasons.append(f"Ten mien qua dai ({len(domain)} ky tu)")

    # Dấu hiệu 2: quá nhiều subdomain
    if len(parts) > 2:
        reasons.append(f"Qua nhieu subdomain ({len(parts)} cap)")

    # Dấu hiệu 3: subdomain chứa toàn ký tự hex hoặc base64
    if len(parts) > 2:
        subdomain = parts[0]
        hex_ratio = sum(1 for c in subdomain if c in "0123456789abcdef") / max(len(subdomain), 1)
        if len(subdomain) > 20 and hex_ratio > 0.8:
            reasons.append(f"Subdomain co ve la du lieu ma hoa")

    if reasons:
        return True, " | ".join(reasons)
    return False, ""


# ─── PHÂN TÍCH HTTP ───────────────────────────────────────────────────────

def analyze_http(packet):
    """
    Phân tích gói tin HTTP (chạy trên TCP port 80).
    
    HTTP là giao thức text — toàn bộ header và body
    đều là văn bản ASCII có thể đọc được.
    
    Tại sao NSM quan tâm HTTP?
    → Username/password có thể bị lộ (form login không dùng HTTPS)
    → Phát hiện User-Agent lạ (malware thường có User-Agent cố định)
    → Phát hiện URL độc hại
    """
    if TCP not in packet or Raw not in packet:
        return {}

    tcp = packet[TCP]

    # HTTP chạy trên port 80 (hoặc 8080)
    is_http_port = tcp.dport in (80, 8080) or tcp.sport in (80, 8080)
    if not is_http_port:
        return {}

    try:
        raw = bytes(packet[Raw]).decode("utf-8", errors="replace")
    except Exception:
        return {}

    # Phân biệt Request và Response
    if raw.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
        return _parse_http_request(raw)
    elif raw.startswith("HTTP/"):
        return _parse_http_response(raw)

    return {}


def _parse_http_request(raw: str):
    """
    Phân tích HTTP Request.
    Ví dụ:
        GET /login.php HTTP/1.1
        Host: example.com
        User-Agent: Mozilla/5.0
    """
    lines = raw.split("\r\n")
    result = {
        "direction": "request",
        "method":    "",
        "uri":       "",
        "version":   "",
        "host":      "",
        "headers":   {},
        "body":      "",
        "credentials_found": False,
        "credentials": []
    }

    # Dòng đầu: "GET /path HTTP/1.1"
    if lines:
        parts = lines[0].split(" ")
        if len(parts) >= 3:
            result["method"]  = parts[0]          # GET, POST...
            result["uri"]     = parts[1]           # /login.php
            result["version"] = parts[2]           # HTTP/1.1

    # Các dòng header
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":                             # dòng trống = bắt đầu body
            body_start = i + 1
            break
        if ":" in line:
            key, _, val = line.partition(":")
            result["headers"][key.strip()] = val.strip()
            if key.strip().lower() == "host":
                result["host"] = val.strip()

    # Body (thường có trong POST)
    if body_start > 0:
        result["body"] = "\r\n".join(lines[body_start:])

    # Tìm credentials trong body (form login)
    result["credentials_found"], result["credentials"] = \
        _find_credentials(result["body"])

    return result


def _parse_http_response(raw: str):
    """
    Phân tích HTTP Response.
    Ví dụ:
        HTTP/1.1 200 OK
        Content-Type: text/html
    """
    lines = raw.split("\r\n")
    result = {
        "direction":   "response",
        "version":     "",
        "status_code": 0,
        "status_text": "",
        "headers":     {},
        "body_preview": ""
    }

    # Dòng đầu: "HTTP/1.1 200 OK"
    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            result["version"]     = parts[0]
            result["status_code"] = int(parts[1]) if parts[1].isdigit() else 0
            result["status_text"] = parts[2] if len(parts) > 2 else ""

    # Headers
    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            key, _, val = line.partition(":")
            result["headers"][key.strip()] = val.strip()

    return result


def _find_credentials(body: str):
    """
    Tìm username/password trong HTTP body.
    
    Đây là tính năng quan trọng của NSM:
    phát hiện credential đi qua mạng không mã hóa.
    
    Các pattern phổ biến trong form login:
    username=admin&password=1234
    user=test&pass=secret
    email=a@b.com&pwd=hello
    """
    credentials = []
    
    # Các tên field phổ biến cho username và password
    user_patterns = r"(?:username|user|email|login|uname)=([^&\s]+)"
    pass_patterns = r"(?:password|pass|passwd|pwd|secret)=([^&\s]+)"

    users = re.findall(user_patterns, body, re.IGNORECASE)
    passwords = re.findall(pass_patterns, body, re.IGNORECASE)

    for u in users:
        credentials.append({"type": "username", "value": u})
    for p in passwords:
        credentials.append({"type": "password", "value": p})

    return len(credentials) > 0, credentials