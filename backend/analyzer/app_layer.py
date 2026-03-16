"""
Application Layer Analyzer — Phân tích DNS & HTTP
100% Python thuần — KHÔNG dùng Scapy
"""

import re
from analyzer.raw_parser import parse_dns


# ─── PHÂN TÍCH DNS ────────────────────────────────────────────────────────

def analyze_dns_raw(payload):
    """
    Phân tích gói DNS từ raw UDP payload bytes.

    Input: payload (bytes) — phần data sau UDP header
    Output: dict chứa queries, answers, suspicious info
    """
    if not payload or len(payload) < 12:
        return None

    return parse_dns(payload)


# ─── PHÂN TÍCH HTTP ───────────────────────────────────────────────────────

def analyze_http_raw(payload, src_port, dst_port):
    """
    Phân tích gói HTTP từ raw TCP payload bytes.

    HTTP chạy trên port 80 hoặc 8080.
    HTTP là giao thức text — toàn bộ header và body
    đều là văn bản ASCII có thể đọc được.
    """
    if not payload:
        return {}

    is_http_port = dst_port in (80, 8080) or src_port in (80, 8080)
    if not is_http_port:
        return {}

    try:
        raw = payload.decode("utf-8", errors="replace")
    except Exception:
        return {}

    # Phân biệt Request và Response
    if raw.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS")):
        return _parse_http_request(raw)
    elif raw.startswith("HTTP/"):
        return _parse_http_response(raw)

    return {}


def _parse_http_request(raw):
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
            result["method"]  = parts[0]
            result["uri"]     = parts[1]
            result["version"] = parts[2]

    # Các dòng header
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        if line == "":
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

    # Tìm credentials trong body
    result["credentials_found"], result["credentials"] = \
        _find_credentials(result["body"])

    return result


def _parse_http_response(raw):
    """
    Phân tích HTTP Response.
    Ví dụ:
        HTTP/1.1 200 OK
        Content-Type: text/html
    """
    lines = raw.split("\r\n")
    result = {
        "direction":    "response",
        "version":      "",
        "status_code":  0,
        "status_text":  "",
        "headers":      {},
        "body_preview": ""
    }

    if lines:
        parts = lines[0].split(" ", 2)
        if len(parts) >= 2:
            result["version"]     = parts[0]
            result["status_code"] = int(parts[1]) if parts[1].isdigit() else 0
            result["status_text"] = parts[2] if len(parts) > 2 else ""

    for line in lines[1:]:
        if line == "":
            break
        if ":" in line:
            key, _, val = line.partition(":")
            result["headers"][key.strip()] = val.strip()

    return result


def _find_credentials(body):
    """
    Tìm username/password trong HTTP body (form login).

    Các pattern phổ biến:
    username=admin&password=1234
    user=test&pass=secret
    email=a@b.com&pwd=hello
    """
    credentials = []

    user_patterns = r"(?:username|user|email|login|uname)=([^&\s]+)"
    pass_patterns = r"(?:password|pass|passwd|pwd|secret)=([^&\s]+)"

    users = re.findall(user_patterns, body, re.IGNORECASE)
    passwords = re.findall(pass_patterns, body, re.IGNORECASE)

    for u in users:
        credentials.append({"type": "username", "value": u})
    for p in passwords:
        credentials.append({"type": "password", "value": p})

    return len(credentials) > 0, credentials