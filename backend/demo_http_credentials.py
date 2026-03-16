"""
Demo phat hien Credentials trong HTTP.

Cach chay:
  Buoc 1: Mo terminal 1, chay server:
      python demo_http_credentials.py server

  Buoc 2: Mo terminal 2, bat dau capture:
      python main.py capture -f "tcp port 8080" -c 20 -d

  Buoc 3: Mo terminal 3, gui login gia:
      python demo_http_credentials.py login

  --> Xem terminal 2: NSM se canh bao "PHAT HIEN CREDENTIALS"

  Hoac chay nhanh khong can mang (test truc tiep ham phan tich):
      python demo_http_credentials.py test
"""

import sys


def run_server():
    """Chay HTTP server co form login tren port 8080"""
    from http.server import HTTPServer, BaseHTTPRequestHandler

    class LoginHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            # Tra ve trang login
            html = """
            <html><body>
            <h1>Login Page (Demo NSM)</h1>
            <form method="POST" action="/login">
                Username: <input name="username" type="text"><br>
                Password: <input name="password" type="password"><br>
                <button type="submit">Login</button>
            </form>
            </body></html>
            """
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(html.encode())

        def do_POST(self):
            # Nhan form login
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode()
            print(f"\n  [SERVER] Nhan duoc POST data: {body}")

            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body><h1>Login received!</h1></body></html>")

        def log_message(self, format, *args):
            print(f"  [SERVER] {args[0]}")

    print("=" * 60)
    print("  HTTP LOGIN SERVER (Demo NSM)")
    print("=" * 60)
    print(f"\n  Server dang chay tai: http://localhost:8080")
    print(f"  Mo trinh duyet: http://localhost:8080")
    print(f"  Nhan Ctrl+C de dung\n")

    server = HTTPServer(("0.0.0.0", 8080), LoginHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server da dung.")


def send_login():
    """Gui POST request chua credentials den server"""
    import urllib.request
    import urllib.parse

    print("=" * 60)
    print("  GUI LOGIN GIA (Demo NSM)")
    print("=" * 60)

    # Du lieu login gia
    credentials = [
        {"username": "admin", "password": "P@ssw0rd123"},
        {"user": "john_doe", "pass": "secret456"},
        {"email": "test@example.com", "pwd": "mypassword"},
    ]

    for i, cred in enumerate(credentials, 1):
        data = urllib.parse.urlencode(cred).encode()
        print(f"\n  [{i}] Gui: {urllib.parse.urlencode(cred)}")

        try:
            req = urllib.request.Request("http://localhost:8080/login", data=data)
            resp = urllib.request.urlopen(req)
            print(f"      Response: {resp.status} {resp.reason}")
        except Exception as e:
            print(f"      Loi: {e}")
            print(f"      --> Hay chay 'python demo_http_credentials.py server' truoc!")
            break

    print("\n  Xong! Kiem tra terminal dang chay NSM capture.")


def test_direct():
    """Test truc tiep ham phat hien credentials (khong can mang)"""
    from analyzer.app_layer import _find_credentials, _parse_http_request

    print("=" * 60)
    print("  TEST TRUC TIEP: Phat hien Credentials")
    print("=" * 60)

    # Gia lap cac HTTP request chua credentials
    test_cases = [
        {
            "name": "Form login co ban",
            "raw": (
                "POST /login HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "\r\n"
                "username=admin&password=P@ssw0rd123"
            ),
        },
        {
            "name": "Form login voi email",
            "raw": (
                "POST /auth HTTP/1.1\r\n"
                "Host: bank.example.com\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "\r\n"
                "email=john@company.com&pwd=SecretKey789"
            ),
        },
        {
            "name": "Form login nhieu truong",
            "raw": (
                "POST /signin HTTP/1.1\r\n"
                "Host: app.example.com\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "\r\n"
                "login=root&passwd=toor&remember=1"
            ),
        },
        {
            "name": "GET binh thuong (khong co credentials)",
            "raw": (
                "GET /index.html HTTP/1.1\r\n"
                "Host: google.com\r\n"
                "\r\n"
            ),
        },
    ]

    for i, case in enumerate(test_cases, 1):
        print(f"\n  [{i}] {case['name']}")
        result = _parse_http_request(case["raw"])

        method = result.get("method", "")
        uri = result.get("uri", "")
        host = result.get("host", "")
        body = result.get("body", "")
        found = result.get("credentials_found", False)
        creds = result.get("credentials", [])

        print(f"      {method} {host}{uri}")
        if body:
            print(f"      Body: {body}")

        if found:
            print(f"      >> PHAT HIEN CREDENTIALS:")
            for c in creds:
                print(f"         [{c['type']}] {c['value']}")
        else:
            print(f"      Khong tim thay credentials.")

    print("\n" + "=" * 60)
    print("  NSM phat hien credentials trong 3/4 truong hop")
    print("  Pattern: username, user, email, login, password, pass, pwd")
    print("=" * 60)


# === MAIN ===
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "server":
        run_server()
    elif cmd == "login":
        send_login()
    elif cmd == "test":
        test_direct()
    else:
        print(__doc__)
