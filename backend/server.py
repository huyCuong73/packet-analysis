from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
from werkzeug.utils import secure_filename
from database import Database
from analyzer.protocol import analyze_packet
from sniffer.capture import PacketCapture
from scapy.all import sniff
import threading
import os
import queue
import socket as py_socket

app      = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")

# ─── DNS RESOLVER NGẦM ────────────────────────────────────────────────────
_dns_queue = queue.Queue()
_dns_cache = {}

def _dns_worker():
    while True:
        try:
            ip = _dns_queue.get()
            if ip is None: break
            
            try:
                # Bỏ qua tra cứu các IP nội bộ / LAN để tăng tốc
                if (ip.startswith("10.") or 
                    ip.startswith("192.168.") or 
                    ip.startswith("127.") or 
                    ip.startswith("172.") or 
                    ip == "255.255.255.255"):
                    _dns_cache[ip] = ip
                else:
                    host, _, _ = py_socket.gethostbyaddr(ip)
                    _dns_cache[ip] = host
                    socketio.emit("dns_resolved", {"ip": ip, "domain": host})
            except Exception:
                _dns_cache[ip] = ip  # Lỗi (không có DNS) thì gán lại IP mặc định
            
            _dns_queue.task_done()
        except Exception:
            pass

threading.Thread(target=_dns_worker, daemon=True).start()
# ────────────────────────────────────────────────────────────────────────


db      = Database()
capture = PacketCapture()
_sniff_thread      = None
_is_capturing      = False
_current_session_id = None      # ← session đang chạy
_current_session_name = ""      # ← tên session đang chạy

UPLOAD_FOLDER = "data/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── Xử lý gói tin ────────────────────────────────────────────────────────

def process_packet(packet):
    global _current_session_id
    analyzed  = analyze_packet(packet)
    packet_id = db.save_packet(analyzed, session_id=_current_session_id)

    ip = analyzed.get("ip", {})
    tr = analyzed.get("transport", {})

    # Trích xuất DNS query name nếu có
    dns_query = ""
    app_layer = analyzed.get("app_layer", {})
    dns_info = app_layer.get("dns", {})
    if dns_info.get("type") == "query" and dns_info.get("queries"):
        dns_query = dns_info["queries"][0].get("name", "")

    # Trích xuất Clear-text Credentials (HTTP)
    credentials = []
    http_info = app_layer.get("http", {})
    if http_info.get("credentials_found"):
        credentials = http_info.get("credentials", [])

    socketio.emit("new_packet", {
        "id":       packet_id,
        "time":     analyzed.get("time"),
        "protocol": analyzed.get("transport_proto"),
        "src_ip":   ip.get("src_ip"),
        "dst_ip":   ip.get("dst_ip"),
        "src_port": tr.get("src_port"),
        "dst_port": tr.get("dst_port"),
        "length":   ip.get("total_length", 0),
        "ttl":      ip.get("ttl"),
        "flags":    tr.get("flags_active", []),
        "service":  tr.get("service", ""),
        "dns_query": dns_query,
        "credentials": credentials,
    })

    # Xếp hàng tra cứu Tên miền (Reverse DNS) ngầm
    for _ip in (ip.get("src_ip"), ip.get("dst_ip")):
        if _ip and _ip not in _dns_cache:
            _dns_cache[_ip] = "pending"
            _dns_queue.put(_ip)

# ─── REST API ─────────────────────────────────────────────────────────────

@app.route("/api/packets")
def get_packets():
    session_id = request.args.get("session_id", type=int)
    limit      = request.args.get("limit", 100, type=int)
    return jsonify(db.get_recent_packets(limit, session_id))

@app.route("/api/packets/<int:packet_id>")
def get_packet_detail(packet_id):
    return jsonify(db.get_packet_detail(packet_id))

@app.route("/api/stats/protocols")
def get_protocol_stats():
    session_id = request.args.get("session_id", type=int)
    return jsonify(db.get_protocol_stats(session_id))

@app.route("/api/stats/top-ips")
def get_top_ips():
    session_id = request.args.get("session_id", type=int)
    return jsonify(db.get_top_ips(session_id=session_id))

@app.route("/api/stats/traffic-time")
def get_traffic_time():
    session_id = request.args.get("session_id", type=int)
    return jsonify(db.get_traffic_over_time(session_id))

@app.route("/api/alerts")
def get_alerts():
    session_id = request.args.get("session_id", type=int)
    return jsonify(db.get_recent_alerts(session_id=session_id))

@app.route("/api/sessions")
def get_sessions():
    return jsonify(db.get_sessions())

@app.route("/api/sessions/<int:session_id>", methods=["DELETE"])
def delete_session(session_id):
    db.delete_session(session_id)
    return jsonify({"ok": True})

@app.route("/api/upload-pcap", methods=["POST"])
def upload_pcap():
    """
    Nhận file .pcap từ frontend,
    đọc và phân tích từng gói tin,
    lưu vào 1 session mới,
    trả về danh sách gói tin đã phân tích.
    """
    if "file" not in request.files:
        return jsonify({"error": "Không có file"}), 400

    file = request.files["file"]

    if not file.filename.endswith(".pcap"):
        return jsonify({"error": "Chỉ hỗ trợ file .pcap"}), 400

    # Lưu file tạm
    filename  = secure_filename(file.filename)
    filepath  = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Tạo session mới cho file này
    session_id = db.create_session(f"📂 {filename}")

    # Đọc và phân tích từng gói tin
    try:
        from scapy.all import rdpcap
        packets = rdpcap(filepath)
    except Exception as e:
        return jsonify({"error": f"Không đọc được file: {str(e)}"}), 400

    results = []
    for packet in packets:
        analyzed  = analyze_packet(packet)
        packet_id = db.save_packet(analyzed, session_id=session_id)

        ip = analyzed.get("ip", {})
        tr = analyzed.get("transport", {})

        results.append({
            "id":       packet_id,
            "time":     analyzed.get("time"),
            "protocol": analyzed.get("transport_proto"),
            "src_ip":   ip.get("src_ip"),
            "dst_ip":   ip.get("dst_ip"),
            "src_port": tr.get("src_port"),
            "dst_port": tr.get("dst_port"),
            "length":   ip.get("total_length", 0),
            "ttl":      ip.get("ttl"),
            "flags":    tr.get("flags_active", []),
            "service":  tr.get("service", "")
        })

        # Cầm IP quăng cho DNS Worker xử lý
        for _ip in (ip.get("src_ip"), ip.get("dst_ip")):
            if _ip and _ip not in _dns_cache:
                _dns_cache[_ip] = "pending"
                _dns_queue.put(_ip)

    # Xóa file tạm sau khi xử lý xong
    os.remove(filepath)

    return jsonify({
        "session_id":    session_id,
        "session_name":  f"📂 {filename}",
        "total_packets": len(results),
        "packets":       results
    })

@app.route("/api/interfaces")
def get_interfaces():
    """
    Trả về danh sách tất cả network interface trên máy
    kèm thông tin IP nếu có.
    """
    from scapy.all import get_if_list, get_if_addr
    
    interfaces = []
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
        except Exception:
            ip = "N/A"

        interfaces.append({
            "name": iface,
            "ip":   ip
        })

    return jsonify(interfaces)



@app.route("/api/friendly-interfaces")
def get_friendly_interfaces():
    """
    Trả về danh sách network interface kèm tên thân thiện.
    Trên Windows, IFACES chứa: name, description, ip, mac...
    """
    from scapy.all import IFACES

    interfaces = []
    for iface_id, iface in IFACES.data.items():
        try:
            interfaces.append({
                "name":        iface.name,             # tên gốc (dùng để truyền cho Scapy)
                "description": iface.description or "", # "Intel Ethernet", "Wi-Fi"...
                "ip":          iface.ip   or "",
                "mac":         iface.mac  or "",
            })
        except Exception:
            pass

    return jsonify(interfaces)













# ─── WebSocket ────────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    global _is_capturing, _current_session_id, _current_session_name
    # Nếu đang capture thì báo ngay cho người mới vào biết
    if _is_capturing:
        socketio.emit("capture_status", {"status": "started"})
        if _current_session_id:
            socketio.emit("session_created", {
                "session_id": _current_session_id,
                "name":       _current_session_name
            })

@socketio.on("start_capture")
def handle_start(data):
    global _sniff_thread, _is_capturing, _current_session_id, _current_session_name
    if _is_capturing:
        return

    session_name          = data.get("name", "")
    _current_session_id   = db.create_session(session_name)
    _current_session_name = session_name or f"Session #{_current_session_id}"
    _is_capturing         = True

    socketio.emit("session_created", {
        "session_id": _current_session_id,
        "name":       _current_session_name
    })

    bpf_filter = data.get("filter",    "")
    # None = Scapy tự chọn interface tốt nhất
    iface      = data.get("interface") or None

    def run_sniff():
        sniff(
            iface=iface,          # ← dùng interface được chọn
            filter=bpf_filter,
            prn=process_packet,
            stop_filter=lambda p: not _is_capturing,
            store=False
        )

    _sniff_thread = threading.Thread(target=run_sniff, daemon=True)
    _sniff_thread.start()
    socketio.emit("capture_status", {"status": "started"})

@socketio.on("stop_capture")
def handle_stop():
    global _is_capturing
    _is_capturing = False
    socketio.emit("capture_status", {"status": "stopped"})

@socketio.on("disconnect")
def handle_disconnect():
    """
    Khi user tắt tab hoặc F5, tự động dừng capture 
    để tránh bị chạy ngầm vô hạn tải nặng máy.
    """
    global _is_capturing
    if _is_capturing:
        _is_capturing = False
        print("[!] Client ngắt kết nối -> Tự động dừng Capture chạy ngầm.")

if __name__ == "__main__":
    print("[*] Server chạy tại http://localhost:5000")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)