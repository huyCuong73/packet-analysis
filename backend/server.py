from flask import Flask, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
from werkzeug.utils import secure_filename
from database import Database
from analyzer.protocol import analyze_packet
from sniffer.capture import PacketCapture
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
                _dns_cache[ip] = ip
            
            _dns_queue.task_done()
        except Exception:
            pass

threading.Thread(target=_dns_worker, daemon=True).start()

db      = Database()
capture = PacketCapture()
_sniff_thread       = None
_is_capturing       = False
_current_session_id  = None
_current_session_name = ""

UPLOAD_FOLDER = "data/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── Xử lý gói tin ────────────────────────────────────────────────────────

def process_packet(raw_bytes):
    """
    Callback cho live capture.
    Nhận raw bytes → phân tích → lọc loopback → lưu DB → emit WebSocket
    """
    global _current_session_id
    analyzed  = analyze_packet(raw_bytes)

    # ── Bỏ qua traffic nội bộ (Loopback) ──────────────────────────
    ip = analyzed.get("ip", {})
    src_ip = ip.get("src_ip", "")
    dst_ip = ip.get("dst_ip", "")
    if src_ip.startswith("127.") or dst_ip.startswith("127."):
        return
    # ──────────────────────────────────────────────────────────────

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

    # Xếp hàng tra cứu Reverse DNS
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
    đọc bằng PCAP reader thuần Python,
    lưu vào 1 session mới.
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

    # Tạo session mới
    session_id = db.create_session(f"PCAP: {filename}")

    # Đọc bằng PCAP reader thuần Python
    try:
        packets = PacketCapture.load_from_pcap(filepath)
    except Exception as e:
        return jsonify({"error": f"Không đọc được file: {str(e)}"}), 400

    results = []
    for raw_bytes in packets:
        analyzed  = analyze_packet(raw_bytes)
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

        for _ip in (ip.get("src_ip"), ip.get("dst_ip")):
            if _ip and _ip not in _dns_cache:
                _dns_cache[_ip] = "pending"
                _dns_queue.put(_ip)

    os.remove(filepath)

    return jsonify({
        "session_id":    session_id,
        "session_name":  f"PCAP: {filename}",
        "total_packets": len(results),
        "packets":       results
    })

@app.route("/api/interfaces")
def get_interfaces():
    """Trả về danh sách network interfaces"""
    interfaces = PacketCapture.list_interfaces()
    return jsonify(interfaces)

@app.route("/api/friendly-interfaces")
def get_friendly_interfaces():
    """Trả về danh sách network interfaces kèm thông tin chi tiết"""
    interfaces = PacketCapture.list_interfaces()
    return jsonify(interfaces)

@app.route("/api/replay-pcap", methods=["POST"])
def replay_pcap():
    """
    Replay file .pcap: đọc và emit từng gói tin qua WebSocket
    với tốc độ delay có thể điều chỉnh.
    """
    global _current_session_id, _is_capturing

    if "file" not in request.files:
        return jsonify({"error": "Không có file"}), 400

    file = request.files["file"]
    speed = float(request.form.get("speed", 1.0))

    if not file.filename.endswith(".pcap"):
        return jsonify({"error": "Chỉ hỗ trợ file .pcap"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # Tạo session mới cho replay
    session_id = db.create_session(f"Replay: {filename}")
    _current_session_id = session_id

    socketio.emit("session_created", {
        "session_id": session_id,
        "name": f"Replay: {filename}"
    })
    
    _is_capturing = True
    socketio.emit("capture_status", {"status": "started"})

    try:
        packets = PacketCapture.load_from_pcap(filepath)
    except Exception as e:
        return jsonify({"error": f"Không đọc được file: {str(e)}"}), 400

    total = len(packets)

    # Replay từng gói trong background thread
    def do_replay():
        import time as _time
        delay = max(0.01, 0.1 / speed)  # delay giữa các gói

        for i, raw_bytes in enumerate(packets):
            if not _is_capturing:
                break

            analyzed = analyze_packet(raw_bytes)
            packet_id = db.save_packet(analyzed, session_id=session_id)

            ip = analyzed.get("ip", {})
            tr = analyzed.get("transport", {})

            dns_query = ""
            app_layer = analyzed.get("app_layer", {})
            dns_info = app_layer.get("dns", {})
            if dns_info.get("type") == "query" and dns_info.get("queries"):
                dns_query = dns_info["queries"][0].get("name", "")

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

            # Emit progress
            progress = int((i + 1) / total * 100)
            socketio.emit("replay_progress", {"progress": progress})

            _time.sleep(delay)

        socketio.emit("replay_progress", {"progress": 100})
        socketio.emit("capture_status", {"status": "stopped"})

    thread = threading.Thread(target=do_replay, daemon=True)
    thread.start()

    os.remove(filepath)

    return jsonify({
        "session_id": session_id,
        "total_packets": total,
        "status": "replaying"
    })

# ─── WebSocket ────────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    global _is_capturing, _current_session_id, _current_session_name
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

    iface = data.get("interface") or None

    def run_sniff():
        """Bắt gói tin bằng raw socket AF_PACKET"""
        cap = PacketCapture()
        cap.start_live_capture(
            interface=iface,
            callback=process_packet,
            count=0  # liên tục cho đến khi dừng
        )

    # Override is_running khi stop
    def run_sniff_with_stop():
        import socket as raw_socket

        try:
            sock = raw_socket.socket(
                raw_socket.AF_PACKET,
                raw_socket.SOCK_RAW,
                raw_socket.ntohs(0x0003)
            )
            if iface:
                sock.bind((iface, 0))
            sock.settimeout(1.0)

            while _is_capturing:
                try:
                    raw_data, addr = sock.recvfrom(65535)
                    process_packet(raw_data)
                except raw_socket.timeout:
                    continue
                except Exception as e:
                    if _is_capturing:
                        print(f"[!] Lỗi nhận gói: {e}")
                    break
        except PermissionError:
            print("[!] Cần quyền root. Chạy: sudo python server.py")
        except Exception as e:
            print(f"[!] Lỗi capture: {e}")
        finally:
            try:
                sock.close()
            except:
                pass

    _sniff_thread = threading.Thread(target=run_sniff_with_stop, daemon=True)
    _sniff_thread.start()
    socketio.emit("capture_status", {"status": "started"})

@socketio.on("stop_capture")
def handle_stop():
    global _is_capturing
    _is_capturing = False
    socketio.emit("capture_status", {"status": "stopped"})

@socketio.on("disconnect")
def handle_disconnect():
    global _is_capturing
    if _is_capturing:
        _is_capturing = False
        print("[!] Client ngắt kết nối -> Tự động dừng Capture.")

if __name__ == "__main__":
    print("[*] Server chạy tại http://localhost:5000")
    print("[*] Backend: 100% Python thuần (Raw Socket + struct.unpack)")
    print("[*] Cần quyền root để bắt gói tin: sudo python server.py")
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)