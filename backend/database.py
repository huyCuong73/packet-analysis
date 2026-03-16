import sqlite3
import json
import os
from datetime import datetime


class SafeEncoder(json.JSONEncoder):
    """Xử lý các kiểu dữ liệu không serialize được (bytes, set...)"""
    def default(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        if isinstance(obj, set):
            return list(obj)
        return super().default(obj)

class Database:
    def __init__(self, db_path: str = "data/packets.db"):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn    = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
        self._migrate()
        print(f"[+] Database sẵn sàng: {db_path}")

    def _create_tables(self):
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT,
                created_at   TEXT,
                packet_count INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS packets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES sessions(id),
                time       TEXT,
                protocol   TEXT,
                src_ip     TEXT,
                dst_ip     TEXT,
                src_port   INTEGER,
                dst_port   INTEGER,
                length     INTEGER,
                ttl        INTEGER,
                flags      TEXT,
                detail     TEXT
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER REFERENCES sessions(id),
                time       TEXT,
                type       TEXT,
                message    TEXT,
                src_ip     TEXT
            );
        """)
        self.conn.commit()

    def _migrate(self):
        """
        Thêm cột session_id vào bảng cũ nếu chưa có.
        Dùng try/except vì SQLite không hỗ trợ
        'ADD COLUMN IF NOT EXISTS'
        """
        for sql in [
            "ALTER TABLE packets ADD COLUMN session_id INTEGER",
            "ALTER TABLE alerts  ADD COLUMN session_id INTEGER"
        ]:
            try:
                self.conn.execute(sql)
                self.conn.commit()
            except Exception:
                pass  # cột đã tồn tại → bỏ qua

    # ─── Session ──────────────────────────────────────────────────────────

    def create_session(self, name: str = None) -> int:
        """Tạo phiên mới, trả về session_id"""
        if not name:
            name = f"Session {datetime.now().strftime('%d/%m %H:%M:%S')}"

        cursor = self.conn.execute(
            "INSERT INTO sessions (name, created_at) VALUES (?, ?)",
            (name, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        self.conn.commit()
        print(f"[+] Tạo phiên mới: '{name}' (id={cursor.lastrowid})")
        return cursor.lastrowid

    def get_sessions(self) -> list:
        """Lấy danh sách tất cả phiên, mới nhất trước"""
        cursor = self.conn.execute("""
            SELECT s.id, s.name, s.created_at,
                   COUNT(p.id) as packet_count
            FROM sessions s
            LEFT JOIN packets p ON p.session_id = s.id
            GROUP BY s.id
            ORDER BY s.id DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def delete_session(self, session_id: int):
        """Xóa 1 phiên và toàn bộ gói tin + alert của phiên đó"""
        self.conn.executescript(f"""
            DELETE FROM packets WHERE session_id = {session_id};
            DELETE FROM alerts  WHERE session_id = {session_id};
            DELETE FROM sessions WHERE id = {session_id};
        """)
        self.conn.commit()
        print(f"[+] Đã xóa phiên id={session_id}")

    # ─── Lưu dữ liệu ──────────────────────────────────────────────────────

    def save_packet(self, analyzed: dict, session_id: int = None) -> int:
        ip = analyzed.get("ip", {})
        tr = analyzed.get("transport", {})
        flags_str = ",".join(tr.get("flags_active", []))

        cursor = self.conn.execute("""
            INSERT INTO packets
              (session_id, time, protocol, src_ip, dst_ip,
               src_port, dst_port, length, ttl, flags, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session_id,
            analyzed.get("time"),
            analyzed.get("transport_proto", "OTHER"),
            ip.get("src_ip"),
            ip.get("dst_ip"),
            tr.get("src_port"),
            tr.get("dst_port"),
            ip.get("total_length", 0),
            ip.get("ttl"),
            flags_str,
            json.dumps(analyzed, ensure_ascii=False, cls=SafeEncoder)
        ))
        self.conn.commit()
        return cursor.lastrowid

    def save_alert(self, alert_type: str, message: str,
                   src_ip: str = "", session_id: int = None):
        self.conn.execute("""
            INSERT INTO alerts (session_id, time, type, message, src_ip)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session_id,
            datetime.now().strftime("%H:%M:%S"),
            alert_type, message, src_ip
        ))
        self.conn.commit()

    # ─── Đọc dữ liệu ──────────────────────────────────────────────────────

    def get_recent_packets(self, limit: int = 100,
                           session_id: int = None) -> list:
        if session_id:
            cursor = self.conn.execute("""
                SELECT id, time, protocol, src_ip, dst_ip,
                       src_port, dst_port, length, ttl, flags
                FROM packets WHERE session_id = ?
                ORDER BY id DESC LIMIT ?
            """, (session_id, limit))
        else:
            cursor = self.conn.execute("""
                SELECT id, time, protocol, src_ip, dst_ip,
                       src_port, dst_port, length, ttl, flags
                FROM packets ORDER BY id DESC LIMIT ?
            """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_packet_detail(self, packet_id: int) -> dict:
        cursor = self.conn.execute(
            "SELECT detail FROM packets WHERE id = ?", (packet_id,)
        )
        row = cursor.fetchone()
        return json.loads(row["detail"]) if row else {}

    def get_protocol_stats(self, session_id: int = None) -> list:
        if session_id:
            cursor = self.conn.execute("""
                SELECT protocol, COUNT(*) as count FROM packets
                WHERE session_id = ?
                GROUP BY protocol ORDER BY count DESC
            """, (session_id,))
        else:
            cursor = self.conn.execute("""
                SELECT protocol, COUNT(*) as count FROM packets
                GROUP BY protocol ORDER BY count DESC
            """)
        return [dict(row) for row in cursor.fetchall()]

    def get_top_ips(self, limit: int = 10,
                    session_id: int = None) -> list:
        if session_id:
            cursor = self.conn.execute("""
                SELECT src_ip as ip, COUNT(*) as count
                FROM packets WHERE session_id = ? AND src_ip IS NOT NULL
                GROUP BY src_ip ORDER BY count DESC LIMIT ?
            """, (session_id, limit))
        else:
            cursor = self.conn.execute("""
                SELECT src_ip as ip, COUNT(*) as count
                FROM packets WHERE src_ip IS NOT NULL
                GROUP BY src_ip ORDER BY count DESC LIMIT ?
            """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def get_traffic_over_time(self, session_id: int = None) -> list:
        if session_id:
            cursor = self.conn.execute("""
                SELECT time, COUNT(*) as count FROM packets
                WHERE session_id = ?
                GROUP BY time ORDER BY time ASC
            """, (session_id,))
        else:
            cursor = self.conn.execute("""
                SELECT time, COUNT(*) as count FROM packets
                GROUP BY time ORDER BY time ASC
            """)
        return [dict(row) for row in cursor.fetchall()]

    def get_recent_alerts(self, limit: int = 20,
                          session_id: int = None) -> list:
        if session_id:
            cursor = self.conn.execute("""
                SELECT * FROM alerts WHERE session_id = ?
                ORDER BY id DESC LIMIT ?
            """, (session_id, limit))
        else:
            cursor = self.conn.execute("""
                SELECT * FROM alerts ORDER BY id DESC LIMIT ?
            """, (limit,))
        return [dict(row) for row in cursor.fetchall()]

    def close(self):
        self.conn.close()