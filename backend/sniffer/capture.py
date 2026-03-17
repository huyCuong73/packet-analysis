import socket
import struct
import os
import time
import threading
import fcntl
from datetime import datetime
from typing import Callable, List, Optional


def _normalize_frame(buf, datalink):

    import struct


    if datalink == 1:
        return buf

    elif datalink == 113:
        if len(buf) < 16:
            return None
        proto = struct.unpack('!H', buf[14:16])[0]
        payload = buf[16:]

      
        fake_eth = (
            b'\xff\xff\xff\xff\xff\xff' + 
            b'\x00\x00\x00\x00\x00\x00' +  
            struct.pack('!H', proto)      
        )
        return fake_eth + payload

  
    elif datalink == 0:
        if len(buf) < 4:
            return None
        af = struct.unpack('<I', buf[:4])[0]  
        payload = buf[4:]


        if af == 2:
            fake_eth = (
                b'\xff\xff\xff\xff\xff\xff' +
                b'\x00\x00\x00\x00\x00\x00' +
                b'\x08\x00'  
            )
            return fake_eth + payload

 
    elif datalink == 228:
        fake_eth = (
            b'\xff\xff\xff\xff\xff\xff' +
            b'\x00\x00\x00\x00\x00\x00' +
            b'\x08\x00'  
        )
        return fake_eth + buf


    return None

class PacketCapture:

    def __init__(self):
        self.captured_packets: List[bytes] = []
        self.is_running = False
        self._sock = None



    @staticmethod
    def list_interfaces() -> list:
        try:
            interfaces = []
            net_dir = "/sys/class/net/"
            for iface in os.listdir(net_dir):
                ip_addr = PacketCapture._get_iface_ip(iface)
                interfaces.append({
                    "name":        iface,
                    "description": iface,
                    "ip":          ip_addr,
                    "mac":         PacketCapture._get_iface_mac(iface)
                })
            return interfaces
        except Exception as e:
            print(f"[!] error listing interfaces: {e}")
            return []

    


    @staticmethod
    def _get_iface_ip(iface_name):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  
                struct.pack('256s', iface_name.encode('utf-8')[:15])
            )[20:24])
            s.close()
            return ip
        except Exception:
            return "N/A"

    @staticmethod
    def _get_iface_mac(iface_name):
        try:
            with open(f"/sys/class/net/{iface_name}/address") as f:
                return f.read().strip()
        except Exception:
            return "N/A"







    def start_live_capture(
        self,
        interface: str = None,
        bpf_filter: str = "",
        count: int = 0,
        callback: Callable = None
    ):

        self.is_running = True
        self.captured_packets = []

        try:
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.ntohs(0x0003)
            )

            if interface:
                self._sock.bind((interface, 0))

            self._sock.settimeout(1.0)  

            print(f"[*] Bắt đầu capture (Raw Socket)")
            print(f"    Interface : {interface or 'tất cả'}")

            packet_count = 0

            while self.is_running:
                try:
                    raw_data, addr = self._sock.recvfrom(65535)

                    self.captured_packets.append(raw_data)
                    packet_count += 1

                    if callback:
                        callback(raw_data)

                    if count > 0 and packet_count >= count:
                        break

                except socket.timeout:
                    continue
                except KeyboardInterrupt:
                    print("\nUser stop capture.")
                    break

        except PermissionError:
            print("root requested")
        except Exception as e:
            print(f" error capturing: {e}")
        finally:
            self.is_running = False
            if self._sock:
                self._sock.close()
                self._sock = None

    def stop(self):
        self.is_running = False








    @staticmethod
    def load_from_pcap(filepath, callback=None) -> list:
        if not os.path.exists(filepath):
            print(f"[!] Không tìm thấy file: {filepath}")
            return []


        with open(filepath, 'rb') as f:
            magic = f.read(4)

        if magic == b'\x0a\x0d\x0d\x0a':
            return PacketCapture._load_pcapng(filepath, callback)
        else:
            return PacketCapture._load_pcap(filepath, callback)

    @staticmethod
    def _load_pcapng(filepath, callback=None) -> list:
        try:
            import dpkt
        except ImportError:
            print("require dpkt")
            return []

        packets = []
        try:
            with open(filepath, 'rb') as f:
                reader = dpkt.pcapng.Reader(f)
                datalink = reader.datalink()
                for ts, buf in reader:

                    normalized = _normalize_frame(buf, datalink)
                    if normalized:
                        packets.append((ts, normalized))
                        if callback:
                            callback((ts, normalized))

        except Exception as e:
            print(e)

        return packets

    
    @staticmethod
    def _load_pcap(filepath, callback=None) -> list:

        if not os.path.exists(filepath):
            print(f"Không tìm thấy file")
            return []

        packets = []

        with open(filepath, 'rb') as f:
       
            global_header = f.read(24)
            if len(global_header) < 24:
                print("File quá ngắn")
                return []

            magic = struct.unpack('<I', global_header[:4])[0]

       
            if magic == 0xa1b2c3d4:
                endian = '<' 
            elif magic == 0xd4c3b2a1:
                endian = '>' 
            else:
                print(f"không phải PCAP")
                return []

    
            idx = 0
            while True:
            
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break

                ts_sec, ts_usec, incl_len, orig_len = \
                    struct.unpack(f'{endian}IIII', pkt_header)

          
                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                ts = ts_sec + ts_usec / 1000000.0
                packets.append((ts, pkt_data))
                idx += 1

                if callback:
                    callback((ts, pkt_data))

        print(f"[+] Đọc được {len(packets)} gói tin từ {filepath}")
        return packets


    @staticmethod
    def save_to_pcap(packets, filepath=None) -> str:

        if not packets:
            print("Không ")
            return ""

        os.makedirs("captures", exist_ok=True)

        if not filepath:
            timestamp = datetime.now().strftime("%Y%m%d_%H-%M-%S")
            filepath = f"captures/capture_{timestamp}.pcap"

        with open(filepath, 'wb') as f:
            f.write(struct.pack('<IHHIIII',
                0xa1b2c3d4,  
                2,            
                4,            
                0,            
                0,            
                65535,        
                1             
            ))
      
            now = int(time.time())
            for pkt in packets:
                pkt_len = len(pkt)
                f.write(struct.pack('<IIII', now, 0, pkt_len, pkt_len))
                f.write(pkt)

        print(f"Đã lưu")
        return filepath

    

    def get_summary(self) -> dict:
        return {
            "total":      len(self.captured_packets),
            "is_running": self.is_running
        }