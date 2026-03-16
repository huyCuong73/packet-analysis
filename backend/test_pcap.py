from sniffer.capture import PacketCapture
from analyzer.protocol import analyze_packet

capture = PacketCapture()

# ── Test 1: Bắt 10 gói với BPF filter ────────────────────────────────────
print("=== TEST 1: Live Capture với BPF Filter ===")

def show_packet(packet):
    result = analyze_packet(packet)
    ip = result.get("ip", {})
    print(f"  [{result['time']}] {result['transport_proto']} | "
          f"{ip.get('src_ip','?')} → {ip.get('dst_ip','?')} | "
          f"TTL={ip.get('ttl','?')} ({ip.get('os_guess','')})")

interfaces = capture.list_interfaces()

capture.start_live_capture(
    interface=None,
    bpf_filter="tcp",       # chỉ bắt gói TCP
    count=5,
    callback=show_packet
)

# ── Test 2: Lưu ra file PCAP ──────────────────────────────────────────────
print("\n=== TEST 2: Lưu file PCAP ===")
saved_file = capture.save_to_pcap()

# ── Test 3: Đọc lại file PCAP vừa lưu ────────────────────────────────────
if saved_file:
    print(f"\n=== TEST 3: Đọc lại file {saved_file} ===")
    capture2 = PacketCapture()
    capture2.load_from_pcap(saved_file, callback=show_packet)