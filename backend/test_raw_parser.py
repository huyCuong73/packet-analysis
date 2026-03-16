#!/usr/bin/env python3
"""Test script — kiểm tra raw parser modules hoạt động đúng"""

import sys
sys.path.insert(0, '.')

# Test 1: Import tất cả modules
print("=== Test 1: Import modules ===")
try:
    from analyzer.raw_parser import (
        parse_ethernet, parse_ip, parse_tcp, parse_udp,
        parse_icmp, parse_arp, parse_dns, hex_dump
    )
    print("[OK] raw_parser imported")
except Exception as e:
    print(f"[FAIL] raw_parser: {e}")
    sys.exit(1)

try:
    from analyzer.protocol import analyze_packet
    print("[OK] protocol imported")
except Exception as e:
    print(f"[FAIL] protocol: {e}")
    sys.exit(1)

try:
    from analyzer.app_layer import analyze_dns_raw, analyze_http_raw
    print("[OK] app_layer imported")
except Exception as e:
    print(f"[FAIL] app_layer: {e}")
    sys.exit(1)

try:
    from sniffer.capture import PacketCapture
    print("[OK] capture imported")
except Exception as e:
    print(f"[FAIL] capture: {e}")
    sys.exit(1)

# Test 2: Parse giả lập Ethernet + IP + TCP packet
print("\n=== Test 2: Parse Ethernet + IP + TCP ===")
import struct, socket

# Tạo Ethernet header (14 bytes)
eth = struct.pack('!6s6sH',
    b'\xaa\xbb\xcc\xdd\xee\xff',  # dst mac
    b'\x11\x22\x33\x44\x55\x66',  # src mac
    0x0800                          # IPv4
)

# Tạo IP header (20 bytes) - TCP protocol
ip_header = struct.pack('!BBHHHBBH4s4s',
    0x45,       # version=4, ihl=5
    0,          # tos
    60,         # total length
    1234,       # identification
    0,          # flags+offset
    64,         # ttl
    6,          # protocol = TCP
    0,          # checksum
    socket.inet_aton('192.168.1.100'),
    socket.inet_aton('93.184.216.34')
)

# Tạo TCP header (20 bytes)
tcp_header = struct.pack('!HHIIHHH H',
    12345,      # src port
    80,         # dst port
    100,        # seq
    0,          # ack
    (5 << 12) | 0x02,  # data_offset=5, flags=SYN
    65535,      # window
    0,          # checksum
    0           # urgent
)

raw_packet = eth + ip_header + tcp_header + b'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n'

result = analyze_packet(raw_packet)
print(f"  Protocol : {result['transport_proto']}")
print(f"  Src IP   : {result['ip'].get('src_ip')}")
print(f"  Dst IP   : {result['ip'].get('dst_ip')}")
print(f"  Src Port : {result['transport'].get('src_port')}")
print(f"  Dst Port : {result['transport'].get('dst_port')}")
print(f"  Flags    : {result['transport'].get('flags_active')}")
print(f"  OS Guess : {result['ip'].get('os_guess')}")
print(f"  Summary  : {result['summary']}")

assert result['transport_proto'] == 'HTTP', f"Expected HTTP, got {result['transport_proto']}"
assert result['ip']['src_ip'] == '192.168.1.100'
assert result['ip']['dst_ip'] == '93.184.216.34'
assert result['transport']['src_port'] == 12345
assert result['transport']['dst_port'] == 80
print("[OK] TCP/HTTP parsing passed!")

# Test 3: Parse ARP packet
print("\n=== Test 3: Parse ARP ===")
eth_arp = struct.pack('!6s6sH',
    b'\xff\xff\xff\xff\xff\xff',
    b'\x11\x22\x33\x44\x55\x66',
    0x0806
)
arp_data = struct.pack('!HHBBH6s4s6s4s',
    1, 0x0800, 6, 4, 1,
    b'\x11\x22\x33\x44\x55\x66', socket.inet_aton('192.168.1.1'),
    b'\x00\x00\x00\x00\x00\x00', socket.inet_aton('192.168.1.2')
)
result_arp = analyze_packet(eth_arp + arp_data)
print(f"  Proto: {result_arp['transport_proto']}")
print(f"  Op   : {result_arp['transport'].get('op')}")
assert result_arp['transport_proto'] == 'ARP'
assert result_arp['transport']['op'] == 'Request'
print("[OK] ARP parsing passed!")

# Test 4: Parse DNS query
print("\n=== Test 4: Parse DNS ===")
dns_payload = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)
dns_payload += b'\x06google\x03com\x00'
dns_payload += struct.pack('!HH', 1, 1)  # type A, class IN

udp_header = struct.pack('!HHHH', 54321, 53, 8 + len(dns_payload), 0)
ip_dns = struct.pack('!BBHHHBBH4s4s',
    0x45, 0, 20 + 8 + len(dns_payload), 0, 0, 64, 17, 0,
    socket.inet_aton('192.168.1.100'),
    socket.inet_aton('8.8.8.8')
)
eth_dns = struct.pack('!6s6sH', b'\xaa'*6, b'\xbb'*6, 0x0800)

result_dns = analyze_packet(eth_dns + ip_dns + udp_header + dns_payload)
print(f"  Proto : {result_dns['transport_proto']}")
dns_info = result_dns['app_layer'].get('dns', {})
print(f"  Type  : {dns_info.get('type')}")
print(f"  Query : {dns_info.get('queries')}")
assert result_dns['transport_proto'] == 'DNS'
assert dns_info['queries'][0]['name'] == 'google.com'
print("[OK] DNS parsing passed!")

# Test 5: PCAP reader (nếu có file .pcap)
print("\n=== Test 5: PCAP reader ===")
import os
pcap_files = [f for f in os.listdir('.') if f.endswith('.pcap')]
if pcap_files:
    packets = PacketCapture.load_from_pcap(pcap_files[0])
    print(f"  File: {pcap_files[0]}")
    print(f"  Packets: {len(packets)}")
    if packets:
        r = analyze_packet(packets[0])
        print(f"  First packet proto: {r['transport_proto']}")
    print("[OK] PCAP reader passed!")
else:
    print("[SKIP] No .pcap files found")

# Test 6: Interface listing
print("\n=== Test 6: Interface listing ===")
interfaces = PacketCapture.list_interfaces()
print(f"  Found {len(interfaces)} interfaces:")
for iface in interfaces:
    print(f"    - {iface['name']} (IP: {iface.get('ip', 'N/A')})")
print("[OK] Interface listing passed!")

print("\n" + "="*50)
print("ALL TESTS PASSED! Backend is Scapy-free!")
print("="*50)
