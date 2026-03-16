from sniffer.capture import list_interfaces
from analyzer.protocol import analyze_packet
from scapy.all import sniff
import json

def my_callback(packet):
    result = analyze_packet(packet)
    
    print(f"\n{'='*60}")
    print(f"[{result['time']}] {result['transport_proto']} — {result['summary']}")
    
    # In chi tiết IP header
    ip = result['ip']
    if ip:
        print(f"  IP: v{ip['version']} | TTL={ip['ttl']} ({ip['os_guess']}) | "
              f"proto={ip['protocol_name']} | len={ip['total_length']}B")
    
    # In chi tiết TCP header
    tr = result['transport']
    if result['transport_proto'] == 'TCP' and tr:
        print(f"  TCP: flags={tr['flags_active']} | "
              f"window={tr['window_size']} | "
              f"seq={tr['seq']}")

interfaces = list_interfaces()
print(f"Bắt gói tin trên: {interfaces[0]}\n")
sniff(iface=None, prn=my_callback, count=10, store=False)