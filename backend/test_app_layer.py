from sniffer.capture import PacketCapture
from analyzer.protocol import analyze_packet
from scapy.all import sniff

capture = PacketCapture()
interfaces = capture.list_interfaces()

def show_packet(packet):
    result = analyze_packet(packet)
    proto  = result["transport_proto"]
    app    = result.get("app_layer", {})

    # Chỉ in gói DNS hoặc HTTP
    if proto == "DNS" and app.get("dns"):
        dns = app["dns"]
        queries = dns.get("queries", [])
        for q in queries:
            flag = " SUSPICIOUS" if dns["is_suspicious"] else ""
            print(f"[DNS {dns['type'].upper()}] {q['name']} "
                  f"({q['type']}) {flag}")
            if dns["is_suspicious"]:
                print(f"  → {dns['suspicious_reason']}")

    elif proto == "HTTP" and app.get("http"):
        http = app["http"]
        if http["direction"] == "request":
            print(f"[HTTP {http['method']}] {http['host']}{http['uri']}")
            if http["credentials_found"]:
                print(f"  CREDENTIALS FOUND: {http['credentials']}")


print(f"Lắng nghe DNS + HTTP trên {interfaces[0]}...\n")
sniff(
    iface=None,
    filter="port 53 or port 80",   # chỉ DNS và HTTP
    prn=show_packet,
    count=20,
    store=False
)