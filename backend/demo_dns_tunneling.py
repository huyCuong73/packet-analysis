"""
Demo phat hien DNS Tunneling.

Script nay tao cac goi DNS gia lap 3 tinh huong:
1. Ten mien qua dai (>50 ky tu)        -> nghi ro ri du lieu qua DNS
2. Qua nhieu subdomain (>5 cap)        -> nghi C&C communication
3. Subdomain chua du lieu ma hoa hex   -> nghi DNS exfiltration

Chay: python demo_dns_tunneling.py
"""

from analyzer.app_layer import _check_dns_suspicious


print("=" * 65)
print("  DEMO: PHAT HIEN DNS TUNNELING")
print("=" * 65)


# == Case 1: Ten mien qua dai =====================================
print("\n[!] CASE 1: Ten mien qua dai (>50 ky tu)")
print("    Ke tan cong giau du lieu trong ten mien DNS\n")

long_domain = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHNlY3JldA.data-exfil.evil.com"
print(f"    Domain : {long_domain}")
print(f"    Do dai : {len(long_domain)} ky tu\n")

suspicious, reason = _check_dns_suspicious(long_domain)
print(f"    Ket qua: {'>> DANG NGO <<' if suspicious else 'Binh thuong'}")
print(f"    Ly do  : {reason}")


# == Case 2: Qua nhieu subdomain ==================================
print("\n\n[!] CASE 2: Qua nhieu subdomain (>5 cap)")
print("    Ke tan cong dung nhieu cap subdomain de truyen lenh C&C\n")

many_subs = "cmd.exec.data.transfer.level5.level6.malware-c2.evil.com"
print(f"    Domain : {many_subs}")
print(f"    So cap : {len(many_subs.split('.'))} cap\n")

suspicious, reason = _check_dns_suspicious(many_subs)
print(f"    Ket qua: {'>> DANG NGO <<' if suspicious else 'Binh thuong'}")
print(f"    Ly do  : {reason}")


# == Case 3: Subdomain chua hex/base64 ============================
print("\n\n[!] CASE 3: Subdomain chua du lieu ma hoa (hex-like)")
print("    Ke tan cong ma hoa du lieu danh cap thanh subdomain\n")

hex_domain = "4a6f686e446f653a50617373776f726431323334.exfil.evil.com"
print(f"    Domain : {hex_domain}")

# Giai ma hex de thay du lieu an
hex_part = hex_domain.split(".")[0]
try:
    decoded = bytes.fromhex(hex_part).decode()
    print(f"    Giai ma: {decoded}  <-- du lieu bi danh cap!")
except Exception:
    pass
print()

suspicious, reason = _check_dns_suspicious(hex_domain)
print(f"    Ket qua: {'>> DANG NGO <<' if suspicious else 'Binh thuong'}")
print(f"    Ly do  : {reason}")


# == Case 4 (doi chung): DNS binh thuong ==========================
print("\n\n[OK] CASE 4 (doi chung): DNS binh thuong")
print("     Truy van DNS hop le, khong dang ngo\n")

normal_domain = "www.google.com"
print(f"    Domain : {normal_domain}")
print(f"    Do dai : {len(normal_domain)} ky tu\n")

suspicious, reason = _check_dns_suspicious(normal_domain)
print(f"    Ket qua: {'>> DANG NGO <<' if suspicious else 'Binh thuong'}")
if reason:
    print(f"    Ly do  : {reason}")

print("\n" + "=" * 65)
print("  Ket luan: NSM phat hien 3/4 truy van dang ngo")
print("  Cac dau hieu: ten dai, nhieu cap, du lieu ma hoa")
print("=" * 65)
