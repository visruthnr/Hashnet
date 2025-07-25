from scapy.all import sniff, TCP, IP, Raw
from firewall import is_blocked, log_blocked
from datetime import datetime

# Optional: Get MAC address to use as "hashed ID"


def get_mac(pkt):
    if pkt.haslayer(IP):
        return pkt[IP].src
    return "unknown"

# Callback for every packet


def inspect_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode('utf-8', errors='ignore')
            mac = get_mac(pkt)
            if is_blocked(payload):
                log_blocked(mac, "server", payload)
                print(
                    f"\n[🛡️ BLOCKED] {datetime.now()} | From: {mac}\n> {payload[:100]}")
            else:
                print(
                    f"\n[✅ ALLOWED] {datetime.now()} | From: {mac}\n> {payload[:100]}")
        except Exception as e:
            print(f"[⚠️] Failed to decode payload: {e}")


# Start sniffing
print("[🔁] Sniffer started. Monitoring packets on all interfaces...")
sniff(filter="tcp port 80", prn=inspect_packet, store=0)
