from scapy.all import *
import socket
import datetime
import sqlite3

# --- SQLite setup ---
conn = sqlite3.connect("network_packets.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    protocol TEXT,
    direction TEXT,
    length INTEGER,
    ip_version TEXT,
    src_mac TEXT,
    dst_mac TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER
)
""")
conn.commit()

# --- Helper: get local IP ---
def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

local_ip = get_local_ip()

# --- Packet handler ---
def network_monitoring(pkt):
    timestamp = datetime.datetime.now()
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "N/A"

    src_port = None
    dst_port = None
    ip_version = "N/A"
    src_ip = "N/A"
    dst_ip = "N/A"
    direction = "N/A"

    # --- TCP ---
    if pkt.haslayer(TCP):
        ip_layer = IP if pkt.haslayer(IP) else IPv6 if pkt.haslayer(IPv6) else None
        if not ip_layer:
            return
        ip_version = str(int(pkt[ip_layer].version))
        src_ip = pkt[ip_layer].src
        dst_ip = pkt[ip_layer].dst
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        direction = "IN" if dst_ip == local_ip else "OUT"
        print(f"[{timestamp}] TCP-{direction}: {len(pkt[TCP])} Bytes SRC:{src_ip}:{src_port} DST:{dst_ip}:{dst_port}")

        cursor.execute("""
            INSERT INTO packets (timestamp, protocol, direction, length, ip_version,
                                 src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), "TCP", direction, len(pkt[TCP]), ip_version,
              src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port))

    # --- UDP ---
    elif pkt.haslayer(UDP):
        ip_layer = IP if pkt.haslayer(IP) else IPv6 if pkt.haslayer(IPv6) else None
        if not ip_layer:
            return
        ip_version = str(int(pkt[ip_layer].version))
        src_ip = pkt[ip_layer].src
        dst_ip = pkt[ip_layer].dst
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
        direction = "IN" if dst_ip == local_ip else "OUT"
        print(f"[{timestamp}] UDP-{direction}: {len(pkt[UDP])} Bytes SRC:{src_ip}:{src_port} DST:{dst_ip}:{dst_port}")

        cursor.execute("""
            INSERT INTO packets (timestamp, protocol, direction, length, ip_version,
                                 src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), "UDP", direction, len(pkt[UDP]), ip_version,
              src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port))

    # --- ICMP ---
    elif pkt.haslayer(ICMP):
        ip_layer = IP if pkt.haslayer(IP) else IPv6 if pkt.haslayer(IPv6) else None
        if ip_layer:
            ip_version = str(int(pkt[ip_layer].version))
            src_ip = pkt[ip_layer].src
            dst_ip = pkt[ip_layer].dst
            direction = "IN" if dst_ip == local_ip else "OUT"
        print(f"[{timestamp}] ICMP-{direction}: {len(pkt[ICMP])} Bytes SRC:{src_ip} DST:{dst_ip}")

        cursor.execute("""
            INSERT INTO packets (timestamp, protocol, direction, length, ip_version,
                                 src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), "ICMP", direction, len(pkt[ICMP]), ip_version,
              src_mac, dst_mac, src_ip, dst_ip, None, None))

    # --- ARP ---
    elif pkt.haslayer(ARP):
        src_ip = pkt[ARP].psrc
        dst_ip = pkt[ARP].pdst
        direction = "IN" if dst_ip == local_ip else "OUT"
        print(f"[{timestamp}] ARP-{direction}: SRC:{src_ip} DST:{dst_ip}")

        cursor.execute("""
            INSERT INTO packets (timestamp, protocol, direction, length, ip_version,
                                 src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), "ARP", direction, len(pkt), "N/A",
              pkt[ARP].hwsrc, pkt[ARP].hwdst, src_ip, dst_ip, None, None))

    # --- STP ---
    elif pkt.haslayer(Dot3) and pkt.haslayer(LLC) and pkt.haslayer(STP):
        print(f"[{timestamp}] STP Frame: SRC:{src_mac} DST:{dst_mac}")
        cursor.execute("""
            INSERT INTO packets (timestamp, protocol, direction, length, ip_version,
                                 src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (str(timestamp), "STP", "N/A", len(pkt), "N/A", src_mac, dst_mac, "N/A", "N/A", None, None))

    conn.commit()

# --- Start sniffing ---
if __name__ == '__main__':
    print(f"Starting network monitoring on local IP: {local_ip}")
    print("Default interface:", conf.iface)
    try:
        sniff(prn=network_monitoring, store=False)
    except KeyboardInterrupt:
        print("\nStopping capture...")
    finally:
        conn.commit()
        conn.close()
        print("Database connection closed.")
