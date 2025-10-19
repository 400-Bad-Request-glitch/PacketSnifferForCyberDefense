from scapy.all import *
import socket
import datetime

def get_local_ip():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]

local_ip = get_local_ip()


#def network_monitoring(pkt):
   #if pkt.haslayer(DNS): 
     #print(pkt)

def network_monitoring(pkt):
    timestamp = datetime.datetime.now()

    # MAC addresses  
    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else "N/A"
    dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else "N/A"

    if pkt.haslayer(TCP):
        ip_layer = IP if pkt.haslayer(IP) else IPv6 if pkt.haslayer(IPv6) else None
        if not ip_layer:
            return

        direction = "IN" if pkt[ip_layer].dst == local_ip else "OUT"
        print(f"[{timestamp}] TCP-{direction}: {len(pkt[TCP])} Bytes "
              f"SRC-MAC: {src_mac} DST-MAC: {dst_mac} "
              f"SRC-Port: {pkt[TCP].sport} DST-Port: {pkt[TCP].dport} "
              f"SRC-IP: {pkt[ip_layer].src} DST-IP: {pkt[ip_layer].dst}")

    elif pkt.haslayer(UDP) and pkt.haslayer(IP):
        direction = "IN" if pkt[IP].dst == local_ip else "OUT"
        print(f"[{timestamp}] UDP-{direction}: {len(pkt[UDP])} Bytes "
              f"SRC-MAC: {src_mac} DST-MAC: {dst_mac} "
              f"SRC-Port: {pkt[UDP].sport} DST-Port: {pkt[UDP].dport} "
              f"SRC-IP: {pkt[IP].src} DST-IP: {pkt[IP].dst}")

    elif pkt.haslayer(ICMP) and pkt.haslayer(IP):
        direction = "IN" if pkt[IP].dst == local_ip else "OUT"
        print(f"[{timestamp}] ICMP-{direction}: {len(pkt[ICMP])} Bytes "
              f"IP-Version: {pkt[IP].version} "
              f"SRC-MAC: {src_mac} DST-MAC: {dst_mac} "
              f"SRC-IP: {pkt[IP].src} DST-IP: {pkt[IP].dst}")

if __name__ == '__main__':
    print(f"Starting network monitoring on local IP: {local_ip}")    
    print("Default interface:", conf.iface)
    sniff(prn=network_monitoring, store=False)
