from scapy.all import sniff, IP, TCP
import logging

logging.basicConfig(filename="suspicious_ips.log", level=logging.INFO, format="%(asctime)s - %(message)s")

logged_ips = set()

def detect_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport

        if dst_port == 22:
            alert_msg = f"Possible SSH scan detected from {src_ip}"
            print(alert_msg)

            # Log the IP if not already logged
            if src_ip not in logged_ips:
                logging.info(alert_msg)
                logged_ips.add(src_ip)

print("Monitoring network traffic for suspicious activity...")
sniff(filter="tcp", prn=detect_packet, store=False)
