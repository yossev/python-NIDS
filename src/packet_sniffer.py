from scapy.all import sniff, IP, TCP


def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP] 
        print(f"New Packet: {ip_layer.src} -> {ip_layer.dst}")
        if TCP in packet and packet[TCP].dport > 1024:  
            print(f"Suspicious packet detected: {ip_layer.src}:{packet[TCP].sport} -> {ip_layer.dst}:{packet[TCP].dport}")
     


def sniff_packets():
    packets =  sniff(prn=packet_callback, count=10)
    return packets