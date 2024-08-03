from scapy.all import IP, TCP
import pandas as pd


def extract_features(packet):
    features = {}

    if IP in packet:
        ip_layer = packet[IP]

        features['src_ip'] = ip_layer.src
        features['dst_ip'] = ip_layer.dst
        features['ip_len'] = ip_layer.len
        features['ip_ttl'] = ip_layer.ttl  # Time to live

    if TCP in packet:
        tcp_layer = packet[TCP]
        features['src_port'] = tcp_layer.sport
        features['dst_port'] = tcp_layer.dport
        features['tcp_flags'] = tcp_layer.flags
    
    features['packet_size'] = len(packet)
    return features



def process_packets(packets):
    features_list = []

    for packet in packets:
        features = extract_features(packet)
        features_list.append(features)

    # Convert the data to a DataFrame
    df = pd.DataFrame(features_list)
    return df
    

def save_features_to_csv(df, filename):
    df.to_csv(filename, index=False)