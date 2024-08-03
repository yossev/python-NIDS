from packet_sniffer import sniff_packets
from feature_extraction import process_packets
from feature_extraction  import save_features_to_csv

def main():
    packets =  sniff_packets()
    print(packets)

    df = process_packets(packets)

    save_features_to_csv(df, 'packet_features.csv')





if __name__ == "__main__":
    main()