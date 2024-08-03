from packet_sniffer import sniff_packets


def main():
    packets =  sniff_packets()
    print(packets)




if __name__ == "__main__":
    main()