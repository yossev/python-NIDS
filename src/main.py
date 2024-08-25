from packet_sniffer import sniff_packets
from feature_extraction import process_packets
from feature_extraction  import save_features_to_csv

def main():
    packets =  sniff_packets()
    ascii = """
    _..-'(                       )`-.._
                   ./'. '||\\.       (\_/)       .//||` .`\.
                ./'.|'.'||||\\|..    )O O(    ..|//||||`.`|.`\.
             ./'..|'.|| |||||\`````` '`"'` ''''''/||||| ||.`|..`\.
           ./'.||'.|||| ||||||||||||.     .|||||||||||| |||||.`||.`\.
          /'|||'.|||||| ||||||||||||{     }|||||||||||| ||||||.`|||`\
         '.|||'.||||||| ||||||||||||{     }|||||||||||| |||||||.`|||.`
        '.||| ||||||||| |/'   ``\||``     ''||/''   `\| ||||||||| |||.`
        |/' \./'     `\./         \!|\   /|!/         \./'     `\./ `\|
        V    V         V          }' `\ /' `{          V         V    V
        `    `         `               V               '         '    '
    """

    print(ascii)


    input("Welcome to batds IDS")
    print("--help for the list of commands")
    while True:
        command = input("batds> ")
        if command == "--help":
            print("Commands:")
            print("--exit: Exit the program")
            print("--show: Show the features of the packets")
            print("--save: Save the features of the packets to a csv file")
        elif command == "--exit":
            break
        elif command == "--show":
            df = process_packets(packets)
            print("Processing packets...")
            print("Showing features of the packets")
            print(df)
        elif command == "--save":
            print("Saving features of the packets to a csv file")
            save_features_to_csv(df, 'packet_features.csv')
        else:
            print("Invalid command")





if __name__ == "__main__":
    main()