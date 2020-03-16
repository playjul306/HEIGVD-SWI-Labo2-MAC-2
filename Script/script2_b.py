# Auteurs : Benoit Julien et Sutcu Volkan
# But: find which station is linked with an AP
# Date : 12.03.2020

from scapy.all import *
import argparse

listOfLinks = []
# Unauthorized source or destination adress
BROADCAST = "ff:ff:ff:ff:ff:ff"

def linkScanner(pkt):
    # Get only data packet which confirm that link between STA and AP exists
    if pkt.type == 2:
        # If BSSID exist and source/destination adress are not a broadcast adress, we continue
        if pkt.addr3 is not None and pkt.addr1 != BROADCAST and pkt.addr2 != BROADCAST:
            # We want to have station adress in position 1 and AP adress in position 3 in the tuple so we check them 
            if pkt.addr1 != pkt.addr3:
                link = (pkt.addr1, pkt.addr3)
            else:
                link = (pkt.addr2, pkt.addr3)

            # If the tuple doesn't exists in the list, so we can add it
            if link not in listOfLinks:
                listOfLinks.append(link)
                # Display title one time
                if len(listOfLinks) == 1:
                    print("\nSTA \t\t\t\t AP")
                # Display station which linked to AP
                print(link[0] + " \t\t " + link[1])

# Permit to add arg to the script
parser = argparse.ArgumentParser(prog="script2_b.py", description="Permit to find which station is linked with an AP")
conf.verb = 0
parser.add_argument("-i", "--Interface", required=True, help="Interface which will used to sniff")
tab_args = parser.parse_args()

# Capture packet to analyze it in the function
sniff(iface=tab_args.Interface, prn=linkScanner)
listOfLinks.clear()
