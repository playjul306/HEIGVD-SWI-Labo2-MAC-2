# Auteurs : Benoit Julien et Sutcu Volkan
# But: find all stations which search a given SSID
# Date : 12.03.2020

from scapy.all import *
import argparse

staList = []

def staScanner(pkt):
    # If the packet is en probe request and the SSID matches and the station is not in the list of stations
    if pkt.type == 0 and pkt.subtype == 4 and pkt.info.decode() == tab_args.SSID and pkt.addr2 not in staList:
        staList.append(pkt.addr2)
        # Display the title on the first start
        if len(staList) == 1:
            print("Here are stations who search the SSID " + tab_args.SSID + "\n")
        print(pkt.addr2)

# Permit to add args to the script
parser = argparse.ArgumentParser(prog="script2_a.py", description="Find all stations which searc a given SSID")
conf.verb = 0
parser.add_argument("-s", "--SSID", required=True, help="SSID which is searched")
parser.add_argument("-i", "--Interface", required=True, help="Interface which will used to sniff")
tab_args = parser.parse_args()

# Capture the packet to analyze it in the function
sniff(iface=tab_args.Interface, prn=staScanner)

