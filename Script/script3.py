# source :  https://books.google.ch/books?id=FEBPDwAAQBAJ&pg=PA106&lpg=PA106&dq=%22python%22+scapy+expose+ssid+hidden&source=bl&ots=UgQwo3kNkT&sig=ACfU3U2O_yhFzZb5vhWnMfTBLK3peIuKzg&hl=fr&sa=X&ved=2ahUKEwiQ_7qI4JToAhUjwsQBHd8NBrkQ6AEwCHoECAoQAQ#v=onepage&q=%22python%22%20scapy%20expose%20ssid%20hidden&f=false
#           https://www.acrylicwifi.com/en/blog/hidden-ssid-wifi-how-to-know-name-of-network-without-ssid/
#           https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/
#
# Auteurs : Benoit Julien et Sutcu Volkan
# But: Révéler les SSID cachés
# Date : 16.03.2020
from scapy.all import *
import texttable as tt
import argparse
from scapy.layers.dot11 import Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11

hiddenSSIDs = dict()

# Permait d'ajouter des arguments au scripts
parser = argparse.ArgumentParser(prog="script3.py", description="Ce script permet de révéler les SSID des réseaux cachés")
conf.verb = 0
parser.add_argument("-i", "--Interface", required=True, help="Interface qui doit être utilisée")
tab_args = parser.parse_args()

# Fonction permettant de récupérer le SSID d'un réseau caché grace au probe response
def parseSSID(pkt):
    if pkt.haslayer(Dot11Elt):
        # On récupère le bssid
        bssid = pkt[Dot11].addr3
        # On récupère le ssid et s'il contient des caractères "\000", on les remplace par ""
        ssid = pkt.info.decode().replace("\000","")
        # Si c'est une probe Response, cela veut dire qu'on peut récupérer son le ssid
        if (pkt.type == 0 and pkt.subtype == 5) and bssid in hiddenSSIDs.keys():
            hiddenSSIDs[bssid] = ssid
        # Si c'est une beacon Frame, cela veut dire que le ssid sera caché et donc on attend une probe response afin de découvrir le ssid de l'ap
        elif pkt.haslayer(Dot11Beacon) and bssid not in hiddenSSIDs.keys() and ssid == "":
            hiddenSSIDs[bssid] = "Hidden SSID"

# Fonction permettant d'afficher proprement les informations
def display(hiddenSSIDs):
    table = tt.Texttable()
    table.set_deco(tt.Texttable.HEADER)
    table.set_cols_dtype(['i','t','t']) 
    table.set_cols_align(["l", "l", "l"])
    table.add_row(["N°", "BSSID", "SSID"])

    i = 0

    for key, value in hiddenSSIDs.items() :
        i=i+1
        table.add_row([i, key, value])
    print (table.draw())

print("Sniffing en cours...")
# Sniff le réseau en exectutant la fonction parseSSID avec un timeout de 15 sec
sniff(iface=tab_args.Interface, prn=parseSSID, timeout=15)
display(hiddenSSIDs)
hiddenSSIDs.clear()
