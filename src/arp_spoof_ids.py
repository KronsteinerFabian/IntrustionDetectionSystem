from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, conf, srp
import datetime
import socket
import sys
from colorama import Fore, Style
from getmac import get_mac_address

print(conf.ifaces)
conf.iface="ASIX USB to Gigabit Ethernet Family Adapter"

local_ip = socket.gethostbyname(socket.gethostname())
local_mac = get_mac_address()
ip_mac_dictionary = {}
#GPT Gateway IP und MAC
gateway_ip = conf.route.route("0.0.0.0")[2]

# ARP-Anfrage senden, um die MAC-Adresse des Gateways zu bekommen
arp_request = ARP(pdst=gateway_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast-Paket
packet = ether / arp_request

result = srp(packet, timeout=2, verbose=False)[0]
gateway_mac = ""
# MAC-Adresse extrahieren und ausgeben
if result:
    gateway_mac = result[0][1].hwsrc
    print(f"Gateway-MAC: {gateway_mac} Gateway-IP: {gateway_ip}")
else:
    print("Keine Antwort vom Gateway erhalten.")
print(f"Gateway-MAC: {gateway_mac} Gateway-IP: {gateway_ip}")
print(f"localhost {local_ip} mac: {local_mac}")

#print(
#    "Time                        |                  MAC              |           IP           |                                  ARP                                  |\nTime------------------------Source------------Destination-------Source---------Destination------Source-------------Destination--------Source---------Destination--")


print("Time------------------------Source------------Destination-------Source---------Destination------Source--------Destination---")
def packet_callback(packet):
    # packet.show()

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(Fore.CYAN + str(datetime.datetime.now()) + Style.RESET_ALL, end="  ")
        print(src_mac + " " + dst_mac, end="\t")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "UNKNOWN"

        if src_ip == local_ip or dst_ip == local_ip:
            print(Fore.GREEN + src_ip + "\t" + dst_ip + Style.RESET_ALL + "\t", end="")
        else:
            print(src_ip + "\t" + dst_ip + "\t", end="")

    else:
        print("\t\t\t\t\t\t\t\t", end="")

    if packet.haslayer(ARP):
        arp_ip_src = packet.psrc
        arp_mac_src = packet.hwsrc
        arp_ip_dst = packet.pdst
        arp_mac_dst = packet.hwdst

        if arp_mac_src == local_mac or arp_mac_src == local_mac:
            print(Fore.GREEN + arp_mac_src + "  " + arp_mac_dst + Style.RESET_ALL, end="  ")
        else:
            print(arp_mac_src + "  " + arp_mac_dst, end="  ")

        if arp_ip_dst == local_ip or arp_ip_src == local_ip:
            print(Fore.GREEN + arp_ip_src + "  " + arp_ip_dst + Style.RESET_ALL, end="")
        else:
            print(arp_ip_src + "  " + arp_ip_dst, end="")

        #print(arp_ip_src+" "+arp_mac_dst+" ",end=" ")

        #packet.show()
        #ARP-SPOOFING ERKENNUNG<------------------------------------
        if arp_mac_src != gateway_mac and arp_ip_src == gateway_ip:
            print(Fore.RED + "Alarm!" + Style.RESET_ALL, end="")
            # with open("log.txt", "a") as file:
            #     file.write(datetime.datetime.now() + " " + arp_mac_src + " " + arp_mac_dst)
        if (gateway_mac == ""):
            print("hey")

    print()

count = 1000
if len(sys.argv) > 1:
    count = int(sys.argv[1])

sniff(prn=packet_callback, store=0,#iface=conf.iface #count=count)
      )
print("IP-ARP-Pool")
for key, value in ip_mac_dictionary.items():
    print(key, ": ", value)
