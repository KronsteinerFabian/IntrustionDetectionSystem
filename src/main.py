
from scapy.all import sniff, IP, TCP, UDP,ARP, Ether
import datetime
import socket
import sys
from colorama import Fore, Style
from getmac import get_mac_address

local_ip = socket.gethostbyname(socket.gethostname())
local_mac = get_mac_address()
ip_mac_dic = {}

print(f"localhost {local_ip} mac: {local_mac}")

print("Time                        |                  MAC              |           IP           |                                  ARP                                  |\nTime------------------------Source------------Destination-------Source---------Destination------Source-------------Destination--------Source---------Destination--")
#print("Time------------------------Source------------Destination-------Source---------Destination------Source--------Destination---")
def packet_callback(packet):

    #packet.show()

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        print(Fore.CYAN + str(datetime.datetime.now())+Style.RESET_ALL,end="  ")
        print(src_mac +" "+dst_mac ,end="\t")


    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "UNKNOWN"


        if src_ip == local_ip or dst_ip == local_ip:
            print(Fore.GREEN + src_ip + "\t"+ dst_ip+Style.RESET_ALL+"\t",end="")
        else:
            print(src_ip + "\t"+ dst_ip+"\t",end="")

    else:
        print("\t\t\t\t\t\t\t\t",end="")
    

    if packet.haslayer(ARP):
        arp_ip_src = packet.psrc
        arp_mac_src = packet.hwsrc
        arp_ip_dst = packet.pdst
        arp_mac_dst = packet.hwdst

        if arp_mac_src == local_mac or arp_mac_src == local_mac:
            print(Fore.GREEN+arp_mac_src+"  "+arp_mac_dst+Style.RESET_ALL,end="  ")
        else:
            print(arp_mac_src + "  " + arp_mac_dst,end="  ")

        if arp_ip_dst == local_ip or arp_ip_src == local_ip:
            print(Fore.GREEN + arp_ip_src + "  " + arp_ip_dst + Style.RESET_ALL, end="")
        else:
            print(arp_ip_src + "  " + arp_ip_dst, end="")

        #print(arp_ip_src+" "+arp_mac_dst+" ",end=" ")

        if arp_ip_src in ip_mac_dic and arp_mac_src not in ip_mac_dic[arp_ip_src] and arp_ip_src != "0.0.0.0":
            print(Fore.RED + "Alarm!" + Style.RESET_ALL, end="")
        else:
            if arp_ip_src !="0.0.0.0":
                ip_mac_dic[arp_ip_src] = arp_mac_src


    print()
        
count=500
if len(sys.argv) > 1:
    count=int(sys.argv[1])


sniff(prn=packet_callback, store=0,count=count)

print("IP-ARP-Pool")
for key,value in ip_mac_dic.items():
    print(key,": ", value)
