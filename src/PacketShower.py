from scapy.all import sniff, IP, TCP, UDP, ARP, Ether,DHCP
import socket

router = "172.17.79.254"

def packet_callback(packet):
    if packet.haslayer(DHCP):
        #packet.show()
        #print(packet.layers())
        dhcp_options = packet[DHCP].options

        for elem in dhcp_options:
            #print("elem",elem)
            #print(type(elem))
            if elem[0] == 'router':
                print("router: ",elem[1])



sniff(prn=packet_callback, store=0)