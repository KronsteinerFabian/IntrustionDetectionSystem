#ARP-SPOOFING
from scapy.all import sniff, IP, TCP, UDP, ARP, Ether, conf, srp
import datetime
import socket
import sys
from colorama import Fore, Style
from getmac import get_mac_address
#MAC-FLOOD
from collections import defaultdict, deque
import datetime
import time
import json
import requests
#Flask
from flask import Flask, jsonify
import threading

#Flask Setup API
app = Flask(__name__)
last_attack = {}  # wird über HTTP verfügbar gemacht

@app.route('/current-attack')
def current_attack():
    return jsonify(last_attack)

def start_flask():
    app.run(port=5000)

# Parameter für die Flood-Erkennung
FLOOD_THRESHOLD = 50  # Anzahl neuer MACs im Zeitfenster
TIME_WINDOW = 10       # Zeitfenster in Sekunden
print(conf.ifaces)
mac_seen = set()
mac_timestamps = deque()

#ARP
print(conf.ifaces)
#conf.iface="ASIX USB to Gigabit Ethernet Family Adapter"

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
reset_timer = None
#Flask
def create_attack_report(attack_type, source):
    return {
        "timestamp": str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        "attack_type": attack_type,
        "source": source
    }


def report_attack(attack_type, source_ip):
    global last_attack, reset_timer

    last_attack = create_attack_report(attack_type, source_ip)
    print(Fore.RED + f"[!] Angriff erkannt: {attack_type} von {source_ip}" + Style.RESET_ALL)

    with open("log.txt", "a") as file:
        file.write(f"{last_attack['timestamp']} {attack_type} from {source_ip}\n")

    # Timer zurücksetzen (falls bereits läuft)
    if reset_timer:
        reset_timer.cancel()
    reset_timer = threading.Timer(20.0, reset_last_attack)
    reset_timer.start()


def reset_last_attack():
    global last_attack
    print(Fore.YELLOW + "[Info] Angriffseintrag wird nach 20 Sekunden zurückgesetzt." + Style.RESET_ALL)
    last_attack = {}

print("Time------------------------Source------------Destination-------Source---------Destination------Source--------Destination---")



def detect_mac_flooding(mac_address):
    now = time.time()
    mac_timestamps.append((mac_address, now))

    # Ältere Einträge außerhalb des Zeitfensters entfernen
    while mac_timestamps and now - mac_timestamps[0][1] > TIME_WINDOW:
        old_mac, _ = mac_timestamps.popleft()
        mac_seen.discard(old_mac)

    # Neue MAC prüfen
    if mac_address not in mac_seen:
        mac_seen.add(mac_address)

    # Flood-Erkennung
    if len(mac_seen) > FLOOD_THRESHOLD:
        print(Fore.RED,end="")
        print(f"[ALARM] Möglicher MAC-Flooding-Angriff erkannt ({len(mac_seen)} neue MACs in {TIME_WINDOW}s)!")
        print(Style.RESET_ALL,end="")
        print(f"Letzte MAC: {mac_address} um {datetime.datetime.now()}")
        # Zurücksetzen, um mehrfachen Spam zu vermeiden
        mac_seen.clear()
        mac_timestamps.clear()
        #with open("log.txt", "a") as file:
            #file.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " MAC-FLOOD\n")
        report_attack("MAC Flooding","-")


def packet_callback(packet):

    # packet.show()

    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        detect_mac_flooding(src_mac)
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
            #with open("log.txt", "a") as file:
                #file.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " ARP-SPOOF\n")
            report_attack("ARP-Spoofing",arp_mac_src)

        if (gateway_mac == ""):
            print("hey")

    print()

# === Hauptprogramm ===

if __name__ == '__main__':
    # Flask in separatem Thread starten
    threading.Thread(target=start_flask, daemon=True).start()
    print(">>> Flask-Server läuft auf http://localhost:5000/current-attack\n")

    # Sniffer starten
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    sniff(prn=packet_callback, store=0, count=count)