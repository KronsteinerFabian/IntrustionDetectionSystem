from scapy.all import sniff, Ether, conf
from collections import defaultdict, deque
import datetime
import time

# Parameter für die Flood-Erkennung
FLOOD_THRESHOLD = 50  # Anzahl neuer MACs im Zeitfenster
TIME_WINDOW = 10       # Zeitfenster in Sekunden
print(conf.ifaces)
mac_seen = set()
mac_timestamps = deque()

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
        print(f"[ALARM] Möglicher MAC-Flooding-Angriff erkannt ({len(mac_seen)} neue MACs in {TIME_WINDOW}s)!")
        print(f"Letzte MAC: {mac_address} um {datetime.datetime.now()}")
        # Zurücksetzen, um mehrfachen Spam zu vermeiden
        mac_seen.clear()
        mac_timestamps.clear()

def packet_callback(packet):
    if packet.haslayer(Ether):
        src_mac = packet[Ether].src
        detect_mac_flooding(src_mac)

print("Starte MAC-Flooding-Erkennung...")
sniff(prn=packet_callback, store=0, iface="ASIX USB to Gigabit Ethernet Family Adapter")
