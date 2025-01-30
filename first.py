from scapy.all import sniff, IP, TCP, UDP

# Fonction pour analyser chaque paquet capturé
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src  # Adresse IP source
        ip_dst = packet[IP].dst  # Adresse IP destination

        if TCP in packet:
            print(f"[TCP] {ip_src} -> {ip_dst} | Port source: {packet[TCP].sport}, Port destination: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"[UDP] {ip_src} -> {ip_dst} | Port source: {packet[UDP].sport}, Port destination: {packet[UDP].dport}")
        else:
            print(f"[Autre] {ip_src} -> {ip_dst}")

# Interface réseau
interface = input("Entrez l'interface réseau à écouter (ex : wlan0, eth0, lo) : ")

print(f"Sniffing sur l'interface {interface}... Appuyez sur Ctrl+C pour arrêter.")
sniff(iface=interface, prn=packet_callback, store=False)
