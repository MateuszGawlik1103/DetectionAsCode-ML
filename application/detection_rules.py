from scapy.all import *
from collections import defaultdict
from time import time

def http_get(packet):
    """
    Wykrywa żądania HTTP GET w pakietach.
    """
    if packet.haslayer("TCP") and packet["TCP"].dport == 80:
        if b"GET" in bytes(packet.payload):
            return True, f"HTTP GET detected from {packet['IP'].src} to {packet['IP'].dst}"
    return False, None


def dns_query(packet):
    """
    Wykrywa zapytania DNS w pakietach.
    """
    if packet.haslayer("UDP") and packet["UDP"].dport == 53:
        if packet.haslayer("DNS") and packet["DNS"].qr == 0:
            domain_name = packet["DNS"].qd.qname.decode("utf-8")
            return True, f"DNS query for {domain_name}"
    return False, None


def ssh_connection(packet):
    """
    Wykrywa próbę połączenia SSH na porcie 22.
    """
    if packet.haslayer("TCP") and packet["TCP"].dport == 22:
        return True, f"SSH connection attempt from {packet['IP'].src} to {packet['IP'].dst}"
    return False, None


def icmp_ping(packet):
    """
    Wykrywa pakiety ICMP (ping).
    """
    if packet.haslayer("ICMP") and packet["ICMP"].type == 8:
        return True, f"ICMP Echo request (ping) from {packet['IP'].src} to {packet['IP'].dst}"
    return False, None


syn_counter = defaultdict(list)


def syn_flood(packet, threshold=100, delta_time=10):
    if packet.haslayer("TCP") and packet["TCP"].flags == "S":
        ip_src = packet["IP"].src
        current_time = time()
        syn_counter[ip_src].append(current_time)
        syn_counter[ip_src] = [t for t in syn_counter[ip_src] if current_time - t <= delta_time]
        
        if len(syn_counter[ip_src]) > threshold:
            return True, f"SYN Flood detected from {ip_src} (over {threshold} SYNs in {delta_time}s)"
    
    return False, None

