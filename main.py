import os
import signal
import sys
from datetime import datetime
import click
from scapy.all import rdpcap
from scapy.sendrecv import sniff
from application import detection_rules
import atexit
from application.csv import csv_append, csv_read
from application.flow_analysis import flows_summary
from application.visualization import generate_plot

DEFAULT_CSV_FILE = "alerts.csv"
TEMP_DIR = "temp"
OUTPUT_IMAGE = "output.png"
DETECTION_RULES = [
    getattr(detection_rules, rule)
    for rule in dir(detection_rules)
    if callable(getattr(detection_rules, rule))
    and getattr(detection_rules, rule).__module__ == detection_rules.__name__
]


@click.group()
def cli():
    pass


@click.command()
@click.argument("pcap_file")
@click.option("--summary", "-s", is_flag=True)
def analyze_pcap(pcap_file, summary):
    packets = rdpcap(pcap_file)
    csv_file = f"{TEMP_DIR}/{pcap_file}.csv"
    for packet in packets:
        detect(packet, csv_file)
    if os.path.exists(f"{TEMP_DIR}/{pcap_file}.csv"):
        data = csv_read(csv_file)
        generate_plot(data, OUTPUT_IMAGE)
    if summary:
        print(flows_summary(pcap_file))


def detect(packet, csv_file=DEFAULT_CSV_FILE):
    for rule in DETECTION_RULES:
        result, message = rule(packet)
        if result:
            timestamp = datetime.now()
            if csv_file is not None:
                csv_append(csv_file, timestamp, message)
            print(f"{timestamp} - \033[31mALERT\033[0m - {message}")


@click.command()   
@click.argument("interface")  
def listen(interface):
    print(f"{datetime.now()} - INFO - Listening on interface {interface}...")
    sniff(iface=interface, prn=lambda packet: detect(packet), store=0)

    def handle_sigint():
        data = csv_read(DEFAULT_CSV_FILE)
        generate_plot(data, OUTPUT_IMAGE)
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_sigint())


def delete_temp_files():
    for file_name in os.listdir(TEMP_DIR):
        file_path = os.path.join(TEMP_DIR, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)


atexit.register(delete_temp_files)
cli.add_command(listen)
cli.add_command(analyze_pcap)


if __name__ == "__main__":
    cli()
    