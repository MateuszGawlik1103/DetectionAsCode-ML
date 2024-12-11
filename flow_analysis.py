from nfstream import NFStreamer
import pandas as pd

pcap_file = "normal_traffic.pcap"
stream = NFStreamer(source=pcap_file)

flows = pd.DataFrame([{
    "src_ip": flow.src_ip,
    "dst_ip": flow.dst_ip,
    "total_packets": flow.total_packets,
    "total_bytes": flow.total_bytes,
    "protocol": flow.protocol
} for flow in stream])

print(flows.head())