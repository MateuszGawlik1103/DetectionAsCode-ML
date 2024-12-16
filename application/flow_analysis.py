from nfstream import NFStreamer


def flows_summary(pcap_file):
    stream = NFStreamer(source=pcap_file, statistical_analysis=True)
    flows = stream.to_pandas().groupby(['src_ip', 'dst_ip'])[['src2dst_packets', 'dst2src_packets']].sum()
    flows['total_packets'] = flows['src2dst_packets'] + flows['dst2src_packets']
    return flows
