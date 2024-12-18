import nfstream
from nfstream import NFStreamer

def convert_pcap_to_csv(pcap_file, output_csv):
    """
    Konwertuje plik PCAP na format CSV z użyciem NFStream.
    """
    try:
        # Przetwarzanie PCAP za pomocą NFStream
        streamer = NFStreamer(source=pcap_file, statistical_analysis=True)
        flow_df = streamer.to_pandas()

        # Zapis do pliku CSV
        flow_df.to_csv(output_csv, index=False)
        print(f"Plik {pcap_file} został pomyślnie zapisany jako {output_csv}.")
    except Exception as e:
        print(f"Błąd podczas konwersji PCAP do CSV: {e}")

convert_pcap_to_csv("./traffics/normal2_1.pcap", "./traffics/normal2_1.csv")
convert_pcap_to_csv("./traffics/malicious2_1.pcap", "./traffics/malicious2_1.csv")
