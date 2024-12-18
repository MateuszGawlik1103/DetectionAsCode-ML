import joblib
import nfstream
from nfstream import NFStreamer
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import requests
from ml_build_tree import load_traffic_data, calculate_fpr_tpr
from geopy.geocoders import Nominatim

matplotlib.use('TkAgg')


def enrich_ip(ip_addresses):
    """
    Wzbogaca adresy IP o informacje geolokalizacyjne przy użyciu ip-api.com.
    
    Args:
        ip_addresses (list): Lista adresów IP do wzbogacenia.
        
    Returns:
        dict: Słownik z informacjami o każdym adresie IP (kraj, miasto, region).
    """
    enriched_data = {}
    base_url = "http://ip-api.com/json/"

    for ip in ip_addresses:
        try:
            response = requests.get(f"{base_url}{ip}")
            data = response.json()
            
            if data["status"] == "fail":
                enriched_data[ip] = {"location": "Unknown"}
            else:
                enriched_data[ip] = {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                }
        except Exception as e:
            enriched_data[ip] = {"location": f"Error: {str(e)}"}
    
    return enriched_data


def load_file(file_path, label):
        """
        Pomocnicza funkcja do ładowania pojedynczego pliku.
        """
        if file_path.endswith('.pcap'):
            # Wczytywanie pliku PCAP za pomocą NFStreamer
            streamer = NFStreamer(source=file_path, statistical_analysis=True)
            data = streamer.to_pandas()
        elif file_path.endswith('.csv'):
            # Wczytywanie pliku CSV
            data = pd.read_csv(file_path)
        else:
            raise ValueError("Nieobsługiwany format pliku. Obsługiwane są tylko PCAP i CSV.")
        
        # Dodanie etykiety
        data['label'] = label
        return data

# Wczytanie modelu oraz listy cech
loaded_data = joblib.load("decision_tree_model.pkl")
model = loaded_data["model"]
feature_names = loaded_data["feature_names"]  # Lista cech, które były użyte podczas trenowania


normal_data = load_file("traffics/normal2_2.pcap", label=0)
malicious_data = load_file("traffics/malicious2_2.pcap", label=1)
combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)
# Wczytanie danych (przypuszczam, że load_traffic_data zwraca surowe dane)
new_data = load_traffic_data("traffics/normal2_2.pcap", "traffics/malicious2_2.pcap")
if new_data is not None:
    # Podział na cechy (X) i etykiety (y)
    y_new = new_data['label']
    X_new = new_data.drop('label', axis=1)

    # Zapewnienie spójności cech
    X_new = X_new.loc[:, X_new.columns.isin(feature_names)]
    for col in feature_names:
        if col not in X_new.columns:
            X_new[col] = 0
    X_new = X_new[feature_names]

    # Predykcja nowego ruchu
    new_predictions = model.predict(X_new)

    # Dodanie predykcji do oryginalnych danych
    combined_data['prediction'] = new_predictions

    # Filtrowanie tylko złośliwego ruchu
    malicious_flows = combined_data[combined_data['prediction'] == 1]
    # print(malicious_flows)
    # print(malicious_flows.columns)

    # Sprawdzenie, czy mamy kolumnę src_ip do analizy
    if 'src_ip' in malicious_flows.columns:
        # Zliczanie unikalnych adresów IP
        ip_counts = malicious_flows['src_ip'].value_counts()

        # Wzbogacanie informacji o adresach IP
        enriched_ips = enrich_ip(ip_counts.index.tolist())


        # Wyświetlenie tabeli wzbogaconej
        enriched_report = pd.DataFrame({
            "IP Address": ip_counts.index,
            "Frequency": ip_counts.values,
            "Country": [enriched_ips[ip].get('country', 'Unknown') for ip in ip_counts.index],
            "Region": [enriched_ips[ip].get('region', 'Unknown') for ip in ip_counts.index],
            "City": [enriched_ips[ip].get('city', 'Unknown') for ip in ip_counts.index],
            "ISP": [enriched_ips[ip].get('isp', 'Unknown') for ip in ip_counts.index],
        })
        print("Raport wzbogaconych IP:")
        print(enriched_report)

        # Generowanie histogramu
        plt.figure(figsize=(10, 6))
        ip_counts.head(10).plot(kind='bar', color='red')
        plt.xlabel("Source IP Addresses")
        plt.ylabel("Frequency")
        plt.title("Top 10 Source IP Addresses in malicious traffic")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.show()
    else:
        print("Kolumna 'src_ip' nie została znaleziona w danych.")

    # Metryki modelu
    accuracy = accuracy_score(y_new, new_predictions)
    conf_matrix = confusion_matrix(y_new, new_predictions)
    print("Dokładność:", accuracy)
    fpr, tpr = calculate_fpr_tpr(conf_matrix)
    print(f"FPR: {fpr:.4f}, TPR: {tpr:.4f}")

    sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.show()