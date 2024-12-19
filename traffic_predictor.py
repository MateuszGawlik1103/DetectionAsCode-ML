import argparse
import joblib
import nfstream
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import accuracy_score, confusion_matrix
from matplotlib.backends.backend_pdf import PdfPages
from ipaddress import ip_address
import requests
import folium
from ml_build_tree import calculate_fpr_tpr, load_traffic_data, load_file


def classify_ip(ip):
    try:
        ip_obj = ip_address(ip)
        return 'Internal' if ip_obj.is_private else 'External'
    except ValueError:
        return 'Invalid'


def enrich_ip(ip_addresses):
    enriched_data = {}
    base_url = "http://ip-api.com/json/"
    for ip in ip_addresses:
        try:
            ip_type = classify_ip(ip)
            response = requests.get(f"{base_url}{ip}", timeout=5)
            data = response.json()
            if data.get("status") == "fail":
                enriched_data[ip] = {
                    "country": "Unknown", "region": "Unknown", "city": "Unknown",
                    "isp": "Unknown", "lat": 0, "lon": 0, "location": "Unknown",
                    "type": ip_type,
                }
            else:
                enriched_data[ip] = {
                    "country": data.get("country", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                    "location": "Known",
                    "type": ip_type,
                }
        except Exception as e:
            enriched_data[ip] = {
                "country": "Unknown", "region": "Unknown", "city": "Unknown",
                "isp": "Unknown", "lat": 0, "lon": 0, "location": f"Error: {str(e)}",
                "type": "Unknown",
            }
    return enriched_data


def create_map(enriched_ips):
    ip_map = folium.Map(location=[0, 0], zoom_start=2)
    for ip, info in enriched_ips.items():
        if info.get("location") == "Known":
            folium.Marker(
                location=[info.get("lat", 0), info.get("lon", 0)],
                popup=(
                    f"IP: {ip}<br>"
                    f"Type: {info.get('type', 'Unknown')}<br>"
                    f"Country: {info.get('country', 'Unknown')}<br>"
                    f"City: {info.get('city', 'Unknown')}"
                ),
                icon=folium.Icon(color="red" if info.get('type') == 'External' else 'blue')
            ).add_to(ip_map)
    return ip_map




def test_model(malicious_traffic, normal_traffic):
    loaded_data = joblib.load("decision_tree_model.pkl")
    model = loaded_data["model"]
    feature_names = loaded_data["feature_names"]

    normal_data = load_file(normal_traffic, label=0)
    malicious_data = load_file(malicious_traffic, label=1)
    combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)

    X_new = combined_data.drop('label', axis=1)
    X_new = X_new.loc[:, X_new.columns.isin(feature_names)]
    for col in feature_names:
        if col not in X_new.columns:
            X_new[col] = 0
    X_new = X_new[feature_names]
    y_new = combined_data['label']

    predictions = model.predict(X_new)
    accuracy = accuracy_score(y_new, predictions)
    conf_matrix = confusion_matrix(y_new, predictions)
    fpr, tpr = calculate_fpr_tpr(conf_matrix)

    print("Confusion Matrix:\n", conf_matrix)
    print(f"Accuracy: {accuracy:.4f}")
    print(f"FPR: {fpr:.4f}, TPR: {tpr:.4f}")

    sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues")
    plt.xlabel("Predicted")
    plt.ylabel("Actual")
    plt.title("Confusion Matrix")
    plt.show()


def generate_report(file_path):
    loaded_data = joblib.load("decision_tree_model.pkl")
    model = loaded_data["model"]
    feature_names = loaded_data["feature_names"]

    data = load_file(file_path, label=None)
    X_new = data.loc[:, data.columns.isin(feature_names)]
    for col in feature_names:
        if col not in X_new.columns:
            X_new[col] = 0
    X_new = X_new[feature_names]

    predictions = model.predict(X_new)
    data['prediction'] = predictions
    malicious_flows = data[data['prediction'] == 1]

    if 'src_ip' in malicious_flows.columns:
        ip_counts = malicious_flows['src_ip'].value_counts()
        enriched_ips = enrich_ip(ip_counts.index.tolist())

        enriched_report = pd.DataFrame({
            "IP Address": ip_counts.index,
            "Frequency": ip_counts.values,
            "Country": [enriched_ips[ip].get('country', 'Unknown') for ip in ip_counts.index],
            "Region": [enriched_ips[ip].get('region', 'Unknown') for ip in ip_counts.index],
            "City": [enriched_ips[ip].get('city', 'Unknown') for ip in ip_counts.index],
            "ISP": [enriched_ips[ip].get('isp', 'Unknown') for ip in ip_counts.index],
            "Type": [enriched_ips[ip].get('type', 'Unknown') for ip in ip_counts.index],
        })

        # Histogram generation
        plt.figure(figsize=(10, 6))
        ip_counts.head(10).plot(kind='bar', color='red')
        plt.xlabel("Source IP Addresses")
        plt.ylabel("Frequency")
        plt.title("Top 10 Source IP Addresses in malicious traffic")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig("top_ips_histogram.png")
        plt.close()

        # Map creation
        ip_map = create_map(enriched_ips)
        map_file = "malicious_ips_map.html"
        ip_map.save(map_file)

        # Report HTML generation
        report_file = "report.html"
        with open(report_file, "w") as report:
            report.write("<html><head><title>Malicious Traffic Report</title></head><body>")
            report.write("<h1>Malicious Traffic Report</h1>")
            report.write("<h2>Top Source IPs Histogram</h2>")
            report.write('<img src="top_ips_histogram.png" alt="Top IPs Histogram"><br><br>')
            report.write("<h2>Detailed IP Report</h2>")
            report.write(f"<pre>{enriched_report.to_string()}</pre><br>")
            report.write(f'<h2>Geographical Map</h2><a href="{map_file}">Open Map</a>')
            report.write("</body></html>")

        print(f"Report saved as {report_file}.")
        print(f"Map saved as {map_file}.")
    else:
        print("No 'src_ip' column found in data.")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyze traffic data.")
    subparsers = parser.add_subparsers(dest="command")

    test_parser = subparsers.add_parser("test", help="Test the model with malicious and normal traffic.")
    test_parser.add_argument("--malicious_traffic", required=True, help="Path to malicious traffic PCAP file.")
    test_parser.add_argument("--normal_traffic", required=True, help="Path to normal traffic PCAP file.")

    report_parser = subparsers.add_parser("report", help="Generate a report for a single traffic file.")
    report_parser.add_argument("--file", required=True, help="Path to the traffic file.")

    args = parser.parse_args()

    if args.command == "test":
        test_model(args.malicious_traffic, args.normal_traffic)
    elif args.command == "report":
        generate_report(args.file)
