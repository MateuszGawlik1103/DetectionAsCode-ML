import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime


def generate_plot(data, output_file):
    timestamps = []
    for row in data:
        timestamp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S").strftime('%Y-%m-%d %H:%M:%S')
        timestamps.append(timestamp)

    time_counts = Counter(timestamps)
    times = list(time_counts.keys())
    counts = list(time_counts.values())

    plt.figure(figsize=(10, 6))
    plt.bar(times, counts, color='skyblue')
    plt.title("Number of detected threats over time")
    plt.xlabel("Time")
    plt.ylabel("Number of detected threats")
    plt.xticks(rotation=30)
    plt.tight_layout()
    plt.savefig(output_file)
