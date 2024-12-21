import matplotlib.pyplot as plt
from collections import Counter
from datetime import datetime, timedelta
import numpy as np


def generate_plot(data, output_file):
    timestamps = []
    for row in data:
        try:
            timestamp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            timestamp = datetime.strptime(row[0], "%Y-%m-%d %H:%M:%S")
        timestamps.append(timestamp)
    min_time = min(timestamps)
    max_time = max(timestamps)
    time_delta = (max_time - min_time) / 20
    bins = [min_time + i * time_delta for i in range(21)]
    binned_data = np.histogram(timestamps, bins=bins)[0]

    plt.figure(figsize=(10, 6))
    plt.bar(range(len(binned_data)), binned_data, color='skyblue')
    plt.title("Number of detected threats over time")
    plt.xlabel("Time")
    plt.ylabel("Number of detected threats")

    xticks = [min_time + i * time_delta for i in range(21)]
    xticklabels = [timestamp.strftime('%Y-%m-%d %H:%M:%S.%f') for timestamp in xticks]
    plt.xticks(range(len(xticklabels)), xticklabels, rotation=30)
    plt.tight_layout()
    plt.savefig(output_file)
