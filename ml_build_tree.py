import click
import nfstream
from nfstream import NFStreamer
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier, plot_tree
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import joblib

matplotlib.use('TkAgg')

import pandas as pd
import numpy as np
from nfstream import NFStreamer

def load_traffic_data(normal_file, malicious_file):
    """
    Ładuje dane z plików PCAP lub CSV i łączy je w jeden DataFrame.
    
    Args:
        normal_file (str): Ścieżka do pliku z normalnym ruchem (PCAP lub CSV).
        malicious_file (str): Ścieżka do pliku ze złośliwym ruchem (PCAP lub CSV).

    Returns:
        pd.DataFrame: Połączone i przetworzone dane.
    """
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

    try:
        # Wczytanie plików (normalny ruch: label=0, złośliwy ruch: label=1)
        normal_data = load_file(normal_file, label=0)
        malicious_data = load_file(malicious_file, label=1)

        # Połączenie obu zestawów danych
        combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)

        # Usunięcie kolumn z brakującymi wartościami lub jedną unikalną wartością
        for col in combined_data.columns:
            if combined_data[col].nunique() == 1 or combined_data[col].isnull().any():
                combined_data.drop(col, inplace=True, axis=1)

        # Wybór tylko kolumn numerycznych
        combined_data = combined_data.select_dtypes(include=[np.number])

        return combined_data

    except Exception as e:
        print(f"Błąd podczas wczytywania danych: {e}")
        return None


# Funkcja trenowania i oceny modelu
def train_and_evaluate_decision_tree(X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
    tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
    tree_model.fit(X_train, y_train)
    predictions = tree_model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    # Wizualizacja drzewa
    plt.figure(figsize=(20, 10))
    plot_tree(tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
    plt.title("Decision tree visualization")
    plt.show()

    return tree_model, accuracy, conf_matrix

# Funkcja obliczania FPR i TPR
def calculate_fpr_tpr(conf_matrix):
    TN, FP, FN, TP = conf_matrix.ravel()
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    return FPR, TPR


# Główna część programu z nową komendą CLI
@click.group()
def cli():
    """
    Narzędzie do trenowania modelu ML na danych z plików PCAP oraz nowych danych CSV.
    """

@click.command()
@click.argument("normal", type=click.Path(exists=True))
@click.argument("malicious", type=click.Path(exists=True))
@click.option("--max_depth", type=int, default=None, help="Maksymalna głębokość drzewa decyzyjnego.")
@click.option("--criterion", type=click.Choice(['gini', 'entropy'], case_sensitive=False), default='gini', help="Kryterium podziału w drzewie decyzyjnym.")
def train_model(normal, malicious, max_depth, criterion):
    """
    Trenowanie modelu ML na danych z plików PCAP lub CSV.
    """
    # Wczytanie danych za pomocą nowej funkcji
    data = load_traffic_data(normal, malicious)

    if data is not None:
        # Przygotowanie danych do modelowania
        X = data.drop('label', axis=1)
        y = data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Trenowanie i ocena modelu
        model, accuracy, conf_matrix = train_and_evaluate_decision_tree(
            X_train, y_train, X_test, y_test, max_depth=max_depth, criterion=criterion
        )

        print("Model accuracy:", accuracy)
        sns.heatmap(conf_matrix, annot=True, fmt="d", cmap="Blues",
                    xticklabels=["Predicted Positive", "Predicted Negative"],
                    yticklabels=["Actual Positive", "Actual Negative"])
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.title("Confusion matrix")
        plt.show()

        # Obliczanie FPR i TPR
        fpr, tpr = calculate_fpr_tpr(conf_matrix)
        print(f"False Positive Rate (FPR): {fpr:.4f}")
        print(f"True Positive Rate (TPR): {tpr:.4f}")

        # Zapisanie modelu do pliku
        joblib.dump({"model": model, "feature_names": X_train.columns.tolist()}, "decision_tree_model.pkl")
        print("Model zapisano jako 'decision_tree_model.pkl' wraz z listą cech.")
    else:
        print("Nie udało się wczytać danych.")

# Dodanie nowej komendy do CLI
cli.add_command(train_model)


if __name__ == "__main__":
    cli()
