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
import pandas as pd
import numpy as np
from nfstream import NFStreamer

matplotlib.use('TkAgg')



def load_file(file_path, label):
    """
    Helper function to load a single file (PCAP or CSV).
    
    Args:
        file_path (str): Path to the file to be loaded.
        label (int): The label for the data (0 for normal, 1 for malicious).
        
    Returns:
        pd.DataFrame: Data loaded into a pandas DataFrame.
    """
    if file_path.endswith('.pcap'):
        # Load the PCAP file using NFStreamer
        streamer = NFStreamer(source=file_path, statistical_analysis=True)
        data = streamer.to_pandas()
    elif file_path.endswith('.csv'):
        # Load the CSV file
        data = pd.read_csv(file_path)
    else:
        raise ValueError("Unsupported file format. Only PCAP and CSV files are supported.")
    
    # Add label column
    data['label'] = label
    return data

def load_traffic_data(normal_file, malicious_file):
    """
    Load and combine normal and malicious traffic data, preprocessing it for training.

    Args:
        normal_file (str): Path to the normal traffic file.
        malicious_file (str): Path to the malicious traffic file.

    Returns:
        pd.DataFrame: Combined and preprocessed data.
    """
    try:
        # Load normal and malicious data (normal traffic: label=0, malicious traffic: label=1)
        normal_data = load_file(normal_file, label=0)
        malicious_data = load_file(malicious_file, label=1)

        # Combine the datasets
        combined_data = pd.concat([normal_data, malicious_data], ignore_index=True)

        # Remove columns with missing values or only one unique value
        for col in combined_data.columns:
            if combined_data[col].nunique() == 1 or combined_data[col].isnull().any():
                combined_data.drop(col, inplace=True, axis=1)

        # Select only numeric columns for training
        combined_data = combined_data.select_dtypes(include=[np.number])

        return combined_data

    except Exception as e:
        print(f"Error loading data: {e}")
        return None


# Function for training and evaluating the decision tree model
def train_and_evaluate_decision_tree(X_train, y_train, X_test, y_test, max_depth=None, criterion='gini'):
    """
    Train and evaluate the decision tree classifier.

    Args:
        X_train (pd.DataFrame): Training features.
        y_train (pd.Series): Training labels.
        X_test (pd.DataFrame): Test features.
        y_test (pd.Series): Test labels.
        max_depth (int, optional): The maximum depth of the tree. Defaults to None.
        criterion (str, optional): The criterion for splitting nodes. Defaults to 'gini'.

    Returns:
        tuple: Trained model, accuracy, confusion matrix.
    """
    tree_model = DecisionTreeClassifier(max_depth=max_depth, criterion=criterion, random_state=42)
    tree_model.fit(X_train, y_train)
    predictions = tree_model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    conf_matrix = confusion_matrix(y_test, predictions)

    # Visualize the decision tree
    plt.figure(figsize=(20, 10))
    plot_tree(tree_model, filled=True, feature_names=X_train.columns, class_names=['Normal', 'Malicious'], fontsize=10)
    plt.title("Decision tree visualization")
    plt.show()

    return tree_model, accuracy, conf_matrix

# Function to calculate False Positive Rate (FPR) and True Positive Rate (TPR)
def calculate_fpr_tpr(conf_matrix):
    """
    Calculate False Positive Rate (FPR) and True Positive Rate (TPR) from the confusion matrix.

    Args:
        conf_matrix (np.ndarray): Confusion matrix.

    Returns:
        tuple: FPR and TPR values.
    """
    TN, FP, FN, TP = conf_matrix.ravel()
    FPR = FP / (FP + TN) if (FP + TN) > 0 else 0
    TPR = TP / (TP + FN) if (TP + FN) > 0 else 0
    return FPR, TPR


# Main program entry point with CLI commands
@click.group()
def cli():
    """
    Tool for training ML models on PCAP and CSV traffic data files.
    """

@click.command()
@click.argument("normal", type=click.Path(exists=True))
@click.argument("malicious", type=click.Path(exists=True))
@click.option("--max_depth", type=int, default=None, help="Maximum depth of the decision tree.")
@click.option("--criterion", type=click.Choice(['gini', 'entropy'], case_sensitive=False), default='gini', help="Criterion for splitting nodes in the decision tree.")
def train_model(normal, malicious, max_depth, criterion):
    """
    Train the machine learning model on PCAP or CSV traffic data files.
    
    Args:
        normal (str): Path to the normal traffic file.
        malicious (str): Path to the malicious traffic file.
        max_depth (int): Maximum depth for the decision tree model.
        criterion (str): Criterion for the decision tree split ('gini' or 'entropy').
    """
    # Load data using the provided function
    data = load_traffic_data(normal, malicious)

    if data is not None:
        # Prepare data for modeling
        X = data.drop('label', axis=1)
        y = data['label']
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

        # Train and evaluate the decision tree model
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

        # Calculate FPR and TPR
        fpr, tpr = calculate_fpr_tpr(conf_matrix)
        print(f"False Positive Rate (FPR): {fpr:.4f}")
        print(f"True Positive Rate (TPR): {tpr:.4f}")

        # Save the trained model to a file
        joblib.dump({"model": model, "feature_names": X_train.columns.tolist()}, "decision_tree_model.pkl")
        print("Model saved as 'decision_tree_model.pkl' along with the feature names.")
    else:
        print("Failed to load data.")

# Add the new CLI command to the CLI group
cli.add_command(train_model)


if __name__ == "__main__":
    cli()
