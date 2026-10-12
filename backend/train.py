
import pandas as pd
import joblib
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

from model import extract_feature_dataframe


# STEP 1: Load dataset

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR.parent / "data" / "phishing_urls.csv"

df = pd.read_csv(DATA_PATH)

print("Original Dataset Shape:", df.shape)
print("Columns:", df.columns.tolist())


# STEP 2: Clean dataset

df.columns = df.columns.str.lower()

df = df[["url", "label"]].copy()

df.dropna(inplace=True)
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""]

df["label"] = pd.to_numeric(
    df["label"], errors="coerce"
)
df = df[df["label"].isin([0, 1])].copy()

# Remove URLs with conflicting labels
conflicts = df.groupby("url")["label"].nunique()
conflicting_urls = conflicts[conflicts > 1].index
df = df[~df["url"].isin(conflicting_urls)]

df.drop_duplicates(subset=["url"], inplace=True)

# Original dataset: 0 = phishing, 1 = legitimate
# Our model: 1 = phishing, 0 = legitimate
df["target"] = (df["label"] == 0).astype(int)

print("\nCleaned Dataset Shape:", df.shape)
print("\nClass Distribution:")
print(df["target"].value_counts())


# STEP 3: Split dataset

X_train_urls, X_test_urls, y_train, y_test = train_test_split(
    df["url"],
    df["target"],
    test_size=0.2,
    random_state=42,
    stratify=df["target"]
)


# STEP 4: Extract features

print("\nExtracting URL features...")

X_train = extract_feature_dataframe(X_train_urls)
X_test = extract_feature_dataframe(X_test_urls)

print("Feature extraction completed!")
print("Training samples:", len(X_train))
print("Testing samples:", len(X_test))


# STEP 5: Define ML models

models = {
    "Logistic Regression": make_pipeline(
        StandardScaler(),
        LogisticRegression(max_iter=1000, random_state=42)
    ),

    "Decision Tree": DecisionTreeClassifier(
        max_depth=15,
        random_state=42
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        random_state=42,
        n_jobs=-1
    )
}


# STEP 6: Train and evaluate models

results = []
trained_models = {}

for name, model in models.items():

    print("\n-----------------------------")
    print("Training:", name)
    print("-----------------------------")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(y_test, predictions, zero_division=0)
    recall = recall_score(y_test, predictions, zero_division=0)
    f1 = f1_score(y_test, predictions, zero_division=0)

    results.append({
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1
    })

    trained_models[name] = model

    print("\nClassification Report:")
    print(classification_report(
        y_test,
        predictions,
        target_names=["Legitimate", "Phishing"],
        zero_division=0
    ))

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, predictions))


# STEP 7: Compare all models

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by="F1 Score",
    ascending=False
)

print("\nFINAL MODEL COMPARISON:")
print(results_df.to_string(index=False))


# STEP 8: Save evaluation results

results_df.to_csv(
    BASE_DIR / "model_results.csv",
    index=False
)


# STEP 9: Save best model

best_model_name = results_df.iloc[0]["Model"]
best_model = trained_models[best_model_name]

joblib.dump(
    best_model,
    BASE_DIR / "phishing_model.joblib"
)

print("\nBest Model:", best_model_name)
print("Model saved successfully!")
print("Results saved successfully!")
