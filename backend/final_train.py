
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

from model import extract_feature_dataframe

BASE_DIR = Path(__file__).resolve().parent
DATA_PATH = BASE_DIR.parent / "data" / "phishing_urls.csv"

# Load dataset
df = pd.read_csv(DATA_PATH)
df.columns = df.columns.str.lower()

df = df[["url", "label"]].dropna().copy()
df["url"] = df["url"].astype(str).str.strip()
df = df[df["url"] != ""]

df["label"] = pd.to_numeric(df["label"], errors="coerce")
df = df[df["label"].isin([0, 1])].copy()

# Remove contradictory labels and duplicates
conflicts = df.groupby("url")["label"].nunique()
df = df[~df["url"].isin(conflicts[conflicts > 1].index)]
df = df.drop_duplicates(subset=["url"])

# 1 = phishing, 0 = legitimate
df["target"] = (df["label"] == 0).astype(int)

print("Extracting features...")
X = extract_feature_dataframe(df["url"])
y = df["target"]

print("Training final Random Forest model...")

model = RandomForestClassifier(
    n_estimators=100,
    max_depth=20,
    random_state=42,
    n_jobs=-1
)

model.fit(X, y)

joblib.dump(
    model,
    BASE_DIR / "phishing_model.joblib"
)

print("Final model trained successfully!")
print("Model saved to backend/phishing_model.joblib")
