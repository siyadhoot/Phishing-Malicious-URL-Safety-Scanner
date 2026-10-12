"""Train and evaluate the URL-only PhiUSIIL phishing classifier.

Run from the repository root: ``python -m backend.train``.
"""

import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.dummy import DummyClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from backend.model import (
    ARTIFACT_VERSION,
    FEATURE_COLUMNS,
    LABEL_MAPPING,
    extract_feature_dataframe,
)
from backend.security import normalize_url, validate_url


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_PATH = ROOT / "data" / "phishing_urls.csv"
# Training writes to an isolated candidate directory by default. A candidate
# must be evaluated before anyone deliberately replaces the serving artifact.
OUTPUT_DIR = Path(__file__).resolve().parent / "candidate_model_output"
RANDOM_STATE = 42


def clean_dataset(path):
    """Load the documented UCI schema and return clean URL/label rows + counts."""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(
            f"Dataset not found: {path}. Run `python download_dataset.py` first."
        )
    frame = pd.read_csv(path)
    if not {"URL", "label"}.issubset(frame.columns):
        raise ValueError("Dataset must contain the exact UCI columns `URL` and `label`.")

    stats = {"rows_loaded": int(len(frame))}
    stats["exact_duplicate_rows_removed"] = int(frame.duplicated().sum())
    frame = frame.drop_duplicates().copy()

    frame["URL"] = frame["URL"].astype("string").str.strip()
    frame["label"] = pd.to_numeric(frame["label"], errors="coerce")
    missing_or_blank = frame["URL"].isna() | frame["URL"].eq("") | frame["label"].isna()
    stats["missing_or_blank_rows_removed"] = int(missing_or_blank.sum())
    frame = frame.loc[~missing_or_blank].copy()

    known_label = frame["label"].isin([0, 1])
    stats["invalid_label_rows_removed"] = int((~known_label).sum())
    frame = frame.loc[known_label, ["URL", "label"]].copy()
    frame["label"] = frame["label"].astype("int8")

    valid_rows = frame["URL"].map(lambda value: validate_url(value)[0])
    stats["invalid_url_rows_removed"] = int((~valid_rows).sum())
    frame = frame.loc[valid_rows].copy()

    # Use the same root-path canonicalization as inference before conflict checks,
    # deduplication, splitting, or feature extraction.
    frame["URL"] = frame["URL"].map(normalize_url)

    conflict_counts = frame.groupby("URL", sort=False)["label"].nunique()
    conflict_urls = set(conflict_counts[conflict_counts > 1].index)
    stats["conflicting_urls_removed"] = len(conflict_urls)
    frame = frame.loc[~frame["URL"].isin(conflict_urls)].copy()

    stats["repeated_same_label_urls_removed"] = int(frame["URL"].duplicated().sum())
    frame = frame.drop_duplicates(subset=["URL"], keep="first").reset_index(drop=True)
    stats["rows_retained"] = int(len(frame))
    stats["label_counts"] = {
        str(int(label)): int(count)
        for label, count in frame["label"].value_counts().sort_index().items()
    }
    if frame.empty or frame["label"].nunique() != 2:
        raise ValueError("Cleaned dataset must contain both documented classes 0 and 1.")
    return frame, stats


def host_group(url):
    """Group apex and www URLs together, without consulting external DNS/PSL data."""
    candidate = url if "://" in url else "http://" + url
    hostname = (urlsplit(candidate).hostname or "").lower().rstrip(".")
    try:
        hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    while hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname


def grouped_stratified_splits(urls, labels, random_state=RANDOM_STATE):
    """Return deterministic 80/10/10 host-grouped, approximately stratified indices."""
    urls = np.asarray(urls, dtype=object)
    labels = np.asarray(labels, dtype=np.int8)
    groups = np.asarray([host_group(url) for url in urls], dtype=object)
    if np.any(groups == ""):
        raise ValueError("Cannot group a URL without a hostname.")

    outer = StratifiedGroupKFold(n_splits=10, shuffle=True, random_state=random_state)
    train_validation, test = next(outer.split(urls, labels, groups))
    inner = StratifiedGroupKFold(n_splits=9, shuffle=True, random_state=random_state + 1)
    inner_train, validation = next(inner.split(
        urls[train_validation], labels[train_validation], groups[train_validation]
    ))
    train = train_validation[inner_train]
    validation = train_validation[validation]

    sets = [set(groups[index]) for index in (train, validation, test)]
    if any(sets[left] & sets[right] for left, right in ((0, 1), (0, 2), (1, 2))):
        raise RuntimeError("Host groups leaked between data splits.")
    return train, validation, test


def make_candidates():
    """Return comparable baselines; all preprocessing is fitted within each model."""
    return {
        "Prior baseline": DummyClassifier(strategy="prior"),
        "Logistic regression": make_pipeline(
            StandardScaler(),
            LogisticRegression(max_iter=700, random_state=RANDOM_STATE),
        ),
        "Histogram gradient boosting": HistGradientBoostingClassifier(
            max_iter=120,
            learning_rate=0.08,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            random_state=RANDOM_STATE,
        ),
    }


def evaluate(estimator, features, labels):
    """Evaluate phishing as the positive class; source label 0 means phishing."""
    predicted_labels = estimator.predict(features)
    actual_phishing = (np.asarray(labels) == 0).astype(np.int8)
    predicted_phishing = (np.asarray(predicted_labels) == 0).astype(np.int8)
    probability = estimator.predict_proba(features)[:, list(estimator.classes_).index(0)]
    matrix = confusion_matrix(actual_phishing, predicted_phishing, labels=[1, 0])
    legitimate_total = int(matrix[1].sum())
    return {
        "accuracy": float(accuracy_score(actual_phishing, predicted_phishing)),
        "precision": float(precision_score(actual_phishing, predicted_phishing, zero_division=0)),
        "recall": float(recall_score(actual_phishing, predicted_phishing, zero_division=0)),
        "f1": float(f1_score(actual_phishing, predicted_phishing, zero_division=0)),
        "roc_auc": float(roc_auc_score(actual_phishing, probability)),
        "false_positive_rate": (
            float(matrix[1, 0] / legitimate_total) if legitimate_total else 0.0
        ),
        "confusion_matrix_phishing_then_legitimate": matrix.tolist(),
        "confusion_matrix_order": ["phishing", "legitimate"],
    }


def _write_json(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def train(data_path=DEFAULT_DATA_PATH, output_dir=OUTPUT_DIR):
    data_path = Path(data_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    dataset, cleaning = clean_dataset(data_path)
    print(f"Rows loaded: {cleaning['rows_loaded']}")
    print(f"Exact duplicate rows removed: {cleaning['exact_duplicate_rows_removed']}")
    print(f"Conflicting URLs removed: {cleaning['conflicting_urls_removed']}")
    print(f"Invalid URLs removed: {cleaning['invalid_url_rows_removed']}")
    print(f"Rows retained: {cleaning['rows_retained']}")

    print("Extracting URL-only feature matrix...")
    features = extract_feature_dataframe(dataset["URL"])
    labels = dataset["label"].to_numpy(dtype=np.int8)
    if list(features.columns) != FEATURE_COLUMNS:
        raise RuntimeError("Training feature order differs from inference schema.")

    train_index, validation_index, test_index = grouped_stratified_splits(
        dataset["URL"].to_numpy(), labels
    )
    split_sizes = {
        "train": int(len(train_index)),
        "validation": int(len(validation_index)),
        "test": int(len(test_index)),
    }
    print("Host-grouped split sizes:", split_sizes)

    validation_rows = []
    trained = {}
    for name, candidate in make_candidates().items():
        print(f"Training validation candidate: {name}", flush=True)
        candidate.fit(features.iloc[train_index], labels[train_index])
        metrics = evaluate(candidate, features.iloc[validation_index], labels[validation_index])
        validation_rows.append({"stage": "validation", "model": name, **metrics})
        trained[name] = candidate
        print(
            f"  phishing precision={metrics['precision']:.4f} "
            f"recall={metrics['recall']:.4f} F1={metrics['f1']:.4f} "
            f"ROC-AUC={metrics['roc_auc']:.4f}"
        )

    validation_by_name = {row["model"]: row for row in validation_rows}
    selected_name = max(
        trained,
        key=lambda name: (
            validation_by_name[name]["f1"],
            validation_by_name[name]["precision"],
            name,
        ),
    )
    selected = make_candidates()[selected_name]
    train_validation_index = np.concatenate((train_index, validation_index))
    selected.fit(features.iloc[train_validation_index], labels[train_validation_index])
    test_metrics = evaluate(selected, features.iloc[test_index], labels[test_index])
    print(f"Selected model: {selected_name} (validation phishing F1)")
    print("Held-out host test metrics:", json.dumps(test_metrics, sort_keys=True))

    comparison = pd.DataFrame(validation_rows)
    comparison.to_csv(output_dir / "model_results.csv", index=False)

    data_hash = hashlib.sha256(data_path.read_bytes()).hexdigest()
    report = {
        "dataset": str(data_path.name),
        "dataset_sha256": data_hash,
        "rows": cleaning["rows_retained"],
        "cleaning": cleaning,
        "split_method": (
            "StratifiedGroupKFold: 10 outer folds for test, then 9 folds within "
            "the remainder for validation; exact hostname groups (www prefix removed) "
            "do not cross splits. Ratios are approximately 80/10/10."
        ),
        "split_sizes": split_sizes,
        "random_state": RANDOM_STATE,
        "feature_columns": FEATURE_COLUMNS,
        "label_mapping": {"0": "phishing", "1": "legitimate"},
        "selection_metric": "validation phishing-class F1; precision then model name break ties",
        "validation_candidates": validation_rows,
        "selected_model": selected_name,
        "held_out_test": test_metrics,
        "scikit_learn_version": sklearn.__version__,
        "limitation": (
            "Features are computed from URL strings only. URL-only performance on this "
            "dataset does not establish real-world reliability or current threat coverage."
        ),
    }
    _write_json(output_dir / "model_evaluation.json", report)

    artifact = {
        "artifact_version": ARTIFACT_VERSION,
        "estimator": selected,
        "feature_columns": FEATURE_COLUMNS,
        "label_mapping": {"0": "phishing", "1": "legitimate"},
        "scikit_learn_version": sklearn.__version__,
        "training_report": report,
    }
    temporary_path = output_dir / "phishing_model.joblib.tmp"
    joblib.dump(artifact, temporary_path, compress=3)
    temporary_path.replace(output_dir / "phishing_model.joblib")
    print(f"Saved evaluated model bundle: {output_dir / 'phishing_model.joblib'}")
    print(f"Saved report: {output_dir / 'model_evaluation.json'}")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA_PATH)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT_DIR)
    arguments = parser.parse_args()
    train(arguments.data, arguments.output_dir)


if __name__ == "__main__":
    main()
