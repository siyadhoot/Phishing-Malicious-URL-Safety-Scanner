import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator

from backend.train import clean_dataset, evaluate, grouped_stratified_splits, host_group


def test_dataset_cleaning_drops_exact_duplicates_conflicts_and_bad_urls(tmp_path):
    rows = [
        {"URL": "https://good.example/", "label": 1, "unused": "same"},
        {"URL": "https://good.example/", "label": 1, "unused": "same"},
        {"URL": "https://conflict.example/", "label": 0, "unused": "a"},
        {"URL": "https://conflict.example/", "label": 1, "unused": "b"},
        {"URL": "javascript:alert(1)", "label": 0, "unused": "bad"},
        {"URL": "https://phish.example/login", "label": 0, "unused": "ok"},
    ]
    path = tmp_path / "sample.csv"
    pd.DataFrame(rows).to_csv(path, index=False)

    clean, stats = clean_dataset(path)
    assert clean[["URL", "label"]].to_dict("records") == [
        {"URL": "https://good.example", "label": 1},
        {"URL": "https://phish.example/login", "label": 0},
    ]
    assert stats["exact_duplicate_rows_removed"] == 1
    assert stats["conflicting_urls_removed"] == 1
    assert stats["invalid_url_rows_removed"] == 1
    assert stats["rows_retained"] == 2


def test_training_canonicalizes_equivalent_root_url_spellings_before_conflicts(tmp_path):
    rows = [
        {"URL": "https://EXAMPLE.org", "label": 1},
        {"URL": "https://example.org/", "label": 1},
        {"URL": "https://example.org/path/", "label": 0},
    ]
    path = tmp_path / "root_urls.csv"
    pd.DataFrame(rows).to_csv(path, index=False)
    clean, _ = clean_dataset(path)
    assert clean["URL"].tolist() == ["https://example.org", "https://example.org/path/"]


def test_training_requires_actual_uci_column_names(tmp_path):
    path = tmp_path / "wrong_schema.csv"
    pd.DataFrame({"url": ["https://example.com"], "label": [1]}).to_csv(path, index=False)
    try:
        clean_dataset(path)
    except ValueError as error:
        assert "URL" in str(error)
    else:
        raise AssertionError("lowercase url must not be silently treated as the UCI schema")


def test_grouped_stratified_splits_keep_host_groups_disjoint():
    urls = []
    labels = []
    for index in range(100):
        root = f"site{index}.example"
        urls.extend([f"https://{root}/", f"https://www.{root}/path"])
        labels.extend([index % 2, index % 2])

    train, validation, test = grouped_stratified_splits(urls, labels)
    host_sets = [
        {host_group(urls[index]) for index in indices}
        for indices in (train, validation, test)
    ]
    assert not (host_sets[0] & host_sets[1])
    assert not (host_sets[0] & host_sets[2])
    assert not (host_sets[1] & host_sets[2])
    assert sum(map(len, (train, validation, test))) == len(urls)
    assert all(0.05 < len(indices) / len(urls) < 0.85
               for indices in (train, validation, test))


def test_evaluation_reports_phishing_false_positive_rate():
    class FixedEstimator(BaseEstimator):
        classes_ = np.array([0, 1])

        def predict(self, features):
            return np.array([0, 1, 0, 1])

        def predict_proba(self, features):
            return np.array([[0.9, 0.1], [0.2, 0.8], [0.8, 0.2], [0.1, 0.9]])

    metrics = evaluate(FixedEstimator(), pd.DataFrame({"feature": [1, 2, 3, 4]}), [0, 0, 1, 1])
    assert metrics["confusion_matrix_phishing_then_legitimate"] == [[1, 1], [1, 1]]
    assert metrics["false_positive_rate"] == 0.5
