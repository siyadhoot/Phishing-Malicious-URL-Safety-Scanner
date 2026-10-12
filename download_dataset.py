"""Download the documented PhiUSIIL dataset from UCI (dataset id 967)."""

from pathlib import Path

import pandas as pd
from ucimlrepo import fetch_ucirepo


ROOT = Path(__file__).resolve().parent
OUTPUT_PATH = ROOT / "data" / "phishing_urls.csv"


def main():
    print("Downloading PhiUSIIL Phishing URL (Website) from UCI...")
    dataset = fetch_ucirepo(id=967)
    features = dataset.data.features
    targets = dataset.data.targets
    if "URL" not in features.columns or "label" not in targets.columns:
        raise ValueError(
            "UCI dataset schema changed: expected feature `URL` and target `label`."
        )
    frame = pd.concat([features, targets], axis=1)
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(OUTPUT_PATH, index=False)
    print(f"Saved {len(frame):,} rows and {len(frame.columns)} columns to {OUTPUT_PATH}")
    print("Verified UCI label mapping: 0 = phishing; 1 = legitimate.")


if __name__ == "__main__":
    main()
