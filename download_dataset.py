from ucimlrepo import fetch_ucirepo
import pandas as pd
import os

print("Downloading dataset...")

dataset = fetch_ucirepo(id=967)

df = pd.concat(
    [dataset.data.features, dataset.data.targets],
    axis=1
)

os.makedirs("data", exist_ok=True)

df.to_csv("data/phishing_urls.csv", index=False)

print("Dataset downloaded successfully!")
print("Dataset shape:", df.shape)