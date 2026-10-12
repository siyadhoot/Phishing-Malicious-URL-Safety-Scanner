# False positive investigation

## Cause and reproduction

The existing histogram-gradient-boosting model uses 16 URL-string counts and flags; its schema has no domain identity. Thus `https://www.wikipedia.com/` and `https://www.wikipedia.org/` have identical feature vectors and scores. Before canonicalization, the shipped model scored `https://www.wikipedia.org` without `/` at phishing probability `0.00326468` (predicted legitimate); adding `/` changed `url_length`, `slash_count`, and `special_char_count`, producing `0.99994588` (predicted phishing). The frontend had used `new URL(candidate).href`, which adds `/` to host-only inputs before submitting them.

There is a matching data collection artifact. After exact URL deduplication, all 31,500 bare-host URLs ending in `/` were labeled phishing. Among 175,357 bare-host rows without `/`, 40,507 were phishing and 134,850 legitimate. These labels make formatting-sensitive counts spuriously predictive.

## Canonicalization and candidate evaluation

`normalize_url` is now shared by inference and training. It lowercases and IDNA-normalizes hostnames, removes a redundant `/` only for the root path, and preserves non-root paths, query strings, and fragments. Training applies it before conflict removal, deduplication, and feature extraction. Inference applies it before feature extraction. Equivalent root URL spellings therefore yield identical feature vectors and model outputs. Regression tests cover Wikipedia with and without `/`, case normalization, query markers, and preservation of non-root paths.

A freshly retrained candidate using this canonicalization was selected on validation phishing F1 and evaluated on a hostname-grouped held-out split. Results:

| Model | Accuracy | Phishing precision | Recall | F1 | ROC-AUC | Legitimate false-positive rate | Confusion matrix `[phishing, legitimate]` |
|---|---:|---:|---:|---:|---:|---:|---|
| Existing reported model | 99.51% | 99.90% | 98.96% | 99.43% | 99.83% | 0.074% (10/13,485) | `[[9945, 105], [10, 13475]]` |
| Canonicalized candidate | 96.60% | 98.03% | 93.90% | 95.92% | 98.65% | 1.402% (189/13,485) | `[[9394, 610], [189, 13296]]` |

The candidate was not promoted because the false-positive rate rose materially. Its report and artifact are retained under [`root_no_slash_candidate/`](root_no_slash_candidate/). An earlier slash-appending candidate is in [`candidate_model_eval/`](candidate_model_eval/); it also had 1.402% FPR and is not used. The currently shipped artifact predates the shared canonicalization and remains in service pending a better candidate. Its score can still be wrong for legitimate sites, and canonicalization does not fix all model false positives.

For the required hand-checked URLs, the currently served model after root canonicalization and the unpromoted candidate produce:

| URL | Served model | Candidate |
|---|---|---|
| `https://www.wikipedia.org` (with or without `/`) | legitimate, phishing score 0.003265 | legitimate, 0.019967 |
| `https://www.wikipedia.com/` | legitimate, 0.003265 | legitimate, 0.019967 |
| `https://www.google.com/` | legitimate, 0.002941 | legitimate, 0.011995 |
| `https://www.microsoft.com/` | legitimate, 0.003265 | legitimate, 0.019967 |
| `https://github.com/` | phishing, 0.999400 | phishing, 0.999816 |

These are diagnostic examples, not domain-specific rules; the model has the same output for `.com` and `.org` Wikipedia spellings because their current feature vectors are identical.

## Binary verdict and estimate

When inference succeeds, `/scan` now returns the model's predicted class (`phishing` or `legitimate`) as the ML verdict. The `example.com` demonstration rule remains a separate `team_rule` override and does not receive model confidence. Invalid input and inference failures remain errors.

The UI displays the predicted-class probability as **Uncalibrated model-estimated confidence**, derived from the probability for the predicted class (using the estimator's class labels). A prior validation-only assessment of the existing artifact recorded a Brier score of 0.00399; that aggregate score did not capture the high-confidence errors on the hand-checked domains. No calibration model was fit for either candidate: the severe format bias and hand-checked errors make calibration on this dataset insufficient evidence of reliable live confidence. Candidate probabilities remain uncalibrated, not confidence guarantees. Near-zero and near-one estimates display as `<0.01%` and `>99.99%`, not misleading 0% or 100%. The page warns that predictions are estimates and not guarantees of safety.

Evaluation uses the local dataset only and makes no network requests. Host grouping removes a leading `www.` but does not guarantee all related registrable domains or subdomains remain together. The reported dataset metrics do not establish real-world threat coverage or reliability.
