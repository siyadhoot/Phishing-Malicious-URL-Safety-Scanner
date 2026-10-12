# Phishing URL Safety Scanner

The service analyzes URL strings only. It never opens or fetches a submitted address. Flask serves the API and static frontend from `http://127.0.0.1:5000/` locally.

## Dataset and model

Training uses the UCI PhiUSIIL `URL` and `label` fields. Label `0` is phishing and label `1` is legitimate. The model uses these 16 URL-only features in order: `url_length`, `hostname_length`, `dot_count`, `hyphen_count`, `at_count`, `question_count`, `equal_count`, `slash_count`, `digit_count`, `special_char_count`, `has_ip_address`, `has_https`, `subdomain_count`, `suspicious_word_count`, `has_punycode`, `has_encoded_chars`.

On the checked-in CSV, the existing artifact's original training report retained 235,352 of 235,795 rows. Its seeded, hostname-grouped split had 188,282 training, 23,535 validation, and 23,535 test rows. Histogram gradient boosting was selected using validation phishing F1. Held-out metrics were precision 0.9990, recall 0.9896, F1 0.9943, ROC-AUC 0.9983, accuracy 0.9951; confusion matrix order `[phishing, legitimate]`: `[[9945, 105], [10, 13475]]`. These are dataset measurements, not real-world reliability claims. The current serving estimator, after root canonicalization, classifies the tested Wikipedia.org, Wikipedia.com, Google, and Microsoft URLs as legitimate but still classifies GitHub as phishing. Identical feature representations necessarily produce identical scores; these outputs are not hardcoded domain exceptions. See `FALSE_POSITIVE_ANALYSIS.md` for exact scores and canonicalized candidate results.

The service returns the model's predicted class as a binary ML verdict after successful inference. This is an operational classification, not a guarantee that the URL is safe or harmful. The model's class probabilities are uncalibrated; `confidence` is the raw probability associated with the predicted class, labeled in the UI as an uncalibrated model-estimated confidence. A validation-only review of the previous model reported Brier score 0.00399 and 0.199% error among scores of 0.99 or higher, but hand-checked legitimate sites also received extreme phishing scores. Treat displayed values as model outputs, not calibrated odds. The UI avoids rounding near-extreme values to 0% or 100% and warns that the scanner can make mistakes.

Training, the public feature-extraction helper, and inference all call `normalize_url` before extracting features. Host case and IDNA spelling are canonicalized; a redundant slash on the root path is removed, while non-root paths and query/fragment data are retained. This prevents a host-only URL and its root-slash equivalent from producing different count features. The currently shipped estimator predates canonicalized training; its inference inputs are now normalized. A retrained canonicalized candidate was evaluated but not promoted because its grouped-test performance was materially worse. See `FALSE_POSITIVE_ANALYSIS.md` for the comparison and limitations.

## Demonstration policy

The application policy defaults to `example.com` and its subdomains. It uses parsed hostname equality or a dot-boundary suffix, not substring matching. `DEMO_PHISHING_DOMAINS` accepts comma-separated domains; set it to an empty value to disable the rule. The model runs before the rule is applied. A policy match returns `verdict_source: "team_rule"`, a phishing application verdict, the unchanged raw model result, and a rule explanation. It does not add confidence for the policy or enter ML training/evaluation. `example.com` is reserved for documentation and is not inherently malicious; this remains an explicit demo behavior.

## API

### `GET /health`

Returns HTTP 200 while the process is serving.

### `POST /scan`

Send `{"url":"example.org/path"}` or a full `http://` / `https://` URL. The backend trims outside whitespace, normalizes a bare hostname to HTTPS, lowercases and IDNA-encodes its host, and validates hostname, scheme, port, credentials, control characters, and a 2048-character limit. Valid IPv4 and bracketed IPv6 literals are supported. Invalid input returns HTTP 400 and a JSON `error`. The backend never performs DNS or HTTP requests to the target.

Response contract:

- `normalized_url` and backward-compatible `url`: canonical URL actually analyzed and shown in the UI.
- `prediction` and `model_prediction`: raw ML class (`phishing` or `legitimate`).
- `phishing_probability` and `model_phishing_probability`: raw class-0 phishing score in `[0,1]`, uncalibrated.
- `verdict`: final `phishing` or `legitimate` decision. For ML results this equals the predicted class; a matching configurable team rule can override it to phishing.
- `verdict_source`: `ml_model` or `team_rule`.
- `policy_override`: whether the demonstration rule determined the final verdict.
- `policy_reason`: explanation for a rule match, otherwise `null`.
- `confidence`: raw probability for the predicted class, or `null` for a policy verdict. It is uncalibrated and is displayed with that caveat only for ML results.
- `summary`, `indicators`, `analysis`, `features`, and `model_mode`: explanation, URL-only signals, parsed analysis, ordered model inputs, and `ml` respectively.

Example ML response (illustrative values):

```json
{
  "normalized_url": "https://sample.org/login",
  "prediction": "phishing",
  "model_prediction": "phishing",
  "phishing_probability": 0.997,
  "model_phishing_probability": 0.997,
  "verdict": "phishing",
  "verdict_source": "ml_model",
  "policy_override": false,
  "policy_reason": null,
  "confidence": 0.997,
  "summary": "The model classifies this URL as phishing. This is an uncalibrated model estimate, not a guarantee; the scanner can make mistakes."
}
```

Example demonstration-policy response (raw ML output stays independent):

```json
{
  "normalized_url": "https://example.com",
  "prediction": "legitimate",
  "model_prediction": "legitimate",
  "phishing_probability": 0.08,
  "model_phishing_probability": 0.08,
  "verdict": "phishing",
  "verdict_source": "team_rule",
  "policy_override": true,
  "policy_reason": "The application flagged the domain example.com because it matches a team-configured demonstration rule. This is not an independent determination that the website is malicious.",
  "confidence": null
}
```

The UI shows a binary heading, uncalibrated predicted-class estimate, normalized URL, and raw model diagnostics. A team-rule override is labeled separately and receives no ML confidence value. Invalid input returns HTTP 400; inference or model-loading failures return HTTP 500 with a generic JSON error, not a fabricated verdict. Rate limits return HTTP 429.

## Install, run, and verify

From the repository root:

```powershell
python -m pip install -r backend/requirements.txt pytest
python download_dataset.py
python -m backend.app
```

Open `http://127.0.0.1:5000/`. Existing model artifact is used for serving. To train an isolated candidate, run `python -m backend.train`; it writes under `backend/candidate_model_output/` and does not replace the serving artifact. Review its report and held-out results before any deliberate promotion. Run checks with `python -m pytest -q backend/tests` and `node --test frontend/script.test.js`. `python -m backend.final_train` remains a compatibility alias. The artifact validates its feature schema, label mapping, and scikit-learn version at load time.
