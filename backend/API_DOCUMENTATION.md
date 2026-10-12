# Phishing & Malicious URL Safety Scanner API

## Overview

This Flask REST API validates submitted URLs and analyzes characteristics that may indicate phishing. It returns JSON responses and includes rate limiting and error handling.

**Base URL (local):** `http://127.0.0.1:5000`

## 1. Health Check

- **Endpoint:** `/health`
- **Method:** GET
- **Purpose:** Checks whether the API is running.

Example response:

```json
{
  "status": "healthy",
  "service": "Phishing URL Safety Scanner API"
}
```

Success status: `200 OK`

## 2. Scan a URL

- **Endpoint:** `/scan`
- **Method:** POST
- **Content-Type:** `application/json`
- **Purpose:** Validates a URL and returns its analysis.

Example request:

```json
{
  "url": "https://example.com"
}
```

Example response:

```json
{
  "url": "https://example.com",
  "prediction": "legitimate",
  "analysis": {
    "https": true,
    "hyphen_count": 0,
    "indicators": [],
    "special_character_count": 4,
    "subdomain_count": 0,
    "suspicious_keywords": [],
    "url_length": 19,
    "uses_ip_address": false
  },
  "model_mode": "rule_based",
  "warning": "Preliminary rule-based result only. This does not guarantee that a URL is safe."
}
```

The analysis fields identify URL characteristics such as length, IP-address usage, hyphens, and suspicious keywords.

## 3. Error Responses

| HTTP status | Meaning |
|---|---|
| 400 | Invalid input or malformed request |
| 429 | Rate limit exceeded |
| 500 | Unexpected server error |

Example invalid request:

```json
{
  "url": ""
}
```

## 4. Rate Limiting

The scan endpoint allows up to 10 requests per minute per client. The application also has a default limit of 100 requests per hour.

## 5. Security Notes

- The API does not visit submitted URLs.
- URL characteristics are indicators, not proof of phishing.
- The current prediction is based on simple rules, not a trained machine-learning model.
- The Flask development server is intended for local testing, not production deployment.
- Production deployment should use HTTPS, a production WSGI server, and appropriate shared rate-limit storage where needed.