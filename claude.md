# 🚀 Project Constitution: SIH26106 Email Forensics

## 1. Directory Structure Specifications
email-threat-platform/
├── ml/
│   ├── datasets/               # Target for phishing_emails.csv
│   ├── models/                 # Target for email_classifier.pth, vectorizer.pkl
│   ├── evaluation/             # Target for training_metrics.png
│   ├── generate_mock_dataset.py
│   └── train.py
├── backend/
│   └── app/
│       ├── main.py             # FastAPI Server Entrypoint
│       ├── parser/
│       │   └── email_parser.py
│       ├── osint/
│       │   └── enrichment.py
│       └── models/
│           └── schemas.py      # Database models (PostgreSQL & SQLite)
└── run_forensic_pipeline.py    # Master integration pipeline

## 2. API Schema Definitions
- `POST /api/analyze`: Ingests email JSON/Raw, runs NLP + Headers + OSINT checks, returns unified JSON payload.
- `GET /api/cases`: Fetches case logs from PostgreSQL / SQLite.
- `GET /api/cases/{case_id}`: Single case drill-down.
- `GET /api/network-graph`: Generates node-link schema representing relationships between cases, domains, and IPs.

## 3. Threat Classification Boundaries
- 0 to 25: Low Risk (Legitimate)
- 26 to 50: Moderate Risk
- 51 to 75: Suspicious (Linguistic or technical warnings active)
- 76 to 100: High Risk (Multi-layer indicators trigger, auto-quarantine)

## 4. Robustness and Dynamic Dimensioning
- **Self-Healing Shape Resolution**: Rather than assuming static shape vector layers (e.g. 1000 features), models and parsers dynamically discover dimensions via `len(vectorizer.vocabulary_)` to ensure immediate compatibility across varying dataset sizes.

