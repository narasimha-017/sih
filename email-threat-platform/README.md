# MailSentinel — SIH26106 Email Threat Forensics MVP

This is an original implementation scaffold based on the uploaded SIH26106 brief. It is intentionally not a copy of any referenced GitHub project.

## What is included
- Responsive Progressive Web App (PWA): works on modern Android/iPhone browsers and can be installed from the browser.
- FastAPI/Python analysis API.
- Safe `.eml` parser using Python's standard `email` package.
- SPF/DKIM/DMARC result parsing from existing authentication headers.
- From/Reply-To/Return-Path analysis.
- URL extraction, visible-vs-actual link mismatch, URL shortener/IP-literal/punycode indicators.
- Attachment inventory + SHA-256 hashes; risky extensions are only flagged, never executed.
- Received-header IP extraction and observable relay count.
- Explainable 0–100 baseline risk engine with the brief's category maxima.
- PostgreSQL forensic schema for cases, evidence, indicators and analyst actions.
- Docker Compose deployment.
- Optional Java Android WebView wrapper skeleton for Android packaging.

## Run locally
1. Install Docker Desktop.
2. From this directory run: `docker compose up --build`
3. Open `http://localhost:8080` on a computer or phone on the same network after binding the service appropriately.
4. Upload an `.eml` file.

For a public deployment, put the API behind HTTPS, use a real domain, restrict CORS, add authentication, rotate secrets, and do not expose PostgreSQL publicly.

## Important safety design
- The MVP never fetches or opens URLs found inside an email.
- It accepts `.eml` only and caps uploads at 5 MB.
- It does not execute attachments.
- It does not claim that an IP location is an attacker's physical location.
- It does not treat SPF/DKIM/DMARC failure as proof of fraud.
- It separates risk from confidence.
- It does not automatically delete/block email based only on an AI prediction.

## PWA / phone installation
A web app is the best cross-phone base because one codebase can serve Android and iOS. Installation is user-controlled by the browser/OS; an app cannot silently install itself. The browser may offer "Add to Home Screen" / "Install" after HTTPS deployment.

## Gmail integration — next module
The SIH brief calls for Gmail integration, but this starter keeps it separate until the analysis pipeline is stable. Use the narrowest Google OAuth scope possible; for reading email, `gmail.readonly` is the relevant Gmail API scope. Public apps using sensitive Google scopes can require verification. See the official Google OAuth scope documentation.

## Originality
Research was used to understand common defensive patterns (email parsing, header forensics, IOC extraction, explainable scoring). No GitHub repository was copied. The architecture and code here are newly authored around SIH26106's requirements.

## Production roadmap
1. Dataset + statistically validated pattern library.
2. Persist cases/evidence to PostgreSQL.
3. Add authentication/RBAC and encrypted secrets.
4. Add passive threat-intelligence adapters (IP/domain/URL reputation) without automatically visiting suspicious URLs.
5. Add geolocation/ASN/ISP enrichment and explicit infrastructure-location labels.
6. Add graph correlation (Neo4j later) and campaign detection.
7. Add evidence-grounded LLM copilot with strict retrieval from the evidence store.
8. Add Gmail OAuth using least privilege.
9. Add PDF forensic reporting and tamper-evident evidence ledger if useful.
10. Validate on an unseen test set using precision, recall, F1 and false-positive/negative rates.

## Files
- `backend/app/main.py` — analysis API
- `frontend/` — mobile-first PWA
- `sql/schema.sql` — forensic relational model
- `android-java-wrapper/` — optional Android Java shell
