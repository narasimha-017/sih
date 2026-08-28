"""
Sender Intelligence — Reputation Provider
Queries public reputation/abuse databases:

  1. Local SentryMail known-phishing threat feed (always available)
  2. AbuseIPDB (public API — requires ABUSEIPDB_API_KEY env var, gracefully skipped if absent)

Zero-fetch safety: Does NOT visit suspicious URLs. Only queries
legitimate threat-intelligence APIs using the domain/IP as a query parameter.
"""

import json
import os
import sys
import urllib.request
import urllib.error
from typing import Optional

# ---------------------------------------------------------------------------
# Re-use the existing threat_intel module (avoids code duplication)
# ---------------------------------------------------------------------------
_local_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _local_dir not in sys.path:
    sys.path.insert(0, _local_dir)

try:
    from backend.app.threat_intel import check_known_bad
except ImportError:
    try:
        from threat_intel import check_known_bad
    except ImportError:
        def check_known_bad(x):
            return None


# ---------------------------------------------------------------------------
# Provider: Local SentryMail Threat Feed
# ---------------------------------------------------------------------------

def _check_local_feed(domain: str) -> dict:
    """
    Check domain against the bundled SentryMail known-phishing feed.
    Always available — no external dependency.
    """
    result = check_known_bad(domain)
    if result:
        return {
            "status": "match",
            "source": "SentryMail Local Threat Feed",
            "category": result.get("category", "Malicious"),
            "severity": result.get("severity", "high"),
            "note": result.get("description", "")
        }
    return {
        "status": "clean",
        "source": "SentryMail Local Threat Feed"
    }


# ---------------------------------------------------------------------------
# Provider: AbuseIPDB Domain Check (optional, needs API key)
# ---------------------------------------------------------------------------

def _check_abuseipdb_domain(domain: str) -> dict:
    """
    Check domain reputation against AbuseIPDB.
    Requires ABUSEIPDB_API_KEY environment variable.
    Gracefully skipped if key is not set.
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
    if not api_key:
        return {
            "status": "source_unavailable",
            "source": "AbuseIPDB",
            "note": "ABUSEIPDB_API_KEY environment variable not set"
        }
    try:
        import urllib.parse
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(domain)}&maxAgeInDays=90"
        req = urllib.request.Request(url, headers={
            "Key": api_key,
            "Accept": "application/json",
            "User-Agent": "SentryMail-Forensics-SIH26106/3.2"
        })
        with urllib.request.urlopen(req, timeout=4.0) as r:
            data = json.loads(r.read().decode()).get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            return {
                "status": "checked",
                "source": "AbuseIPDB",
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt"),
                "is_whitelisted": data.get("isWhitelisted", False)
            }
    except Exception as e:
        return {
            "status": "source_unavailable",
            "source": "AbuseIPDB",
            "note": f"Query failed: {e}"
        }


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(domain: str, sender_address: str = "") -> dict:
    """
    Run all reputation providers for a domain.
    Returns consolidated reputation intelligence.
    """
    print(f"[SenderIntel/Reputation] Checking reputation for: {domain}")

    local  = _check_local_feed(domain)
    abuse  = _check_abuseipdb_domain(domain)

    indicators = []

    if local["status"] == "match":
        indicators.append({
            "label": f"Domain in SentryMail threat feed ({local.get('category', 'Malicious')})",
            "detail": local.get("note") or "Domain appears in SentryMail's curated phishing/malicious domain database.",
            "points": 25
        })

    if abuse.get("status") == "checked":
        score = abuse.get("abuse_confidence_score", 0)
        if score >= 75:
            indicators.append({
                "label": f"AbuseIPDB confidence score: {score}% — HIGH",
                "detail": f"Reported {abuse.get('total_reports', 0)} time(s). High confidence of malicious activity.",
                "points": 20
            })
        elif score >= 25:
            indicators.append({
                "label": f"AbuseIPDB confidence score: {score}% — MODERATE",
                "detail": f"Reported {abuse.get('total_reports', 0)} time(s). Moderate abuse signals.",
                "points": 10
            })

    # Overall reputation label
    if local["status"] == "match":
        reputation_label = "Confirmed Malicious (Threat Feed)"
    elif abuse.get("abuse_confidence_score", 0) >= 75:
        reputation_label = "High Abuse Score"
    elif abuse.get("abuse_confidence_score", 0) >= 25:
        reputation_label = "Moderate Abuse Signals"
    else:
        reputation_label = "No known threat matches found"

    return {
        "provider": "Reputation Intelligence",
        "domain": domain,
        "reputation_label": reputation_label,
        "local_feed": local,
        "abuseipdb": abuse,
        "indicators": indicators
    }
