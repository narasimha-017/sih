"""
SentryMail — Sender Intelligence Service
Orchestrates all intelligence providers and produces a unified result.

Activation threshold: configurable via SENDER_INTEL_THRESHOLD env var.
Default: 70 (out of 100 risk score).

This module is the single entry point called from main_v3.py.
"""

import os
import sys
import time

_local_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _local_dir not in sys.path:
    sys.path.insert(0, _local_dir)

# Configurable risk threshold — change via environment variable
RISK_THRESHOLD: int = int(os.environ.get("SENDER_INTEL_THRESHOLD", "70"))

# In-memory result cache keyed by domain (avoids re-querying same domain)
_INTEL_CACHE: dict = {}


def run_sender_intelligence(
    domain: str,
    sender_address: str,
    risk_score: int
) -> dict:
    """
    Main entry point. Checks threshold, runs all providers, returns unified result.

    Args:
        domain:         Sender email domain (e.g. "update-service-alert.com")
        sender_address: Full sender address (e.g. "security@update-service-alert.com")
        risk_score:     SentryMail risk score (0–100) from the main forensic engine

    Returns a dict with keys:
        activated: bool
        threshold: int
        domain: str
        sender_address: str
        dns: dict
        domain_reg: dict
        reputation: dict
        indicators: list (all aggregated indicators from all providers)
        total_intel_score: int (sum of all indicator points — informational only)
        disclaimer: str
    """

    base_result = {
        "activated": False,
        "threshold": RISK_THRESHOLD,
        "domain": domain,
        "sender_address": sender_address,
        "dns": None,
        "domain_reg": None,
        "reputation": None,
        "indicators": [],
        "total_intel_score": 0,
        "disclaimer": (
            "Information shown here is based on publicly available technical and "
            "threat-intelligence sources. IP/domain locations and registration data "
            "may be approximate or incomplete. SentryMail does not visit, download, "
            "or execute content from extracted URLs."
        )
    }

    # --- Threshold gate ---
    if risk_score < RISK_THRESHOLD:
        base_result["locked_reason"] = (
            f"Sender Intelligence activates at risk score ≥ {RISK_THRESHOLD}. "
            f"Current score: {risk_score}/100."
        )
        return base_result

    # --- Validate domain ---
    if not domain or "." not in domain:
        base_result["activated"] = True
        base_result["error"] = "Invalid or missing sender domain — cannot run intelligence."
        return base_result

    # --- Cache hit ---
    if domain in _INTEL_CACHE:
        cached = _INTEL_CACHE[domain].copy()
        cached["from_cache"] = True
        return cached

    base_result["activated"] = True
    print(f"[SenderIntel] Running full intelligence for domain: {domain} (risk={risk_score})")
    t0 = time.time()

    # --- Import providers lazily (allows graceful failure per-provider) ---
    dns_result = _run_provider("DNS", _run_dns, domain)
    domain_result = _run_provider("Domain Registration", _run_domain, domain)
    reputation_result = _run_provider("Reputation", _run_reputation, domain, sender_address)

    # --- Aggregate indicators from all providers ---
    all_indicators = []
    for src in [dns_result, domain_result, reputation_result]:
        if src and isinstance(src, dict):
            all_indicators.extend(src.get("indicators", []))

    total_score = sum(i.get("points", 0) for i in all_indicators)

    result = {
        **base_result,
        "dns": dns_result,
        "domain_reg": domain_result,
        "reputation": reputation_result,
        "indicators": all_indicators,
        "total_intel_score": total_score,
        "elapsed_ms": round((time.time() - t0) * 1000)
    }

    _INTEL_CACHE[domain] = result
    return result


def _run_provider(name: str, fn, *args) -> dict:
    """Wraps a provider call with top-level exception handling."""
    try:
        return fn(*args)
    except Exception as e:
        print(f"[SenderIntel] Provider '{name}' failed: {e}")
        return {
            "provider": name,
            "status": "provider_error",
            "note": f"Source unavailable: {e}",
            "indicators": []
        }


def _run_dns(domain: str) -> dict:
    try:
        from backend.app.sender_intelligence import dns as dns_mod
    except ImportError:
        from sender_intelligence import dns as dns_mod
    return dns_mod.run(domain)


def _run_domain(domain: str) -> dict:
    try:
        from backend.app.sender_intelligence import domain as domain_mod
    except ImportError:
        from sender_intelligence import domain as domain_mod
    return domain_mod.run(domain)


def _run_reputation(domain: str, sender_address: str) -> dict:
    try:
        from backend.app.sender_intelligence import reputation as rep_mod
    except ImportError:
        from sender_intelligence import reputation as rep_mod
    return rep_mod.run(domain, sender_address)
