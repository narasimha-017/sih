"""
Sender Intelligence — Domain Registration Provider
Uses RDAP (Registration Data Access Protocol) — the modern, free,
machine-readable replacement for WHOIS.
No API key required. RDAP is a public IETF standard (RFC 7483).

RDAP Bootstrap: https://data.iana.org/rdap/dns.json
We use IANA's bootstrap file to find the correct RDAP server per TLD,
then query it for domain registration data.

Privacy note: RDAP may contain registrant name/contact info.
This provider extracts ONLY:
  - Domain creation date
  - Domain expiry date
  - Last changed date
  - Registrar name
  - Domain status flags
We deliberately do NOT extract or display:
  - Registrant personal name
  - Registrant email
  - Registrant phone/address
"""

import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Optional

# In-memory cache: maps TLD -> RDAP base URL
_RDAP_BOOTSTRAP_CACHE: dict = {}
_RDAP_BOOTSTRAP_LOADED_AT: float = 0.0
_RDAP_CACHE_TTL_SECONDS = 3600  # Refresh IANA bootstrap hourly

IANA_RDAP_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_TIMEOUT = 4.0


def _get_rdap_url_for_tld(tld: str) -> Optional[str]:
    """
    Look up the RDAP server URL for a given TLD using the IANA bootstrap registry.
    Falls back to the generic RDAP.io proxy if bootstrap lookup fails.
    """
    global _RDAP_BOOTSTRAP_CACHE, _RDAP_BOOTSTRAP_LOADED_AT

    # Refresh cache if stale or empty
    now = time.time()
    if not _RDAP_BOOTSTRAP_CACHE or (now - _RDAP_BOOTSTRAP_LOADED_AT) > _RDAP_CACHE_TTL_SECONDS:
        try:
            req = urllib.request.Request(
                IANA_RDAP_BOOTSTRAP,
                headers={"User-Agent": "SentryMail-Forensics-SIH26106/3.2"}
            )
            with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as r:
                data = json.loads(r.read().decode())
                # Build TLD -> [url] mapping
                new_cache = {}
                for entry in data.get("services", []):
                    tlds_list, urls_list = entry[0], entry[1]
                    for t in tlds_list:
                        new_cache[t.lower()] = urls_list[0] if urls_list else None
                _RDAP_BOOTSTRAP_CACHE = new_cache
                _RDAP_BOOTSTRAP_LOADED_AT = now
        except Exception as e:
            print(f"[SenderIntel/Domain] IANA RDAP bootstrap fetch failed: {e}")

    return _RDAP_BOOTSTRAP_CACHE.get(tld.lower())


def _parse_rdap_date(date_str: Optional[str]) -> Optional[str]:
    """Parse ISO 8601 date string to a readable format."""
    if not date_str:
        return None
    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return date_str[:10] if len(date_str) >= 10 else date_str


def _compute_domain_age_days(creation_date_str: Optional[str]) -> Optional[int]:
    """Compute age of domain in days from creation date string."""
    if not creation_date_str:
        return None
    try:
        dt = datetime.fromisoformat(creation_date_str.replace("Z", "+00:00"))
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


def run(domain: str) -> dict:
    """
    Query RDAP for domain registration intelligence.
    Returns structured registration data with privacy protections applied.
    """
    print(f"[SenderIntel/Domain] RDAP lookup for: {domain}")

    tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
    rdap_base = _get_rdap_url_for_tld(tld)

    indicators = []
    result = {
        "provider": "RDAP (IANA — public domain registration protocol)",
        "domain": domain,
        "creation_date": None,
        "expiry_date": None,
        "last_changed": None,
        "registrar": None,
        "status": [],
        "age_days": None,
        "age_label": None,
        "indicators": indicators,
        "note": None
    }

    # Construct lookup URL
    if rdap_base:
        url = rdap_base.rstrip("/") + f"/domain/{domain}"
    else:
        # Fallback to rdap.org proxy (public, no key)
        url = f"https://rdap.org/domain/{domain}"

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "SentryMail-Forensics-SIH26106/3.2",
                          "Accept": "application/rdap+json, application/json"}
        )
        with urllib.request.urlopen(req, timeout=RDAP_TIMEOUT) as r:
            data = json.loads(r.read().decode())

        # --- Extract dates ---
        creation_date = None
        expiry_date = None
        last_changed = None
        for event in data.get("events", []):
            action = event.get("eventAction", "")
            date = event.get("eventDate")
            if action == "registration":
                creation_date = date
            elif action == "expiration":
                expiry_date = date
            elif action == "last changed":
                last_changed = date

        result["creation_date"] = _parse_rdap_date(creation_date)
        result["expiry_date"]   = _parse_rdap_date(expiry_date)
        result["last_changed"]  = _parse_rdap_date(last_changed)

        # --- Domain age ---
        age_days = _compute_domain_age_days(creation_date)
        result["age_days"] = age_days
        if age_days is not None:
            if age_days < 30:
                result["age_label"] = f"{age_days} days ⚠️ VERY NEW"
                indicators.append({
                    "label": f"Domain registered very recently ({age_days} days ago)",
                    "detail": "Newly registered domains are commonly used for phishing campaigns and are disposed after use.",
                    "points": 15
                })
            elif age_days < 180:
                result["age_label"] = f"{age_days} days (< 6 months)"
                indicators.append({
                    "label": f"Domain registered recently ({age_days} days ago)",
                    "detail": "Domain is less than 6 months old — elevated risk for disposable attack infrastructure.",
                    "points": 8
                })
            elif age_days < 365:
                result["age_label"] = f"{age_days} days (< 1 year)"
            else:
                years = age_days // 365
                result["age_label"] = f"{years} year{'s' if years > 1 else ''}"

        # --- Registrar (privacy-safe: name only) ---
        entities = data.get("entities", [])
        for entity in entities:
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = field[3]
                            break
                # Also try nameserver from entity handle
                if not result["registrar"]:
                    result["registrar"] = entity.get("handle") or entity.get("publicIds", [{}])[0].get("identifier")
                break

        # --- Status flags ---
        status_flags = data.get("status", [])
        result["status"] = status_flags

        # Suspicious if no clientTransferProhibited (may be a fresh/disposable reg)
        if status_flags and "client transfer prohibited" not in [s.lower() for s in status_flags]:
            indicators.append({
                "label": "Domain lacks clientTransferProhibited lock",
                "detail": "Domain registration is not locked — may indicate a temporary/disposable domain.",
                "points": 3
            })

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["note"] = "Domain not found in RDAP registry (may be very new, ccTLD-only, or recently deleted)"
            indicators.append({
                "label": "Domain not found in RDAP registry",
                "detail": "No RDAP registration data available — domain may be too new or use a non-RDAP TLD.",
                "points": 5
            })
        else:
            result["note"] = f"RDAP lookup returned HTTP {e.code}"
    except Exception as e:
        print(f"[SenderIntel/Domain] RDAP lookup failed for {domain}: {e}")
        result["note"] = "Source unavailable (RDAP query failed)"

    return result
