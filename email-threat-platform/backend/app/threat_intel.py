"""
SentryMail Threat Intelligence & Geolocation Adapter
Handles:
1. Static / API-ready Known Phishing Threat Database Checks (Priority 2b / 4)
2. Real IP Geolocation Lookup via ip-api.com with strict Public IP Filtering (Priority 3)

Filter design:
  - Uses ipaddress.ip_address(ip).is_global as the SOLE authoritative check.
  - is_global correctly covers ALL non-routable ranges:
      * RFC 1918 private:  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
      * RFC 5737 TEST-NET: 198.51.100.0/24, 203.0.113.0/24, 192.0.2.0/24
      * Loopback:          127.0.0.0/8
      * Link-local:        169.254.0.0/16
      * CGNAT:             100.64.0.0/10
      * Multicast:         224.0.0.0/4
      * Unspecified:       0.0.0.0
  - Only IPs where is_global=True are sent to ip-api.com.
"""

import ipaddress
import json
import os
import urllib.request
import urllib.parse
from typing import Dict, Optional

THREAT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "known_phishing_domains.json")
_GEO_CACHE: Dict[str, dict] = {}
_THREAT_CACHE: Dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Threat Feed Adapter
# ---------------------------------------------------------------------------

def load_threat_db() -> Dict[str, dict]:
    global _THREAT_CACHE
    if not _THREAT_CACHE and os.path.exists(THREAT_DB_PATH):
        try:
            with open(THREAT_DB_PATH, "r", encoding="utf-8") as f:
                entries = json.load(f)
                _THREAT_CACHE = {e["domain"].lower(): e for e in entries if "domain" in e}
        except Exception as e:
            print(f"[ThreatIntel] Failed to load threat DB: {e}")
    return _THREAT_CACHE

def check_known_bad(domain_or_email: str) -> Optional[dict]:
    """
    Check if a domain or email matches known malicious threat intelligence feeds.
    Modular design ready to swap in PhishTank / MISP API in future versions.
    """
    if not domain_or_email:
        return None
    db = load_threat_db()
    clean = domain_or_email.strip().lower()
    dom = clean.rsplit('@', 1)[-1] if '@' in clean else clean
    return db.get(dom)

# ---------------------------------------------------------------------------
# IP Classification
# ---------------------------------------------------------------------------

def is_globally_routable(ip_str: str) -> bool:
    """
    Returns True ONLY for IPs that are globally routable (i.e., valid for
    geolocation via a public API). Uses Python's built-in ipaddress.is_global
    which covers all non-public ranges:
      - RFC 1918 private subnets
      - RFC 5737 documentation/TEST-NET subnets (198.51.100.x, 203.0.113.x, 192.0.2.x)
      - RFC 6598 CGNAT (100.64.0.0/10)
      - Loopback, link-local, multicast, unspecified
    """
    try:
        return ipaddress.ip_address(ip_str.strip()).is_global
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# Geolocation Lookup
# ---------------------------------------------------------------------------

def lookup_ip_geo(ip_str: str) -> dict:
    """
    Performs real IP geolocation via ip-api.com (free, no API key required).
    
    Pipeline:
      1. Validate IP string.
      2. Check is_global — if False, label as Internal/Local Hop. Never geolocate.
      3. Check in-memory cache to avoid duplicate API calls.
      4. Perform live lookup with diagnostic logging.
      5. On API failure, return 'Location unavailable' — never default to USA.

    Returns a hop dict with keys:
      ip, is_public, geolocated, city, country, lat, lon, org, label
    """
    ip_clean = ip_str.strip()

    # --- 1. Validate -------------------------------------------------------
    if not ip_clean:
        return {
            "ip": "",
            "is_public": False,
            "geolocated": False,
            "city": "Location unavailable",
            "country": "Location unavailable",
            "lat": None,
            "lon": None,
            "org": "",
            "label": "Invalid IP"
        }

    # --- 2. Non-global / private / reserved --------------------------------
    if not is_globally_routable(ip_clean):
        print(f"[GEO] Extracted IP: {ip_clean}")
        print(f"[GEO] Private/reserved IP — skipping geolocation")
        return {
            "ip": ip_clean,
            "is_public": False,
            "is_private": True,      # kept for frontend backward-compat
            "geolocated": False,
            "city": "Internal/Local Hop",
            "country": "Private Subnet",
            "lat": None,
            "lon": None,
            "org": "Internal Network",
            "label": f"Internal/Local Hop ({ip_clean})"
        }

    # --- 3. Cache hit -------------------------------------------------------
    if ip_clean in _GEO_CACHE:
        return _GEO_CACHE[ip_clean]

    # --- 4. Live geolocation lookup via ip-api.com --------------------------
    print(f"[GEO] Extracted IP: {ip_clean}")
    print(f"[GEO] Public IP: True")
    print(f"[GEO] Looking up: {ip_clean}")

    try:
        url = (
            f"http://ip-api.com/json/{urllib.parse.quote(ip_clean)}"
            f"?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
        )
        req = urllib.request.Request(
            url, headers={"User-Agent": "SentryMail-Forensics-SIH26106/3.1"}
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"[GEO] Raw API response for {ip_clean}: {data}")

            if data.get("status") == "success" and data.get("lat") is not None:
                city    = data.get("city") or "Location unavailable"
                country = data.get("country") or "Location unavailable"
                res = {
                    "ip":          ip_clean,
                    "is_public":   True,
                    "is_private":  False,    # backward-compat
                    "geolocated":  True,
                    "city":        city,
                    "country":     country,
                    "country_code": data.get("countryCode", ""),
                    "region":      data.get("regionName", ""),
                    "lat":         float(data["lat"]),
                    "lon":         float(data["lon"]),
                    "isp":         data.get("isp", ""),
                    "org":         data.get("org", ""),
                    "asn":         data.get("as", ""),
                    "label":       f"Mail Relay — {city}, {country} ({ip_clean})"
                }
                print(f"[GEO] Result: {city}, {country}")
                _GEO_CACHE[ip_clean] = res
                return res

            api_msg = data.get("message", "no match")
            print(f"[GEO] API returned non-success for {ip_clean}: {api_msg}")

    except Exception as exc:
        print(f"[GEO] Lookup failed for {ip_clean}: {exc}")
        print(f"[GEO] Location unavailable")

    # --- 5. Failure fallback — no fabricated location ----------------------
    fallback = {
        "ip":         ip_clean,
        "is_public":  True,
        "is_private": False,
        "geolocated": False,
        "city":       "Location unavailable",
        "country":    "Location unavailable",
        "lat":        None,
        "lon":        None,
        "org":        "Public Gateway",
        "label":      f"Location unavailable ({ip_clean})"
    }
    _GEO_CACHE[ip_clean] = fallback
    return fallback
