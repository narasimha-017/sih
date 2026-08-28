"""
Sender Intelligence — DNS Provider
Queries public DNS records for a domain:
  - MX records (mail server infrastructure)
  - SPF record (TXT)
  - DMARC record (_dmarc TXT)
  - A/AAAA records (IP existence check)
Uses dnspython if available; falls back to socket for basic checks.
Zero-fetch safety: only queries authoritative public DNS servers.
Does NOT visit any URLs found in email content.
"""

import os
import socket

# ---------------------------------------------------------------------------
# dnspython is optional — if not installed, we fall back gracefully
# ---------------------------------------------------------------------------
try:
    import dns.resolver
    import dns.exception
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


def _safe_dns_query(domain: str, record_type: str, timeout: float = 3.0):
    """
    Wraps dns.resolver.resolve() with timeout and graceful error handling.
    Returns list of record strings, or None on any failure.
    """
    if not _DNS_AVAILABLE:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        answers = resolver.resolve(domain, record_type)
        return [str(r) for r in answers]
    except (dns.exception.DNSException, Exception):
        return None


def query_mx(domain: str) -> dict:
    """
    Query MX records. Returns provider list and availability status.
    """
    records = _safe_dns_query(domain, "MX")
    if records is None and not _DNS_AVAILABLE:
        return {"status": "source_unavailable", "records": [], "note": "dnspython not installed"}
    if records is None:
        return {"status": "not_found", "records": []}
    # Strip trailing dot, sort by priority (already in string form "10 mx.host.")
    cleaned = [r.split()[-1].rstrip(".") for r in records]
    return {"status": "found", "records": cleaned}


def query_spf(domain: str) -> dict:
    """
    Query SPF record from TXT records.
    Returns the SPF policy string if found.
    """
    records = _safe_dns_query(domain, "TXT")
    if records is None and not _DNS_AVAILABLE:
        return {"status": "source_unavailable", "record": None}
    if records is None:
        return {"status": "not_found", "record": None}
    for r in records:
        cleaned = r.strip('"')
        if cleaned.startswith("v=spf1"):
            return {"status": "found", "record": cleaned}
    return {"status": "not_found", "record": None}


def query_dmarc(domain: str) -> dict:
    """
    Query DMARC record from _dmarc.<domain> TXT.
    """
    records = _safe_dns_query(f"_dmarc.{domain}", "TXT")
    if records is None and not _DNS_AVAILABLE:
        return {"status": "source_unavailable", "record": None, "policy": None}
    if records is None:
        return {"status": "not_found", "record": None, "policy": None}
    for r in records:
        cleaned = r.strip('"')
        if "v=DMARC1" in cleaned:
            # Extract policy value
            policy = None
            for part in cleaned.split(";"):
                part = part.strip()
                if part.startswith("p="):
                    policy = part[2:].strip()
                    break
            return {"status": "found", "record": cleaned, "policy": policy}
    return {"status": "not_found", "record": None, "policy": None}


def query_a_record(domain: str) -> dict:
    """
    Basic A-record check — does the domain resolve at all?
    Falls back to socket.getaddrinfo if dnspython unavailable.
    """
    # Try dnspython first
    records = _safe_dns_query(domain, "A")
    if records:
        return {"status": "resolves", "ips": records}

    # Fallback: socket
    try:
        results = socket.getaddrinfo(domain, None, socket.AF_INET)
        ips = list({r[4][0] for r in results})
        return {"status": "resolves", "ips": ips}
    except Exception:
        pass

    return {"status": "nxdomain", "ips": []}


def run(domain: str) -> dict:
    """
    Execute all DNS intelligence providers for a domain.
    Returns a unified DNS intelligence dict.
    """
    print(f"[SenderIntel/DNS] Querying DNS records for: {domain}")

    mx   = query_mx(domain)
    spf  = query_spf(domain)
    dmarc = query_dmarc(domain)
    a    = query_a_record(domain)

    indicators = []

    # MX missing = no legitimate mail infra
    if mx["status"] == "not_found":
        indicators.append({
            "label": "No MX records found",
            "detail": "Domain has no published mail-exchanger records — unusual for a legitimate sender.",
            "points": 8
        })

    # SPF missing
    if spf["status"] == "not_found":
        indicators.append({
            "label": "No SPF record published",
            "detail": "Sender Policy Framework record absent — domain does not declare authorized senders.",
            "points": 6
        })

    # DMARC missing
    if dmarc["status"] == "not_found":
        indicators.append({
            "label": "No DMARC record published",
            "detail": "No DMARC policy — receiving servers cannot enforce reject/quarantine on spoofed mail.",
            "points": 6
        })
    elif dmarc["policy"] in ("none", None):
        indicators.append({
            "label": "DMARC policy is 'none' (monitor-only)",
            "detail": "DMARC exists but does not enforce reject or quarantine — spoofed mail may still be delivered.",
            "points": 3
        })

    # Domain does not resolve at all
    if a["status"] == "nxdomain":
        indicators.append({
            "label": "Domain does not resolve (NXDOMAIN)",
            "detail": "No A record found — domain may be ephemeral or already taken down.",
            "points": 10
        })

    return {
        "provider": "DNS Intelligence (dnspython + socket)",
        "mx":    mx,
        "spf":   spf,
        "dmarc": dmarc,
        "a_record": a,
        "indicators": indicators
    }
