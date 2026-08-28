def run_reverse_email_lookup(email_address):
    """
    Simulates a Spokeo/SEON footprint lookup checking social networks and data breach age.
    """
    domain = email_address.split("@")[-1] if "@" in email_address else ""

    # Footprint heuristic model: new lookalike domains have low age and no social associations
    is_suspect_domain = domain in [
        "chase-security-update.net",
        "executive-president.com",
        "unsecured-relay.net"
    ]

    return {
        "domain_age_days": 11 if is_suspect_domain else 4200,
        "social_profile_associations": (
            {} if is_suspect_domain
            else {"linkedin": "profile_verified", "facebook": "active"}
        ),
        "data_breach_appearances": 0 if is_suspect_domain else 4,
        # risk_multiplier: 1.0 = high-risk, 0.0 = clean
        "risk_multiplier": 1.0 if is_suspect_domain else 0.0,
    }


def trace_smtp_routing(received_headers, trusted_gateways=None):
    """
    Backward-parsing engine tracking SMTP relays.
    Flags everything outside our trusted mail gateways as UNVERIFIED.
    """
    if trusted_gateways is None:
        trusted_gateways = ["target-firm.com", "target-gateway.com"]

    route_trace = []

    for i, received in enumerate(received_headers):
        sender_ip  = received.get("ip")
        mail_server = received.get("by")
        isp     = received.get("isp",     "Deutsche Telekom AG")
        city    = received.get("city",    "Frankfurt")
        country = received.get("country", "Germany")

        # First hop coming from our own gateway is VERIFIED; all others are UNVERIFIED
        is_verified = (
            i == 0 and
            any(gw in mail_server for gw in trusted_gateways)
        )

        route_trace.append({
            "hop_number":          i + 1,
            "ip":                  sender_ip,
            "mail_server":         mail_server,
            "isp":                 isp,
            "location":            f"{city}, {country}",
            "verification_status": "VERIFIED" if is_verified else "UNVERIFIED",
        })

    return route_trace


if __name__ == "__main__":
    email = "support@chase-security-update.net"
    print("👤 Running mock Spokeo Reverse Lookup on suspect address...")
    osint_result = run_reverse_email_lookup(email)
    print(
        f"   Footprint Result: Age={osint_result['domain_age_days']} days | "
        f"Social Profiles={osint_result['social_profile_associations']} | "
        f"Identity Risk Score={osint_result['risk_multiplier'] * 100:.0f}%"
    )

    received_payloads = [
        {"ip": "18.20.151.4",   "by": "mail-router.target-firm.com"},
        {"ip": "185.112.144.5", "by": "mx.chase-security-update.net"},
        {"ip": "178.21.11.42",  "by": "hacker-relay.local"},
    ]
    print("\n🗺️  Analyzing email relay transit routing and geolocating hops...")
    hops = trace_smtp_routing(received_payloads)
    for hop in hops:
        print(
            f"   Hop {hop['hop_number']}: {hop['ip']} ({hop['location']}) | "
            f"Server: {hop['mail_server']} | ISP: {hop['isp']} | "
            f"Status: {hop['verification_status']}"
        )
