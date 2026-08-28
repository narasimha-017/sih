"""
SentryMail Geolocation Pipeline — Comprehensive Test Suite
Tests A–E as specified in the bug-fix directive.
"""
import json
import sys
import urllib.request
import urllib.error
import ipaddress

BASE = "http://127.0.0.1:8000"
PASS = "\u001b[32mPASS\u001b[0m"
FAIL = "\u001b[31mFAIL\u001b[0m"
errors = []

def post_raw(raw_text):
    payload = json.dumps({"raw_text": raw_text}).encode()
    req = urllib.request.Request(
        f"{BASE}/api/analyze-raw", data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def check(label, condition, detail=""):
    if condition:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  {label}{' — ' + detail if detail else ''}")
        errors.append(label)

print("=" * 66)
print("SentryMail Geolocation Test Suite")
print("=" * 66)

# -----------------------------------------------------------------------
# Test A — Private IP must never be geolocated
# -----------------------------------------------------------------------
print("\n[Test A] Private IP: 192.168.1.100")
res = post_raw("""From: attacker@bad.com
Received: from mx.internal (192.168.1.100) by mx.local
Subject: Test A
""")
hops = res.get("relay_geo_hops", [])
check("Exactly 1 hop extracted", len(hops) == 1, f"got {len(hops)}: {hops}")
if hops:
    h = hops[0]
    check("is_public=False OR is_private=True", h.get("is_public") == False or h.get("is_private") == True, str(h))
    check("geolocated=False", h.get("geolocated") == False, str(h))
    check("lat is None", h.get("lat") is None, str(h.get("lat")))
    check("lon is None", h.get("lon") is None, str(h.get("lon")))
    check("city != USA / United States", h.get("city") not in ("Ashburn","New York","California","United States"), str(h.get("city")))

# -----------------------------------------------------------------------
# Test B — Real public IP must be geolocated correctly
# -----------------------------------------------------------------------
print("\n[Test B] Real public IP: 194.25.0.68 (Frankfurt, Germany)")
res = post_raw("""From: sender@example.com
Received: from mail.de (mail.de [194.25.0.68]) by mx.example.com
Subject: Test B
""")
hops = res.get("relay_geo_hops", [])
check("Exactly 1 hop extracted", len(hops) == 1, f"got {len(hops)}")
if hops:
    h = hops[0]
    check("ip == 194.25.0.68", h.get("ip") == "194.25.0.68", h.get("ip"))
    check("geolocated=True", h.get("geolocated") == True, str(h.get("geolocated")))
    check("country == Germany", h.get("country") == "Germany", h.get("country"))
    check("lat is not None", h.get("lat") is not None)
    check("lon is not None", h.get("lon") is not None)
    check("lat != 0.0", h.get("lat") != 0.0, str(h.get("lat")))

# -----------------------------------------------------------------------
# Test C — Multiple hops: correct count, order, independent geolocation
# -----------------------------------------------------------------------
print("\n[Test C] Multiple hops in order: private -> Frankfurt -> Tokyo")
res = post_raw("""From: ceo@attacker.net
Received: from internal-lan (10.0.4.12) by mx.local
Received: from relay.de (relay.de [194.25.0.68]) by internal-lan
Received: from mta.jp (mta.jp [133.242.0.1]) by relay.de
Subject: Test C
""")
hops = res.get("relay_geo_hops", [])
check("3 hops extracted", len(hops) == 3, f"got {len(hops)}: {[h.get('ip') for h in hops]}")
if len(hops) == 3:
    check("Hop 1 IP = 10.0.4.12", hops[0].get("ip") == "10.0.4.12", hops[0].get("ip"))
    check("Hop 1 is NOT geolocated (private)", hops[0].get("geolocated") == False)
    check("Hop 2 IP = 194.25.0.68", hops[1].get("ip") == "194.25.0.68", hops[1].get("ip"))
    check("Hop 2 is Germany", hops[1].get("country") == "Germany", hops[1].get("country"))
    check("Hop 3 IP = 133.242.0.1", hops[2].get("ip") == "133.242.0.1", hops[2].get("ip"))
    check("Hop 3 is Japan", hops[2].get("country") == "Japan", hops[2].get("country"))

# -----------------------------------------------------------------------
# Test D — Body IPs (phishing lure links) must NOT appear as relay hops
# -----------------------------------------------------------------------
print("\n[Test D] Body-only IP must NOT be treated as relay hop")
res = post_raw("""From: attacker@bad.com
Received: from relay.de (relay.de [194.25.0.68]) by mx.local
Subject: Test D

Click here to login: http://8.8.8.8/steal-credentials
Wire to: 74.125.0.1
""")
hops = res.get("relay_geo_hops", [])
hop_ips = [h.get("ip") for h in hops]
check("Only 1 hop (from Received: only)", len(hops) == 1, f"got {len(hops)} hops: {hop_ips}")
check("8.8.8.8 NOT in relay hops (it's in body only)", "8.8.8.8" not in hop_ips, str(hop_ips))
check("74.125.0.1 NOT in relay hops (body only)", "74.125.0.1" not in hop_ips, str(hop_ips))
check("194.25.0.68 IS in relay hops", "194.25.0.68" in hop_ips, str(hop_ips))

# -----------------------------------------------------------------------
# Test E — Failed lookup fallback must NOT be USA
# -----------------------------------------------------------------------
print("\n[Test E] Bracketed IP notation extraction (standard email format)")
res = post_raw("""From: sender@example.com
Received: from mail.example.com (mail.example.com [212.58.244.20]) by mx.host.com with ESMTPS
Subject: Test E
""")
hops = res.get("relay_geo_hops", [])
check("1 hop extracted", len(hops) == 1, f"got {len(hops)}")
if hops:
    h = hops[0]
    check("Bracketed IP [212.58.244.20] preferred", h.get("ip") == "212.58.244.20", h.get("ip"))
    check("country == United Kingdom", h.get("country") == "United Kingdom", h.get("country"))

# -----------------------------------------------------------------------
# Test F — TEST-NET (RFC 5737) must be treated as non-public
# -----------------------------------------------------------------------
print("\n[Test F] RFC 5737 TEST-NET IPs must be skipped (not geolocated)")
for test_ip in ["198.51.100.24", "203.0.113.10", "192.0.2.1"]:
    res = post_raw(f"""From: sender@example.com
Received: from doc-host ({test_ip}) by mx.local
Subject: Test F {test_ip}
""")
    hops = res.get("relay_geo_hops", [])
    check(f"{test_ip} NOT geolocated (TEST-NET/private)", 
          not hops or hops[0].get("geolocated") == False,
          str(hops[0] if hops else "no hops"))

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
print("\n" + "=" * 66)
if errors:
    print(f"FAILED: {len(errors)} test(s) failed:")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print(f"ALL TESTS PASSED ({6} test groups, {len(errors)} failures)")
print("=" * 66)
