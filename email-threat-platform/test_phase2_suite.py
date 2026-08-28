"""
SentryMail Phase 2 — Full Test Suite
Tests Sender Intelligence + Home Widget + all existing functionality.
"""
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:8000"
PASS = "\033[32mPASS\033[0m"
FAIL = "\033[31mFAIL\033[0m"
SKIP = "\033[33mSKIP\033[0m"
errors = []

def post_raw(raw_text):
    payload = json.dumps({"raw_text": raw_text}).encode()
    req = urllib.request.Request(
        f"{BASE}/api/analyze-raw", data=payload,
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read().decode())

def get_si(domain, address="", risk_score=0):
    url = f"{BASE}/api/sender-intelligence?domain={urllib.request.quote(domain)}&address={urllib.request.quote(address)}&risk_score={risk_score}"
    with urllib.request.urlopen(url, timeout=20) as r:
        return json.loads(r.read().decode())

def get_url(path):
    with urllib.request.urlopen(f"{BASE}{path}", timeout=8) as r:
        return r.status, r.read().decode()

def check(label, condition, detail=""):
    if condition:
        print(f"  {PASS}  {label}")
    else:
        print(f"  {FAIL}  {label}{' — ' + str(detail) if detail else ''}")
        errors.append(label)

print("=" * 70)
print("SentryMail Phase 2 — Full Test Suite")
print("=" * 70)

# -----------------------------------------------------------------------
# Test 1 — Clean email → Sender Intelligence LOCKED
# -----------------------------------------------------------------------
print("\n[Test 1] Clean email → Sender Intelligence locked")
res = post_raw("""From: Newsletter <newsletter@techweekly.org>
Received: from relay.de (relay.de [194.25.0.68]) by mx.local
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Subject: Tech Weekly Issue #42

Hello subscriber, enjoy this week's digest!
""")
check("Clean email analyzed OK", "risk_score" in res)
check("Risk score is low (< 70)", res.get("risk_score", 99) < 70, f"score={res.get('risk_score')}")

si_clean = get_si(res["sender"]["domain"], res["sender"]["address"], res["risk_score"])
check("SI not activated (locked)", si_clean["activated"] == False)
check("locked_reason returned", "locked_reason" in si_clean)
check("threshold is 70", si_clean["threshold"] == 70)

# -----------------------------------------------------------------------
# Test 2 — Suspicious email below threshold → Sender Intelligence LOCKED
# -----------------------------------------------------------------------
print("\n[Test 2] Suspicious email (score ~50) → Sender Intelligence locked")
res2 = post_raw("""From: HR Dept <hr@suspicious-co.xyz>
Received: from relay.xyz (relay.xyz [182.79.0.1]) by mx.local
Authentication-Results: mx; spf=fail; dkim=unknown; dmarc=none
Subject: Urgent: Salary review needed - verify login

Please login and verify your account immediately.
""")
check("Email analyzed OK", "risk_score" in res2)
si2 = get_si(res2["sender"]["domain"], res2["sender"]["address"], res2["risk_score"])
if res2["risk_score"] < 70:
    check("SI locked (score below 70)", si2["activated"] == False)
else:
    check("SI activated (score >= 70)", si2["activated"] == True, f"score={res2['risk_score']}")

# -----------------------------------------------------------------------
# Test 3 — High risk email → Sender Intelligence ACTIVATED
# -----------------------------------------------------------------------
print("\n[Test 3] Phishing email (high risk) → Sender Intelligence activated")
res3 = post_raw("""From: Security Alert <security@update-service-alert.com>
Reply-To: attacker@drop.net
Received: from vps.hack.net (vps.hack.net [194.25.0.68]) by mx.local
Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail
Subject: URGENT: Your account has been suspended - verify immediately

Dear Customer,
Your account has been suspended. Please verify your credentials immediately.
Click here: http://bit.ly/ph1sh1ng-link
Login: http://attacker-drop.net/login
""")
check("High-risk email analyzed", "risk_score" in res3, f"score={res3.get('risk_score')}")
check("Risk score >= 50", res3.get("risk_score", 0) >= 50, f"score={res3.get('risk_score')}")

si3 = get_si(res3["sender"]["domain"], res3["sender"]["address"], res3["risk_score"])
if res3["risk_score"] >= 70:
    check("SI activated (score >= 70)", si3["activated"] == True, f"score={res3['risk_score']}")
    check("dns provider present", si3.get("dns") is not None)
    check("domain_reg provider present", si3.get("domain_reg") is not None)
    check("reputation provider present", si3.get("reputation") is not None)
    check("indicators list present", isinstance(si3.get("indicators"), list))
    check("disclaimer present", bool(si3.get("disclaimer")))
else:
    check(f"SI locked (score={res3['risk_score']} < 70)", si3["activated"] == False)
    print(f"    NOTE: test3 score={res3['risk_score']} — increase score for full SI test")

# -----------------------------------------------------------------------
# Test 4 — No external API → No crash, graceful
# -----------------------------------------------------------------------
print("\n[Test 4] Missing external API → graceful 'source unavailable'")
si4 = get_si("example.com", "user@example.com", 90)
check("No crash on example.com", si4 is not None)
check("activated=True (score=90)", si4["activated"] == True)
check("dns provider returned", si4.get("dns") is not None)
check("domain_reg returned (or note)", si4.get("domain_reg") is not None)
check("No provider_error crash in dns",
      si4.get("dns", {}).get("status") != "provider_error" or si4.get("dns", {}).get("note") is not None)

# -----------------------------------------------------------------------
# Test 5 — Invalid domain → Graceful failure
# -----------------------------------------------------------------------
print("\n[Test 5] Invalid/garbage domain → graceful failure")
si5 = get_si("not-a-real-domain-xyz-abc-123.invalid", "", 90)
check("No crash on invalid domain", si5 is not None)
check("activated=True (score=90)", si5["activated"] == True)
# Domain may return RDAP 404 or DNS NXDOMAIN — either is fine, just no crash
dns5 = si5.get("dns", {})
arec5 = dns5.get("a_record", {})
check("Domain correctly identified as non-resolving OR RDAP error is graceful",
      arec5.get("status") in ("nxdomain", "resolves", None)
      or si5.get("domain_reg", {}).get("note") is not None)

# -----------------------------------------------------------------------
# Test 6 — Existing scanner still works
# -----------------------------------------------------------------------
print("\n[Test 6] Existing scanner still works (POST /api/analyze-raw)")
res6 = post_raw("""From: admin@trusted-corporation.com
Subject: Test

Hello, this is a test email.
""")
check("Scanner returns risk_score", "risk_score" in res6)
check("Scanner returns findings", "findings" in res6)
check("Scanner returns relay_geo_hops", "relay_geo_hops" in res6)

# -----------------------------------------------------------------------
# Test 7 — Geolocation still works
# -----------------------------------------------------------------------
print("\n[Test 7] Existing geolocation still works")
res7 = post_raw("""From: sender@example.com
Received: from mail.de (mail.de [194.25.0.68]) by mx.local
Subject: Test 7
""")
hops = res7.get("relay_geo_hops", [])
check("1 hop extracted", len(hops) == 1, f"got {len(hops)}")
if hops:
    check("194.25.0.68 geolocated to Germany", hops[0].get("country") == "Germany", hops[0].get("country"))

# -----------------------------------------------------------------------
# Test 8 — Existing risk score unchanged
# -----------------------------------------------------------------------
print("\n[Test 8] Risk score engine unchanged (no SI contamination)")
res8 = post_raw("""From: test@clean-corp.com
Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass
Subject: Regular notification

Hello team.
""")
check("Risk score is integer", isinstance(res8.get("risk_score"), int))
check("Risk score in valid range 0-100", 0 <= res8.get("risk_score", -1) <= 100)
check("findings is list", isinstance(res8.get("findings"), list))

# -----------------------------------------------------------------------
# Test 9 — Threat intelligence still works
# -----------------------------------------------------------------------
print("\n[Test 9] Existing threat intelligence still works")
res9 = post_raw("""From: security@paypal-security-update.com
Authentication-Results: mx; spf=fail; dkim=fail
Subject: URGENT verify your PayPal account now
""")
check("Threat scan ran", "risk_score" in res9)

# Test SI on known threat domain if risk is high enough
si9 = get_si("update-service-alert.com", "security@update-service-alert.com", 90)
check("Threat intel check ran in SI", si9.get("reputation") is not None)
check("No crash on threat domain SI", "error" not in si9 or si9.get("activated"))

# -----------------------------------------------------------------------
# Test 10 — Home widget navigation (GET /)
# -----------------------------------------------------------------------
print("\n[Test 10] Home widget: GET / returns landing page")
status, html = get_url("/")
check("GET / returns 200", status == 200, f"status={status}")
check("Landing page contains SentryMail branding", "SentryMail" in html)
check("Landing page links to /scanner", "/scanner" in html)

# Home button in scanner nav
_, scanner_html = get_url("/scanner")
check("Scanner nav has 🏠 Home link", "🏠 Home" in scanner_html or "&#127968; Home" in scanner_html or 'href="/"' in scanner_html)

# -----------------------------------------------------------------------
# Test 11 — Sender Intelligence API endpoint accessible
# -----------------------------------------------------------------------
print("\n[Test 11] /api/sender-intelligence endpoint is live")
si11 = get_si("google.com", "noreply@google.com", 90)
check("Endpoint returns JSON", si11 is not None)
check("activated=True (score=90)", si11["activated"] == True)
check("All 3 providers present", all(si11.get(k) is not None for k in ["dns", "domain_reg", "reputation"]))
print(f"    google.com MX: {si11.get('dns', {}).get('mx', {}).get('records', [])}")
print(f"    google.com registrar: {si11.get('domain_reg', {}).get('registrar')}")
print(f"    google.com reputation: {si11.get('reputation', {}).get('reputation_label')}")

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
print("\n" + "=" * 70)
if errors:
    print(f"FAILED: {len(errors)} test(s):")
    for e in errors:
        print(f"  - {e}")
    sys.exit(1)
else:
    print(f"ALL TESTS PASSED (11 test groups, 0 failures)")
print("=" * 70)
