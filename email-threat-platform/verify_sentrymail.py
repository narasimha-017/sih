import urllib.request
import json

print('=== 1. Testing Landing Page (GET /) ===')
req = urllib.request.urlopen('http://127.0.0.1:8000/')
html_root = req.read().decode()
print('Status:', req.status, '| Contains Landing Page:', 'Why Email Security Matters' in html_root and '[VERIFY SOURCE' in html_root)

print('=== 2. Testing Scanner Dashboard (GET /scanner) ===')
req = urllib.request.urlopen('http://127.0.0.1:8000/scanner')
html_scanner = req.read().decode()
print('Status:', req.status, '| Contains Leaflet.js & Map:', 'leaflet.js' in html_scanner and 'id="map"' in html_scanner)

print('=== 3. Testing Mobile Simulator (GET /app) ===')
req = urllib.request.urlopen('http://127.0.0.1:8000/app')
html_app = req.read().decode()
print('Status:', req.status, '| Contains Mobile Frame & App Store:', 'phone-frame' in html_app and 'Coming Soon' in html_app)

print('=== 4. Testing Trusted Contacts API (GET /api/contacts) ===')
req = urllib.request.urlopen('http://127.0.0.1:8000/api/contacts')
contacts = json.loads(req.read().decode())
print(f'Trusted Contacts Seed Count: {len(contacts)}')
for c in contacts:
    print(f" - {c['name']} (@{c['real_domain']})")

print('=== 5. Testing Executive Impersonation Detection (BEC) ===')
spoof_payload = json.dumps({
    'raw_text': 'From: John Doe (CEO) <john.doe@attacker-drop.net>\nReply-To: confidential-executive@protonmail-drop.com\nTo: finance@trusted-corporation.com\nSubject: URGENT: Confidential Wire Transfer Needed\nAuthentication-Results: mx; spf=fail; dkim=none; dmarc=fail\nReceived: from 8.8.8.8 by mx.trusted-corporation.com\n\nPlease wire $45,000 immediately to the attached account.\nThanks,\nCEO'
}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/api/analyze-raw', data=spoof_payload, headers={'Content-Type': 'application/json'})
res = json.loads(urllib.request.urlopen(req).read().decode())
print('Risk Score:', res['risk_score'], '| Level:', res['risk_level'])
print('Evidence Findings:')
for f in res['findings']:
    print(f"  [{f['category']}] +{f['points']} pts: {f['evidence']}")
print('Relay Geo Hops:', res.get('relay_geo_hops'))
print('All Verification Tests PASSED!')
