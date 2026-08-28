import urllib.request
import json

print('=== 1. Testing Phishing Sample with Multi-Hop Relay ===')
boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW'
with open('samples/sample_phishing.eml', 'rb') as f:
    data = f.read()

body = (
    b'--' + boundary.encode() + b'\r\n'
    b'Content-Disposition: form-data; name="file"; filename="sample_phishing.eml"\r\n'
    b'Content-Type: message/rfc822\r\n\r\n'
    + data +
    b'\r\n--' + boundary.encode() + b'--\r\n'
)
req = urllib.request.Request('http://127.0.0.1:8000/api/analyze', data=body, headers={'Content-Type': f'multipart/form-data; boundary={boundary}'})
res = json.loads(urllib.request.urlopen(req).read().decode())

print('Case ID:', res.get('case_id'))
print('Risk Score:', res.get('risk_score'), '| Level:', res.get('risk_level'))
print('Relay Hops Extracted:')
for i, hop in enumerate(res.get('relay_geo_hops', [])):
    print(f"  Hop #{i+1}: IP={hop.get('ip')} | IsPrivate={hop.get('is_private')} | Geolocated={hop.get('geolocated')} | City={hop.get('city')}, {hop.get('country')} | Lat/Lon={hop.get('lat')},{hop.get('lon')}")

print('\n=== 2. Testing Simulation Scenario (CEO Spoof with Tokyo & London hops) ===')
spoof_text = """From: John Doe (CEO) <john.doe@attacker-drop.net>
Reply-To: confidential-executive@protonmail-drop.com
To: finance@trusted-corporation.com
Subject: URGENT: Confidential Acquisition Wire Payment
Date: Fri, 28 Aug 2026 14:00:00 +0000
Authentication-Results: mx.trusted-corporation.com; spf=fail; dkim=none; dmarc=fail
Received: from internal-lan (10.0.4.12) by mx.local
Received: from relay.london-hub.co.uk (212.58.244.20) by internal-lan
Received: from mail.tokyo-gateway.jp (133.242.0.1) by relay.london-hub.co.uk

Please wire $45,000 immediately.
CEO"""
payload = json.dumps({'raw_text': spoof_text}).encode()
req = urllib.request.Request('http://127.0.0.1:8000/api/analyze-raw', data=payload, headers={'Content-Type': 'application/json'})
res2 = json.loads(urllib.request.urlopen(req).read().decode())
print('Case ID:', res2.get('case_id'))
print('Relay Hops Extracted:')
for i, hop in enumerate(res2.get('relay_geo_hops', [])):
    print(f"  Hop #{i+1}: IP={hop.get('ip')} | IsPrivate={hop.get('is_private')} | Geolocated={hop.get('geolocated')} | City={hop.get('city')}, {hop.get('country')} | Lat/Lon={hop.get('lat')},{hop.get('lon')}")
