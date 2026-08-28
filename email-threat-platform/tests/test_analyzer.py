from backend.app.main import analyze, analyze_pdf

def test_basic_phish():
    raw=b'''From: Bank Support <support@fake.example>\nReply-To: thief@evil.example\nSubject: URGENT verify your account immediately\nAuthentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\nContent-Type: text/html; charset=utf-8\n\n<html><body>Login now <a href="https://evil.example/login">https://bank.example/login</a></body></html>'''
    d=analyze(raw)
    assert d['risk_score']>=50
    assert d['authentication']['spf']=='fail'
    assert d['relay_ips']==[]
    assert d['evidence_sha256']

def test_pdf_phish():
    with open('samples/sample_phishing_email.pdf', 'rb') as f:
        d = analyze_pdf(f.read())
    assert d['risk_score'] >= 50
    assert d['authentication']['spf'] == 'fail'
    assert d['sender']['address'] == 'security@update-service-alert.com'
    assert d['evidence_sha256']

