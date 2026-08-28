"""
MailSentinel v2 - Unified Zero-Dependency Cyber-Forensics & Email Threat Platform
Role: Senior Cyber-Security System Architect
Unified FastAPI + SQLite + Embedded Multi-Page Cyber-Forensics Dashboard
"""

import hashlib
import html
import io
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser, Parser
from email.utils import parseaddr
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Database Layer (SQLite)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "forensics.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            confidence INTEGER NOT NULL,
            threat TEXT NOT NULL,
            subject TEXT,
            sender_display TEXT,
            sender_address TEXT,
            sender_domain TEXT,
            reply_to TEXT,
            return_path TEXT,
            evidence_sha256 TEXT NOT NULL,
            raw_result TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id TEXT NOT NULL,
            kind TEXT NOT NULL,
            value TEXT NOT NULL,
            flags TEXT,
            FOREIGN KEY (case_id) REFERENCES cases(case_id) ON DELETE CASCADE
        )
    """)
    conn.commit()
    conn.close()

def save_case_to_db(case_data: dict):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO cases (
                case_id, created_at, risk_score, risk_level, confidence,
                threat, subject, sender_display, sender_address, sender_domain,
                reply_to, return_path, evidence_sha256, raw_result
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            case_data.get('case_id'),
            datetime.now(timezone.utc).isoformat(),
            case_data.get('risk_score', 0),
            case_data.get('risk_level', 'Unknown'),
            case_data.get('confidence', 0),
            case_data.get('threat', ''),
            case_data.get('subject', ''),
            case_data.get('sender', {}).get('display_name', ''),
            case_data.get('sender', {}).get('address', ''),
            case_data.get('sender', {}).get('domain', ''),
            case_data.get('reply_to', ''),
            case_data.get('return_path', ''),
            case_data.get('evidence_sha256', ''),
            json.dumps(case_data)
        ))
        for u in case_data.get('url_details', []):
            cursor.execute("INSERT INTO indicators (case_id, kind, value, flags) VALUES (?, ?, ?, ?)",
                           (case_data.get('case_id'), 'URL', u.get('url', ''), ','.join(u.get('flags', []))))
        for ip in case_data.get('relay_ips', []):
            cursor.execute("INSERT INTO indicators (case_id, kind, value, flags) VALUES (?, ?, ?, ?)",
                           (case_data.get('case_id'), 'IP', ip, 'relay'))
        for a in case_data.get('attachments', []):
            cursor.execute("INSERT INTO indicators (case_id, kind, value, flags) VALUES (?, ?, ?, ?)",
                           (case_data.get('case_id'), 'ATTACHMENT', a.get('filename', ''), a.get('sha256', '')))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB Error] Failed to persist case: {e}")

def get_all_cases():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT case_id, created_at, risk_score, risk_level, confidence, threat, subject, sender_address, evidence_sha256
        FROM cases ORDER BY created_at DESC LIMIT 100
    """)
    rows = cursor.fetchall()
    conn.close()
    return [{
        'case_id': r[0],
        'created_at': r[1],
        'risk_score': r[2],
        'risk_level': r[3],
        'confidence': r[4],
        'threat': r[5],
        'subject': r[6],
        'sender_address': r[7],
        'evidence_sha256': r[8]
    } for r in rows]

def get_case_by_id(case_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT raw_result FROM cases WHERE case_id = ?", (case_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return json.loads(row[0])
    return None

def delete_case_from_db(case_id: str):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM indicators WHERE case_id = ?", (case_id,))
    cursor.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
    conn.commit()
    conn.close()

# ---------------------------------------------------------------------------
# Forensic Threat Engine
# ---------------------------------------------------------------------------
MAX_FILE = 10 * 1024 * 1024
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URGENCY = re.compile(r'\b(urgent|immediately|act now|verify|suspend|suspended|final warning|expire|expires|limited time|confirm|action required|security alert|unauthorized|breach|locked|restricted)\b', re.I)
CREDENTIAL = re.compile(r'\b(password|otp|one[- ]time password|login|sign in|verify your account|credentials|passcode|token|2fa|mfa|reset password|secret code)\b', re.I)
FINANCIAL = re.compile(r'\b(invoice|payment|bank|account number|wire|transfer|refund|gift card|crypto|upi|bitcoin|wallet|transaction|billing|overdue|remittance)\b', re.I)
ATTACHMENT_RISK = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.hta', '.jar', '.iso', '.img', '.lnk', '.wsf', '.docm', '.xlsm'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly'}

def domain(addr):
    return addr.rsplit('@', 1)[-1].lower() if '@' in addr else ''

def parse_auth(msg):
    raw = ' '.join(msg.get_all('Authentication-Results', []) + msg.get_all('Received-SPF', []) + msg.get_all('ARC-Authentication-Results', []))
    out = {}
    for key in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'\b{key}=(pass|fail|softfail|neutral|none|temperror|permerror)\b', raw, re.I)
        out[key] = m.group(1).lower() if m else 'unknown'
    return out

def extract_urls(text):
    urls = set(URL_RE.findall(text or ''))
    return sorted(u.rstrip(').,;]') for u in urls)

def visible_link_mismatches(html_body):
    findings = []
    for href, label in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body or '', re.I | re.S):
        label_text = re.sub(r'<[^>]+>', ' ', label).strip()
        if label_text and re.match(r'https?://', label_text, re.I) and label_text.rstrip('/') != href.rstrip('/'):
            findings.append({'visible': label_text, 'actual': href})
    return findings

def score_email(msg, body, html_body):
    findings = []
    score = 0
    auth = parse_auth(msg)
    auth_bad = sum(1 for v in auth.values() if v in {'fail', 'softfail', 'permerror'})
    if auth_bad:
        add = min(30, auth_bad * 10)
        score += add
        findings.append({'category': 'Authentication', 'points': add, 'evidence': f'SPF/DKIM/DMARC failures: {auth_bad}'})
    
    from_addr = parseaddr(msg.get('From', ''))[1]
    reply_addr = parseaddr(msg.get('Reply-To', ''))[1]
    return_addr = parseaddr(msg.get('Return-Path', ''))[1].strip('<>')

    if reply_addr and from_addr and domain(reply_addr) != domain(from_addr):
        score += 15
        findings.append({'category': 'Sender / Identity', 'points': 15, 'evidence': f'Reply-To domain ({domain(reply_addr)}) differs from From domain ({domain(from_addr)})'})
    if return_addr and from_addr and domain(return_addr) != domain(from_addr):
        score += 8
        findings.append({'category': 'Sender / Identity', 'points': 8, 'evidence': f'Return-Path domain ({domain(return_addr)}) differs from From domain ({domain(from_addr)})'})
    
    subject = msg.get('Subject', '')
    text = (subject + '\n' + body).strip()
    if URGENCY.search(text):
        score += 8
        findings.append({'category': 'AI / Social Engineering', 'points': 8, 'evidence': 'Psychological urgency or coercion triggers detected'})
    if CREDENTIAL.search(text):
        score += 8
        findings.append({'category': 'AI / Social Engineering', 'points': 8, 'evidence': 'Credential harvesting & account login keywords detected'})
    if FINANCIAL.search(text):
        score += 6
        findings.append({'category': 'AI / Social Engineering', 'points': 6, 'evidence': 'Financial transaction, invoice, or wire manipulation phrasing detected'})
    
    urls = extract_urls(body + '\n' + html_body)
    mismatch = visible_link_mismatches(html_body)
    if mismatch:
        score += min(20, 10 * len(mismatch))
        findings.append({'category': 'URL Forensics', 'points': min(20, 10 * len(mismatch)), 'evidence': f'Visible anchor text misdirects to different actual link ({len(mismatch)} detected)'})
    
    url_details = []
    for u in urls:
        p = urlparse(u)
        host = (p.hostname or '').lower()
        flags = []
        if host in SHORTENERS: flags.append('shortener')
        if IP_RE.fullmatch(host or ''): flags.append('ip-literal')
        if host.startswith('xn--') or 'xn--' in host: flags.append('punycode')
        if '@' in p.netloc: flags.append('userinfo-in-url')
        if flags:
            score += min(8, len(flags) * 4)
            findings.append({'category': 'URL Forensics', 'points': min(8, len(flags) * 4), 'evidence': f'Suspicious URL host structure ({host}): {", ".join(flags)}'})
        url_details.append({'url': u, 'host': host, 'flags': flags})
    
    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            name = part.get_filename() or 'unnamed'
            payload = part.get_payload(decode=True) or b''
            ext = '.' + name.rsplit('.', 1)[-1].lower() if '.' in name else ''
            item = {'filename': name, 'size': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(), 'risk': ext in ATTACHMENT_RISK}
            attachments.append(item)
            if item['risk']:
                score += 12
                findings.append({'category': 'Attachment Security', 'points': 12, 'evidence': f'High-risk executable/script attachment payload: {ext} ({name})'})
    
    score = min(100, score)
    level = 'Low' if score <= 25 else 'Moderate' if score <= 50 else 'Suspicious' if score <= 75 else 'High Risk'
    confidence = min(100, 40 + len(findings) * 7)
    return score, level, confidence, findings, url_details, attachments, auth

def analyze(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain = []
    html_parts = []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart': continue
        if part.get_content_disposition() == 'attachment': continue
        try: content = part.get_content()
        except Exception: content = ''
        if part.get_content_type() == 'text/html': html_parts.append(content)
        elif part.get_content_type() == 'text/plain': plain.append(content)
    
    body = '\n'.join(plain)
    html_body = '\n'.join(html_parts)
    score, level, confidence, findings, urls, attachments, auth = score_email(msg, body, html_body)
    
    received = msg.get_all('Received', [])
    relay_ips = []
    for r in received:
        relay_ips.extend(IP_RE.findall(r))
    relay_ips = list(dict.fromkeys(relay_ips))
    
    sender = parseaddr(msg.get('From', ''))
    
    case_res = {
        'case_id': 'CASE-' + uuid.uuid4().hex[:8].upper(),
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'created_at': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'risk_score': score,
        'risk_level': level,
        'confidence': confidence,
        'threat': 'Potential Phishing / Malicious Spoofing' if score >= 51 else 'Low / Benign Communication',
        'sender': {'display_name': sender[0], 'address': sender[1], 'domain': domain(sender[1])},
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'message_id': msg.get('Message-ID', ''),
        'authentication': auth,
        'received_count': len(received),
        'relay_ips': relay_ips,
        'urls': urls,
        'url_details': urls,
        'attachments': attachments,
        'findings': findings,
        'evidence_sha256': hashlib.sha256(raw).hexdigest(),
        'body_preview': (body or html_body)[:600] + ('...' if len(body or html_body) > 600 else ''),
        'limitations': [
            'Forensic analysis executed in zero-fetch sandbox mode (no external phishing links are actively visited).',
            'IP relay locations represent infrastructure route hops, not verified physical threat actor coordinates.',
            'SPF/DKIM/DMARC evaluations reflect cryptographic verification headers present in the provided evidence record.'
        ]
    }
    save_case_to_db(case_res)
    return case_res

def analyze_raw_text(text: str):
    return analyze(text.encode('utf-8'))

def analyze_pdf(raw: bytes):
    if not PYPDF_AVAILABLE:
        raise HTTPException(500, 'PDF processing module (pypdf) is not available.')
    reader = pypdf.PdfReader(io.BytesIO(raw))
    pages_text = []
    pdf_links = []
    for page in reader.pages:
        txt = page.extract_text() or ''
        pages_text.append(txt)
        if "/Annots" in page:
            try:
                for annot in page["/Annots"]:
                    obj = annot.get_object() if hasattr(annot, 'get_object') else annot
                    if isinstance(obj, dict) and "/A" in obj:
                        action = obj["/A"]
                        if isinstance(action, dict) and "/URI" in action:
                            pdf_links.append(str(action["/URI"]))
            except Exception:
                pass
    full_text = "\n".join(pages_text)
    
    from_match = re.search(r'(?:^|\n)\s*From:\s*(.+)', full_text, re.I)
    reply_match = re.search(r'(?:^|\n)\s*Reply-To:\s*(.+)', full_text, re.I)
    subject_match = re.search(r'(?:^|\n)\s*Subject:\s*(.+)', full_text, re.I)
    date_match = re.search(r'(?:^|\n)\s*Date:\s*(.+)', full_text, re.I)

    meta = reader.metadata or {}
    subject = subject_match.group(1).strip() if subject_match else str(meta.get('/Subject', '') or '')
    raw_from = from_match.group(1).strip() if from_match else str(meta.get('/Author', '') or '')
    reply_to = reply_match.group(1).strip() if reply_match else ''
    date_val = date_match.group(1).strip() if date_match else str(meta.get('/CreationDate', '') or '')

    sender = parseaddr(raw_from)
    from_addr = sender[1]
    reply_addr = parseaddr(reply_to)[1]

    findings = []
    score = 0

    auth = {}
    for key in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'\b{key}=(pass|fail|softfail|neutral|none|temperror|permerror)\b', full_text, re.I)
        auth[key] = m.group(1).lower() if m else 'unknown'

    auth_bad = sum(1 for v in auth.values() if v in {'fail', 'softfail', 'permerror'})
    if auth_bad:
        add = min(30, auth_bad * 10)
        score += add
        findings.append({'category': 'Authentication', 'points': add, 'evidence': f'SPF/DKIM/DMARC failures noted in text: {auth_bad}'})

    if reply_addr and from_addr and domain(reply_addr) != domain(from_addr):
        score += 15
        findings.append({'category': 'Sender / Identity', 'points': 15, 'evidence': f'Reply-To domain ({domain(reply_addr)}) differs from From domain ({domain(from_addr)})'})

    if URGENCY.search(full_text):
        score += 8
        findings.append({'category': 'AI / Social Engineering', 'points': 8, 'evidence': 'Psychological urgency or coercion triggers detected'})
    if CREDENTIAL.search(full_text):
        score += 8
        findings.append({'category': 'AI / Social Engineering', 'points': 8, 'evidence': 'Credential harvesting & account login keywords detected'})
    if FINANCIAL.search(full_text):
        score += 6
        findings.append({'category': 'AI / Social Engineering', 'points': 6, 'evidence': 'Financial transaction or wire phrasing detected'})

    found_urls = set(URL_RE.findall(full_text)).union(set(pdf_links))
    cleaned_urls = sorted(u.rstrip(').,;]') for u in found_urls)
    url_details = []
    for u in cleaned_urls:
        p = urlparse(u)
        host = (p.hostname or '').lower()
        flags = []
        if host in SHORTENERS: flags.append('shortener')
        if IP_RE.fullmatch(host or ''): flags.append('ip-literal')
        if host.startswith('xn--') or 'xn--' in host: flags.append('punycode')
        if '@' in p.netloc: flags.append('userinfo-in-url')
        if flags:
            score += min(8, len(flags) * 4)
            findings.append({'category': 'URL Forensics', 'points': min(8, len(flags) * 4), 'evidence': f'Suspicious host: {host} ({", ".join(flags)})'})
        url_details.append({'url': u, 'host': host, 'flags': flags})

    attachments = []
    try:
        if hasattr(reader, "attachments") and reader.attachments:
            for name, file_datas in reader.attachments.items():
                items_list = file_datas if isinstance(file_datas, list) else [file_datas]
                for payload in items_list:
                    data_bytes = bytes(payload) if not isinstance(payload, bytes) else payload
                    ext = '.' + name.rsplit('.', 1)[-1].lower() if '.' in name else ''
                    item = {'filename': name, 'size': len(data_bytes), 'sha256': hashlib.sha256(data_bytes).hexdigest(), 'risk': ext in ATTACHMENT_RISK}
                    attachments.append(item)
                    if item['risk']:
                        score += 12
                        findings.append({'category': 'Attachment Security', 'points': 12, 'evidence': f'Potentially risky embedded attachment: {ext}'})
    except Exception:
        pass

    relay_ips = list(dict.fromkeys(IP_RE.findall(full_text)))
    score = min(100, score)
    level = 'Low' if score <= 25 else 'Moderate' if score <= 50 else 'Suspicious' if score <= 75 else 'High Risk'
    confidence = min(100, 35 + len(findings) * 7)

    case_res = {
        'case_id': 'CASE-' + uuid.uuid4().hex[:8].upper(),
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'created_at': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'risk_score': score,
        'risk_level': level,
        'confidence': confidence,
        'threat': 'Potential Phishing / Malicious Spoofing' if score >= 51 else 'Low / Benign Communication',
        'sender': {'display_name': sender[0], 'address': sender[1], 'domain': domain(sender[1])},
        'reply_to': reply_to,
        'return_path': '',
        'subject': subject,
        'date': date_val,
        'message_id': '',
        'authentication': auth,
        'received_count': len(relay_ips),
        'relay_ips': relay_ips,
        'urls': url_details,
        'url_details': url_details,
        'attachments': attachments,
        'findings': findings,
        'evidence_sha256': hashlib.sha256(raw).hexdigest(),
        'body_preview': full_text[:600] + ('...' if len(full_text) > 600 else ''),
        'limitations': [
            'Document analyzed from exported PDF artifact. Cryptographic validation headers require original raw .eml RFC 822 format.',
            'Forensic analysis executed in zero-fetch sandbox mode (no external phishing links visited).',
            'IP relay locations represent infrastructure route hops, not physical threat actor coordinates.'
        ]
    }
    save_case_to_db(case_res)
    return case_res

# ---------------------------------------------------------------------------
# FastAPI Application & Unified Dashboard
# ---------------------------------------------------------------------------
app = FastAPI(title="MailSentinel Cyber-Forensics v2", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

init_db()

class RawTextRequest(BaseModel):
    raw_text: str

@app.get("/api/health")
def health():
    return {
        "status": "online",
        "service": "MailSentinel Cyber-Forensics Engine v2",
        "database": "SQLite (forensics.db)",
        "pdf_support": PYPDF_AVAILABLE,
        "mode": "Zero-Dependency Unified Deployment"
    }

@app.post("/api/analyze")
async def api_analyze_upload(file: UploadFile = File(...)):
    filename = (file.filename or '').lower()
    if not (filename.endswith('.eml') or filename.endswith('.pdf')):
        raise HTTPException(400, 'Accepted evidence formats: .eml and .pdf.')
    raw = await file.read()
    if len(raw) > MAX_FILE:
        raise HTTPException(413, 'File exceeds maximum 10 MB forensic upload limit.')
    try:
        if filename.endswith('.pdf'):
            res = analyze_pdf(raw)
        else:
            res = analyze(raw)
        res['original_filename'] = file.filename
        return JSONResponse(res)
    except Exception as e:
        raise HTTPException(422, f'Forensic parsing error: {e}')

@app.post("/api/analyze-raw")
def api_analyze_raw(req: RawTextRequest):
    if not req.raw_text or not req.raw_text.strip():
        raise HTTPException(400, 'Raw email text cannot be empty.')
    try:
        res = analyze_raw_text(req.raw_text)
        res['original_filename'] = 'Live_Pasted_Email.eml'
        return JSONResponse(res)
    except Exception as e:
        raise HTTPException(422, f'Forensic parsing error: {e}')

@app.get("/api/cases")
def api_get_cases():
    return JSONResponse(get_all_cases())

@app.get("/api/cases/{case_id}")
def api_get_case(case_id: str):
    c = get_case_by_id(case_id)
    if not c:
        raise HTTPException(404, 'Case not found')
    return JSONResponse(c)

@app.delete("/api/cases/{case_id}")
def api_delete_case(case_id: str):
    delete_case_from_db(case_id)
    return {"status": "deleted", "case_id": case_id}

# ---------------------------------------------------------------------------
# Embedded Cyber-Forensics Dashboard (HTML/CSS/JS)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailSentinel v2 — Cyber-Forensics & Email Threat Intelligence</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root {
  --bg-main: #060a12;
  --bg-card: rgba(14, 23, 42, 0.78);
  --bg-card-hover: rgba(22, 36, 66, 0.85);
  --bg-input: #0b1329;
  --border-color: rgba(59, 130, 246, 0.2);
  --border-glow: rgba(6, 182, 212, 0.35);
  --cyan: #06b6d4;
  --cyan-glow: #00f0ff;
  --blue: #3b82f6;
  --green: #10b981;
  --amber: #f59e0b;
  --red: #ef4444;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --text-muted: #64748b;
  --radius: 14px;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: 'Inter', system-ui, -apple-system, sans-serif;
  background-color: var(--bg-main);
  background-image: 
    radial-gradient(circle at 15% 15%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
    radial-gradient(circle at 85% 85%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
    linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 40px 40px, 40px 40px;
  color: var(--text-primary);
  min-height: 100vh;
  padding: 24px 20px;
}
.container { max-width: 1240px; margin: 0 auto; }
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 14px 24px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius);
  backdrop-filter: blur(12px);
  margin-bottom: 24px;
}
.brand { display: flex; align-items: center; gap: 14px; }
.logo-icon {
  width: 42px; height: 42px;
  background: linear-gradient(135deg, #06b6d4, #3b82f6);
  border-radius: 10px;
  display: grid; place-items: center;
  font-size: 20px; font-weight: 800; color: white;
  box-shadow: 0 0 20px rgba(6, 182, 212, 0.4);
}
.brand h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.5px; }
.brand p { font-size: 12px; color: var(--cyan); font-weight: 500; }
.nav-tabs { display: flex; gap: 8px; }
.nav-btn {
  background: transparent; border: 1px solid transparent;
  color: var(--text-secondary); padding: 8px 16px; border-radius: 8px;
  font-weight: 600; font-size: 13px; cursor: pointer; transition: all .2s;
}
.nav-btn.active, .nav-btn:hover {
  background: rgba(6, 182, 212, 0.12);
  border-color: var(--border-glow);
  color: var(--cyan-glow);
}
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px; }
.card {
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  border-radius: var(--radius);
  padding: 22px;
  backdrop-filter: blur(12px);
  box-shadow: 0 8px 30px rgba(0,0,0,0.3);
}
.card h2, .card h3 { font-size: 16px; font-weight: 600; margin-bottom: 14px; display: flex; align-items: center; gap: 8px; }
.drop-zone {
  border: 2px dashed var(--border-color);
  border-radius: var(--radius);
  padding: 36px 20px;
  text-align: center;
  cursor: pointer;
  background: rgba(11, 19, 41, 0.4);
  transition: all .25s;
}
.drop-zone:hover, .drop-zone.dragover {
  border-color: var(--cyan);
  background: rgba(6, 182, 212, 0.08);
  box-shadow: 0 0 25px rgba(6, 182, 212, 0.2);
}
.drop-zone input { display: none; }
.drop-zone .icon { font-size: 38px; margin-bottom: 10px; }
.drop-zone p { font-size: 14px; color: var(--text-secondary); margin-bottom: 6px; }
.drop-zone small { font-size: 11px; color: var(--text-muted); }
.tab-content { display: none; }
.tab-content.active { display: block; }
textarea.raw-input {
  width: 100%; height: 180px;
  background: var(--bg-input); border: 1px solid var(--border-color);
  border-radius: 10px; padding: 12px; color: #e2e8f0;
  font-family: 'JetBrains Mono', monospace; font-size: 12px;
  resize: vertical; outline: none; margin-bottom: 12px;
}
textarea.raw-input:focus { border-color: var(--cyan); box-shadow: 0 0 15px rgba(6,182,212,0.25); }
.btn-primary {
  width: 100%; background: linear-gradient(135deg, #0284c7, #06b6d4);
  color: white; border: none; padding: 13px; border-radius: 10px;
  font-weight: 700; font-size: 14px; cursor: pointer;
  transition: all .2s; box-shadow: 0 4px 18px rgba(6, 182, 212, 0.3);
}
.btn-primary:hover { filter: brightness(1.15); box-shadow: 0 0 25px rgba(6, 182, 212, 0.5); }
.btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
.sample-bar { display: flex; gap: 8px; margin-top: 14px; align-items: center; }
.sample-bar span { font-size: 12px; color: var(--text-muted); }
.btn-pill {
  background: rgba(255,255,255,0.06); border: 1px solid var(--border-color);
  color: var(--text-secondary); padding: 5px 12px; border-radius: 999px;
  font-size: 11px; cursor: pointer; transition: all .2s;
}
.btn-pill:hover { border-color: var(--cyan); color: var(--cyan); background: rgba(6,182,212,0.1); }
.score-banner {
  display: grid; grid-template-columns: 1fr 1fr;
  background: linear-gradient(135deg, rgba(15,23,42,0.9), rgba(11,19,41,0.9));
  border: 1px solid var(--border-color); border-radius: var(--radius);
  padding: 24px; margin-bottom: 20px; text-align: center; gap: 20px;
}
.score-banner.high { border-color: var(--red); box-shadow: 0 0 30px rgba(239, 68, 68, 0.25); }
.score-banner.suspicious { border-color: var(--amber); box-shadow: 0 0 30px rgba(245, 158, 11, 0.25); }
.score-banner.moderate { border-color: #eab308; box-shadow: 0 0 30px rgba(234, 179, 8, 0.25); }
.score-banner.low { border-color: var(--green); box-shadow: 0 0 30px rgba(16, 185, 129, 0.25); }
.score-num { font-size: 48px; font-weight: 800; letter-spacing: -1px; }
.score-banner.high .score-num { color: var(--red); }
.score-banner.suspicious .score-num { color: var(--amber); }
.score-banner.moderate .score-num { color: #eab308; }
.score-banner.low .score-num { color: var(--green); }
.score-label { font-size: 13px; text-transform: uppercase; font-weight: 700; letter-spacing: 1px; color: var(--text-muted); }
.score-subtitle { font-size: 14px; font-weight: 600; margin-top: 4px; }
.chips { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
.chip {
  padding: 6px 12px; border-radius: 8px; font-size: 11px; font-weight: 600;
  background: rgba(255,255,255,0.05); border: 1px solid var(--border-color);
}
.chip.ok { background: rgba(16, 185, 129, 0.15); border-color: var(--green); color: #34d399; }
.chip.bad { background: rgba(239, 68, 68, 0.15); border-color: var(--red); color: #f87171; }
.meta-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.meta-table td { padding: 8px 6px; border-bottom: 1px solid rgba(255,255,255,0.05); }
.meta-table td.key { color: var(--text-muted); width: 120px; font-weight: 500; }
.meta-table td.val { color: var(--text-primary); word-break: break-all; }
code { font-family: 'JetBrains Mono', monospace; font-size: 12px; color: var(--cyan); }
.finding-item {
  padding: 12px; border-radius: 10px; background: rgba(11, 19, 41, 0.6);
  border-left: 4px solid var(--cyan); margin-bottom: 10px; display: grid; gap: 4px;
}
.finding-item.high { border-left-color: var(--red); }
.finding-item.amber { border-left-color: var(--amber); }
.finding-head { display: flex; justify-content: space-between; font-size: 13px; font-weight: 600; }
.finding-desc { font-size: 12px; color: var(--text-secondary); }
.ioc-tag { display: inline-block; padding: 2px 6px; border-radius: 4px; font-size: 10px; font-weight: 600; margin-left: 6px; background: rgba(245,158,11,0.2); color: var(--amber); }
.case-row {
  display: grid; grid-template-columns: 140px 1fr 100px 100px 100px;
  padding: 12px; border-radius: 8px; background: rgba(11,19,41,0.5);
  border: 1px solid var(--border-color); margin-bottom: 8px; align-items: center; font-size: 13px;
}
.case-row:hover { background: rgba(22, 36, 66, 0.7); }
.badge-pill { padding: 4px 10px; border-radius: 999px; font-size: 11px; font-weight: 700; text-align: center; }
.badge-pill.high { background: rgba(239,68,68,0.2); color: var(--red); border: 1px solid var(--red); }
.badge-pill.suspicious { background: rgba(245,158,11,0.2); color: var(--amber); border: 1px solid var(--amber); }
.badge-pill.moderate { background: rgba(234,179,8,0.2); color: #eab308; border: 1px solid #eab308; }
.badge-pill.low { background: rgba(16,185,129,0.2); color: var(--green); border: 1px solid var(--green); }
.spinner {
  display: inline-block; width: 16px; height: 16px;
  border: 2px solid rgba(255,255,255,0.3); border-top-color: white;
  border-radius: 50%; animation: spin 0.8s linear infinite; margin-right: 8px;
}
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 860px) {
  .grid-2, .grid-3 { grid-template-columns: 1fr; }
  .score-banner { grid-template-columns: 1fr; }
  header { flex-direction: column; gap: 14px; align-items: flex-start; }
}
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">
      <div class="logo-icon">🛡️</div>
      <div>
        <h1>MailSentinel v2</h1>
        <p>Cyber-Forensics & Email Threat Intelligence Platform</p>
      </div>
    </div>
    <div class="nav-tabs">
      <button class="nav-btn active" onclick="showTab('analyzer')">⚡ Threat Analyzer</button>
      <button class="nav-btn" onclick="showTab('ledger')">🗄️ SQLite Case Ledger</button>
      <button class="nav-btn" onclick="showTab('docs')">📖 Architecture Docs</button>
    </div>
  </header>

  <!-- TAB 1: THREAT ANALYZER -->
  <div id="tab-analyzer" class="tab-content active">
    <div class="grid-2">
      <!-- Input Panel -->
      <div class="card">
        <h2>📥 Email Evidence Ingestion</h2>
        <div style="display:flex; gap:8px; margin-bottom:14px;">
          <button id="btn-mode-file" class="btn-pill" style="border-color:var(--cyan); color:var(--cyan);" onclick="switchInputMode('file')">📂 File Upload (.eml / .pdf)</button>
          <button id="btn-mode-raw" class="btn-pill" onclick="switchInputMode('raw')">📝 Paste Raw Email Text</button>
        </div>

        <div id="panel-file">
          <div id="drop-zone" class="drop-zone" onclick="document.getElementById('file-input').click()">
            <input type="file" id="file-input" accept=".eml,message/rfc822,.pdf,application/pdf">
            <div class="icon">📁</div>
            <p id="drop-label"><b>Drag & Drop .eml or .pdf file here</b></p>
            <small>Or click to browse from your computer (Up to 10 MB)</small>
          </div>
        </div>

        <div id="panel-raw" style="display:none;">
          <textarea id="raw-text-input" class="raw-input" placeholder="Paste full RFC 822 email headers and body here...&#10;&#10;From: Bank Security <security@fake-bank.com>&#10;Subject: Urgent Security Alert&#10;Authentication-Results: mx; spf=fail; dkim=fail&#10;&#10;Click here to verify: http://192.168.1.100/login"></textarea>
        </div>

        <div style="margin-top:16px;">
          <button id="btn-run-analysis" class="btn-primary" onclick="performAnalysis()">🔍 Execute Forensic Analysis</button>
        </div>

        <div class="sample-bar">
          <span>Quick load sample:</span>
          <button class="btn-pill" onclick="loadSample('phish')">🚨 Phishing Attack</button>
          <button class="btn-pill" onclick="loadSample('clean')">✅ Clean Newsletter</button>
        </div>
      </div>

      <!-- Quick Intel Panel -->
      <div class="card">
        <h2>🔬 Defense Engine Status</h2>
        <table class="meta-table">
          <tr><td class="key">Deployment</td><td class="val">Zero-Dependency Unified Python + SQLite</td></tr>
          <tr><td class="key">Parser Suite</td><td class="val">RFC 822 (Standard) & PDF Binary Extractor</td></tr>
          <tr><td class="key">Risk Matrix</td><td class="val">0–100 Explainable Weighted Heuristics</td></tr>
          <tr><td class="key">Sandbox Policy</td><td class="val"><span style="color:var(--green)">100% Zero-Fetch (Safe Inspection)</span></td></tr>
          <tr><td class="key">Storage Engine</td><td class="val"><code>forensics.db</code> (SQLite Relational Ledger)</td></tr>
        </table>
        <div style="margin-top:18px; padding:12px; background:rgba(6,182,212,0.06); border:1px solid rgba(6,182,212,0.2); border-radius:10px; font-size:12px; color:var(--text-secondary);">
          💡 <b>How it works:</b> Drag an email or paste headers. The engine performs RFC 822 decoding, cryptographic authentication inspection, visible-vs-actual URL mismatch detection, and relay hop tracking in real-time.
        </div>
      </div>
    </div>

    <!-- Results Section -->
    <div id="results-area" style="display:none;">
      <div id="score-banner" class="score-banner">
        <div>
          <div class="score-label">FORENSIC RISK LEVEL</div>
          <div id="risk-score-num" class="score-num">0/100</div>
          <div id="risk-level-title" class="score-subtitle">Low Risk</div>
        </div>
        <div>
          <div class="score-label">EVIDENCE CONFIDENCE</div>
          <div id="confidence-num" class="score-num" style="color:var(--cyan)">0%</div>
          <div id="threat-summary" class="score-subtitle">Deterministic Pattern Support</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <h3>👤 Identity & Header Alignment</h3>
          <table class="meta-table">
            <tr><td class="key">Case ID</td><td class="val"><code id="res-case-id"></code></td></tr>
            <tr><td class="key">Evidence Hash</td><td class="val"><code id="res-sha256"></code></td></tr>
            <tr><td class="key">From</td><td class="val" id="res-from"></td></tr>
            <tr><td class="key">Reply-To</td><td class="val" id="res-reply"></td></tr>
            <tr><td class="key">Subject</td><td class="val" id="res-subject"></td></tr>
            <tr><td class="key">Date</td><td class="val" id="res-date"></td></tr>
          </table>
          <div class="chips" id="res-auth-chips"></div>
        </div>

        <div class="card">
          <h3>🌐 Relay Route & Infrastructure</h3>
          <p style="font-size:13px; color:var(--text-secondary); margin-bottom:10px;">
            Observed Relay Count: <b id="res-relay-count" style="color:var(--text-primary)">0</b>
          </p>
          <div id="res-relay-path" style="padding:10px; background:rgba(11,19,41,0.6); border-radius:8px; font-family:'JetBrains Mono',monospace; font-size:12px; color:var(--cyan); word-break:break-all; min-height:40px;">
            No external relay hops observed
          </div>
          <h3 style="margin-top:18px;">📎 Attachments (<span id="res-attach-count">0</span>)</h3>
          <div id="res-attach-list" style="font-size:12px; color:var(--text-secondary);">None</div>
        </div>
      </div>

      <div class="grid-2">
        <div class="card">
          <h3>🔗 Extracted URLs & Indicators (<span id="res-url-count">0</span>)</h3>
          <div id="res-url-list" style="max-height:240px; overflow-y:auto; display:grid; gap:8px;"></div>
        </div>

        <div class="card">
          <h3>📋 Weighted Forensic Findings</h3>
          <div id="res-findings-list" style="max-height:240px; overflow-y:auto;"></div>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 2: SQLITE CASE LEDGER -->
  <div id="tab-ledger" class="tab-content">
    <div class="card">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:16px;">
        <h2>🗄️ SQLite Forensic Case Ledger (forensics.db)</h2>
        <button class="btn-pill" onclick="loadCaseLedger()">🔄 Refresh Cases</button>
      </div>
      <div style="overflow-x:auto;">
        <div style="display:grid; grid-template-columns:140px 1fr 100px 100px 120px; padding:10px 12px; font-size:12px; font-weight:700; color:var(--text-muted); text-transform:uppercase; border-bottom:1px solid var(--border-color);">
          <div>Case ID</div>
          <div>Subject & Sender</div>
          <div>Risk Score</div>
          <div>Confidence</div>
          <div>Actions</div>
        </div>
        <div id="ledger-rows" style="margin-top:8px;">
          <p style="padding:20px; text-align:center; color:var(--text-muted);">Loading forensic ledger...</p>
        </div>
      </div>
    </div>
  </div>

  <!-- TAB 3: ARCHITECTURE DOCS -->
  <div id="tab-docs" class="tab-content">
    <div class="card">
      <h2>📖 MailSentinel v2 Architectural Blueprint</h2>
      <div style="font-size:14px; line-height:1.7; color:var(--text-secondary);">
        <p><b>Unified Deployment:</b> Built as an all-in-one Zero-Dependency FastAPI backend with an embedded cyber-defense UI and persistent SQLite database.</p>
        <br>
        <p><b>Risk Calculation Formula:</b></p>
        <ul style="margin-left:24px;">
          <li><b>Authentication Failure:</b> +10 pts per SPF/DKIM/DMARC failure (max 30 pts)</li>
          <li><b>Domain Spoofing:</b> +15 pts for Reply-To domain mismatch</li>
          <li><b>Social Engineering:</b> +8 pts for urgency cues, +8 pts for credential harvesting, +6 pts for financial triggers</li>
          <li><b>URL Threats:</b> +10 pts per visible-vs-actual anchor mismatch; +4 pts per IP-literal / punycode / shortener flag</li>
          <li><b>Dangerous Attachments:</b> +12 pts for executable/script payload types</li>
        </ul>
      </div>
    </div>
  </div>
</div>

<script>
let currentMode = 'file';
let selectedFile = null;

function showTab(tab) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + tab).classList.add('active');
  event.target.classList.add('active');
  if (tab === 'ledger') loadCaseLedger();
}

function switchInputMode(mode) {
  currentMode = mode;
  document.getElementById('panel-file').style.display = mode === 'file' ? 'block' : 'none';
  document.getElementById('panel-raw').style.display = mode === 'raw' ? 'block' : 'none';
  document.getElementById('btn-mode-file').style.borderColor = mode === 'file' ? 'var(--cyan)' : 'var(--border-color)';
  document.getElementById('btn-mode-file').style.color = mode === 'file' ? 'var(--cyan)' : 'var(--text-secondary)';
  document.getElementById('btn-mode-raw').style.borderColor = mode === 'raw' ? 'var(--cyan)' : 'var(--border-color)';
  document.getElementById('btn-mode-raw').style.color = mode === 'raw' ? 'var(--cyan)' : 'var(--text-secondary)';
}

const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');

['dragenter', 'dragover'].forEach(name => {
  dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
});
['dragleave', 'drop'].forEach(name => {
  dropZone.addEventListener(name, (e) => { e.preventDefault(); dropZone.classList.remove('dragover'); });
});
dropZone.addEventListener('drop', (e) => {
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    selectedFile = e.dataTransfer.files[0];
    document.getElementById('drop-label').innerHTML = `<b>Selected:</b> ${selectedFile.name}`;
  }
});
fileInput.addEventListener('change', () => {
  if (fileInput.files && fileInput.files[0]) {
    selectedFile = fileInput.files[0];
    document.getElementById('drop-label').innerHTML = `<b>Selected:</b> ${selectedFile.name}`;
  }
});

async function performAnalysis() {
  const btn = document.getElementById('btn-run-analysis');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Analyzing Threat Vectors...';

  try {
    let res;
    if (currentMode === 'file') {
      if (!selectedFile) throw new Error('Please select or drag an .eml or .pdf file first.');
      const fd = new FormData();
      fd.append('file', selectedFile);
      const r = await fetch('/api/analyze', { method: 'POST', body: fd });
      res = await r.json();
      if (!r.ok) throw new Error(res.detail || 'Analysis failed');
    } else {
      const text = document.getElementById('raw-text-input').value;
      if (!text.trim()) throw new Error('Please paste raw email headers and text first.');
      const r = await fetch('/api/analyze-raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_text: text })
      });
      res = await r.json();
      if (!r.ok) throw new Error(res.detail || 'Analysis failed');
    }
    renderResults(res);
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '🔍 Execute Forensic Analysis';
  }
}

function renderResults(d) {
  document.getElementById('results-area').style.display = 'block';
  const banner = document.getElementById('score-banner');
  banner.className = 'score-banner ' + (d.risk_level === 'High Risk' ? 'high' : d.risk_level === 'Suspicious' ? 'suspicious' : d.risk_level === 'Moderate' ? 'moderate' : 'low');
  document.getElementById('risk-score-num').textContent = `${d.risk_score}/100`;
  document.getElementById('risk-level-title').textContent = d.risk_level;
  document.getElementById('confidence-num').textContent = `${d.confidence}%`;
  document.getElementById('threat-summary').textContent = d.threat;

  document.getElementById('res-case-id').textContent = d.case_id;
  document.getElementById('res-sha256').textContent = d.evidence_sha256;
  document.getElementById('res-from').textContent = `${d.sender.display_name || ''} <${d.sender.address || 'Unknown'}>`;
  document.getElementById('res-reply').textContent = d.reply_to || 'None specified';
  document.getElementById('res-subject').textContent = d.subject || 'No subject';
  document.getElementById('res-date').textContent = d.date || 'N/A';

  const authDiv = document.getElementById('res-auth-chips');
  authDiv.innerHTML = Object.entries(d.authentication).map(([k, v]) => `
    <span class="chip ${v === 'pass' ? 'ok' : v === 'fail' ? 'bad' : ''}">${k.toUpperCase()}: ${v}</span>
  `).join('');

  document.getElementById('res-relay-count').textContent = d.received_count;
  document.getElementById('res-relay-path').innerHTML = d.relay_ips.length ? d.relay_ips.join(' &rarr; ') : 'No external relay hops observed';

  document.getElementById('res-attach-count').textContent = d.attachments.length;
  document.getElementById('res-attach-list').innerHTML = d.attachments.length ? d.attachments.map(a => `
    <div style="padding:6px 0; border-bottom:1px solid rgba(255,255,255,0.05);">
      <b>${a.filename}</b> (${a.size} B) &mdash; SHA256: <code>${a.sha256.substring(0,16)}...</code> ${a.risk ? '<span class="ioc-tag" style="background:rgba(239,68,68,0.2); color:var(--red);">RISKY EXTENSION</span>' : ''}
    </div>
  `).join('') : 'No attachments detected';

  document.getElementById('res-url-count').textContent = d.url_details.length;
  document.getElementById('res-url-list').innerHTML = d.url_details.length ? d.url_details.map(u => `
    <div style="padding:8px; background:rgba(11,19,41,0.5); border-radius:6px; font-size:12px;">
      <code>${u.url}</code>
      ${u.flags.map(f => `<span class="ioc-tag">${f}</span>`).join('')}
    </div>
  `).join('') : '<p style="color:var(--text-muted); font-size:12px;">No URLs found in email body.</p>';

  document.getElementById('res-findings-list').innerHTML = d.findings.length ? d.findings.map(f => `
    <div class="finding-item ${f.points >= 15 ? 'high' : f.points >= 8 ? 'amber' : ''}">
      <div class="finding-head">
        <span>${f.category}</span>
        <span style="color:var(--cyan)">+${f.points} pts</span>
      </div>
      <div class="finding-desc">${f.evidence}</div>
    </div>
  `).join('') : '<p style="color:var(--text-muted); font-size:12px;">No suspicious heuristics triggered.</p>';

  document.getElementById('results-area').scrollIntoView({ behavior: 'smooth' });
}

async function loadCaseLedger() {
  const container = document.getElementById('ledger-rows');
  container.innerHTML = '<p style="padding:20px; text-align:center; color:var(--text-muted);">Loading forensic ledger...</p>';
  try {
    const r = await fetch('/api/cases');
    const cases = await r.json();
    if (!cases.length) {
      container.innerHTML = '<p style="padding:20px; text-align:center; color:var(--text-muted);">No cases recorded in SQLite yet. Perform an analysis first.</p>';
      return;
    }
    container.innerHTML = cases.map(c => `
      <div class="case-row">
        <div><code>${c.case_id}</code></div>
        <div>
          <div style="font-weight:600; color:var(--text-primary);">${c.subject || 'Untitled Case'}</div>
          <div style="font-size:11px; color:var(--text-muted);">${c.sender_address || 'No sender'} &bull; ${c.created_at.substring(0,19)}</div>
        </div>
        <div><span class="badge-pill ${c.risk_level === 'High Risk' ? 'high' : c.risk_level === 'Suspicious' ? 'suspicious' : c.risk_level === 'Moderate' ? 'moderate' : 'low'}">${c.risk_score}/100</span></div>
        <div>${c.confidence}%</div>
        <div style="display:flex; gap:6px;">
          <button class="btn-pill" onclick="viewCaseDetail('${c.case_id}')">View</button>
          <button class="btn-pill" style="color:var(--red);" onclick="deleteCase('${c.case_id}')">&times;</button>
        </div>
      </div>
    `).join('');
  } catch (err) {
    container.innerHTML = `<p style="color:var(--red); text-align:center;">Failed to load ledger: ${err.message}</p>`;
  }
}

async function viewCaseDetail(caseId) {
  try {
    const r = await fetch(`/api/cases/${caseId}`);
    const d = await r.json();
    showTab('analyzer');
    renderResults(d);
  } catch (err) {
    alert('Failed to load case: ' + err.message);
  }
}

async function deleteCase(caseId) {
  if (!confirm(`Delete case ${caseId} from SQLite database?`)) return;
  try {
    await fetch(`/api/cases/${caseId}`, { method: 'DELETE' });
    loadCaseLedger();
  } catch (err) {
    alert('Failed to delete case: ' + err.message);
  }
}

function loadSample(type) {
  switchInputMode('raw');
  if (type === 'phish') {
    document.getElementById('raw-text-input').value = `From: Security Alert <security@secure-verify-banking.net>
Reply-To: credential-drop@attacker-box.com
To: victim@target-organization.com
Subject: URGENT: Immediate Account Suspension - Verification Required
Date: Fri, 28 Aug 2026 10:15:00 +0000
Authentication-Results: mx.corp.com; spf=fail; dkim=fail; dmarc=fail
Received: from 198.51.100.42 by mx.corp.com

Dear Client,

We detected unauthorized access attempts on your financial account. You must verify your credentials immediately within 24 hours to prevent permanent account suspension.

Click below to verify:
http://192.168.1.50/login-verify

Regards,
Fraud Prevention Unit`;
  } else {
    document.getElementById('raw-text-input').value = `From: Tech Digest <newsletter@techpulse.org>
Reply-To: newsletter@techpulse.org
To: user@example.com
Subject: Weekly Engineering & Open Source Highlights #88
Date: Fri, 28 Aug 2026 09:00:00 +0000
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=pass
Received: from 203.0.113.19 by mx.corp.com

Hello Engineers!

Here is this week's curated roundup of technology releases and architecture guides.

Check out the full issue: https://techpulse.org/digest/88

Happy coding!`;
  }
}
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return HTMLResponse(DASHBOARD_HTML)

# ---------------------------------------------------------------------------
# Direct Entrypoint Execution
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("==================================================================")
    print("  MailSentinel v2 - Zero-Dependency Unified Deployment")
    print("  Cyber-Forensics Dashboard + FastAPI + SQLite Database")
    print("==================================================================")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
