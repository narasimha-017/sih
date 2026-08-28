"""
MailSentinel v3 - Unified Zero-Dependency Cyber-Forensics & Threat Defense Platform
Role: Lead Cyber-Forensics Architect
Protocol: B.L.A.S.T. / Autopilot

Features:
1. Landing Page (GET /) explaining Phishing, BEC, Spoofing with 3-step workflow
2. Cyber-Forensics Dashboard (GET /scanner) with Leaflet.js Animated Relay Map & Trusted Contacts Manager
3. Impersonation Engine (Trusted Contacts Matching + Static Threat Intelligence Database)
4. Real IP Geolocation via ip-api.com (Private IPs filtered and labeled)
5. Mobile App Interactive Showcase (GET /app) driven by real SQLite database records
"""

import hashlib
import html
import io
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from typing import List, Optional
from urllib.parse import urlparse

import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, create_engine, desc
from sqlalchemy.orm import Session, relationship, sessionmaker, declarative_base

# Ensure local directory is on python path for zero-dependency execution
sys_path_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if sys_path_root not in sys.path:
    sys.path.insert(0, sys_path_root)
local_dir = os.path.dirname(os.path.abspath(__file__))
if local_dir not in sys.path:
    sys.path.insert(0, local_dir)

try:
    from backend.app.threat_intel import check_known_bad, lookup_ip_geo
except ImportError:
    from threat_intel import check_known_bad, lookup_ip_geo

try:
    from backend.app.sender_intelligence.service import run_sender_intelligence, RISK_THRESHOLD
except ImportError:
    try:
        from sender_intelligence.service import run_sender_intelligence, RISK_THRESHOLD
    except ImportError:
        RISK_THRESHOLD = 70
        def run_sender_intelligence(domain, sender_address, risk_score):
            return {"activated": False, "threshold": RISK_THRESHOLD, "error": "sender_intelligence module not found"}


try:
    import pypdf
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ---------------------------------------------------------------------------
# Database Layer (SQLAlchemy ORM + SQLite)
# ---------------------------------------------------------------------------
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentrymail_v3.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class CaseModel(Base):
    __tablename__ = "cases"

    case_id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    risk_score = Column(Integer, nullable=False)
    risk_level = Column(String(32), nullable=False)
    confidence = Column(Integer, nullable=False)
    threat_category = Column(String(128), nullable=False)
    subject = Column(Text, nullable=True)
    sender_display = Column(String(256), nullable=True)
    sender_address = Column(String(256), nullable=True, index=True)
    sender_domain = Column(String(128), nullable=True)
    reply_to = Column(String(256), nullable=True)
    return_path = Column(String(256), nullable=True)
    evidence_sha256 = Column(String(64), nullable=False, index=True)
    raw_json = Column(Text, nullable=False)

    indicators = relationship("IndicatorModel", back_populates="case", cascade="all, delete-orphan")

class IndicatorModel(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(64), ForeignKey("cases.case_id", ondelete="CASCADE"), nullable=False)
    kind = Column(String(32), nullable=False, index=True)
    value = Column(Text, nullable=False)
    flags = Column(String(128), nullable=True)

    case = relationship("CaseModel", back_populates="indicators")

class TrustedContactModel(Base):
    __tablename__ = "trusted_contacts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(128), nullable=False, index=True)
    real_domain = Column(String(128), nullable=False, index=True)
    notes = Column(String(256), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pre-populate sample trusted contacts if empty
def seed_default_contacts():
    db = SessionLocal()
    if db.query(TrustedContactModel).count() == 0:
        sample_contacts = [
            TrustedContactModel(name="John Doe (CEO)", real_domain="trusted-corporation.com", notes="Chief Executive Officer"),
            TrustedContactModel(name="Jane Smith (CFO)", real_domain="trusted-corporation.com", notes="Chief Financial Officer"),
            TrustedContactModel(name="IT Helpdesk", real_domain="trusted-corporation.com", notes="Internal Support Desk"),
            TrustedContactModel(name="Finance Department", real_domain="trusted-corporation.com", notes="Treasury & Wire Operations")
        ]
        db.add_all(sample_contacts)
        db.commit()
    db.close()

seed_default_contacts()

# ---------------------------------------------------------------------------
# Forensic Threat Engine Heuristics
# ---------------------------------------------------------------------------
MAX_FILE_BYTES = 10 * 1024 * 1024
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
# Prefer bracketed IP in Received: headers: "from host (host [1.2.3.4])" or "from host (1.2.3.4)"
# Group 1 = bracketed [IP], Group 2 = bare IP as fallback
RECEIVED_IP_RE = re.compile(r'\[(' + r'(?:\d{1,3}\.){3}\d{1,3}' + r')\]|\b(' + r'(?:\d{1,3}\.){3}\d{1,3}' + r')\b')
URGENCY_RE = re.compile(r'\b(urgent|immediately|act now|verify|suspend|suspended|final warning|expire|expires|limited time|confirm|action required|security alert|unauthorized|breach|locked|restricted|deactivation)\b', re.I)
CREDENTIAL_RE = re.compile(r'\b(password|otp|one[- ]time password|login|sign in|verify your account|credentials|passcode|token|2fa|mfa|reset password|secret code|auth code|banking pin)\b', re.I)
FINANCIAL_RE = re.compile(r'\b(invoice|payment|bank|account number|wire|transfer|refund|gift card|crypto|upi|bitcoin|wallet|transaction|billing|overdue|remittance|swift code|direct deposit)\b', re.I)
EXTORTION_RE = re.compile(r'\b(blackmail|recorded you|ransom|pay bitcoin|compromised webcam|leaked footage|confidential video)\b', re.I)
ATTACHMENT_RISK_EXT = {'.exe', '.scr', '.js', '.vbs', '.bat', '.cmd', '.ps1', '.hta', '.jar', '.iso', '.img', '.lnk', '.wsf', '.docm', '.xlsm', '.dll', '.cpl'}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy', 'rebrand.ly', 't.ly'}

def extract_relay_ips_from_received_headers(received_headers: list) -> list:
    """
    Extract IPs EXCLUSIVELY from Received: header lines.
    Prefers bracketed notation [x.x.x.x] which is the actual MTA IP;
    falls back to bare IPs on the same header line.
    Preserves order and removes duplicates.
    """
    seen = set()
    ordered = []
    for header in received_headers:
        matches = RECEIVED_IP_RE.findall(header)  # returns (bracketed, bare) tuples
        for bracketed, bare in matches:
            ip = (bracketed or bare).strip()
            if ip and ip not in seen:
                seen.add(ip)
                ordered.append(ip)
    return ordered

def extract_relay_ips_from_text(text: str) -> list:
    """
    For plain-text/PDF email content where headers are embedded as text:
    scan ONLY lines beginning with 'Received:' (case-insensitive).
    Prevents IPs in the email body (phishing lure links, etc.) from
    being mistaken for relay hops.
    """
    received_lines = [
        line for line in text.splitlines()
        if line.strip().lower().startswith('received:')
    ]
    return extract_relay_ips_from_received_headers(received_lines)

def get_domain(email_addr: str) -> str:
    return email_addr.rsplit('@', 1)[-1].lower() if '@' in email_addr else ''

def parse_auth_headers(msg) -> dict:
    raw = ' '.join(msg.get_all('Authentication-Results', []) + msg.get_all('Received-SPF', []) + msg.get_all('ARC-Authentication-Results', []))
    auth = {}
    for key in ('spf', 'dkim', 'dmarc'):
        match = re.search(rf'\b{key}=(pass|fail|softfail|neutral|none|temperror|permerror)\b', raw, re.I)
        auth[key] = match.group(1).lower() if match else 'unknown'
    return auth

def extract_urls_from_text(text: str) -> List[str]:
    urls = set(URL_RE.findall(text or ''))
    return sorted(u.rstrip(').,;]') for u in urls)

def find_visible_link_mismatches(html_body: str) -> List[dict]:
    findings = []
    for href, label in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body or '', re.I | re.S):
        label_text = re.sub(r'<[^>]+>', ' ', label).strip()
        if label_text and re.match(r'https?://', label_text, re.I) and label_text.rstrip('/') != href.rstrip('/'):
            findings.append({'visible': label_text, 'actual': href})
    return findings

def check_contact_impersonation(display_name: str, sender_domain: str, db: Session) -> Optional[dict]:
    """Priority 2a: Checks if From Display Name resembles a trusted contact with mismatching domain."""
    if not display_name:
        return None
    contacts = db.query(TrustedContactModel).all()
    d_clean = display_name.lower()
    for c in contacts:
        c_clean = c.name.lower()
        # Check if first/last name words overlap closely
        c_words = [w for w in re.split(r'[\s\(\)\,\-\_]+', c_clean) if len(w) > 2]
        matches = any(w in d_clean for w in c_words)
        if matches and sender_domain and sender_domain != c.real_domain.lower():
            return {
                'contact_name': c.name,
                'real_domain': c.real_domain,
                'spoofed_domain': sender_domain
            }
    return None

def score_email_content(msg, plain_text: str, html_text: str, db: Session):
    findings = []
    score = 0
    auth = parse_auth_headers(msg)
    auth_bad = sum(1 for v in auth.values() if v in {'fail', 'softfail', 'permerror'})
    if auth_bad:
        points = min(30, auth_bad * 10)
        score += points
        findings.append({
            'category': 'Cryptographic Authentication',
            'points': points,
            'evidence': f'SPF/DKIM/DMARC validation failures: {auth_bad} checks failed ({", ".join(f"{k.upper()}={v}" for k,v in auth.items() if v in {"fail","softfail","permerror"})})'
        })

    sender_tuple = parseaddr(msg.get('From', ''))
    display_name = sender_tuple[0]
    from_addr = sender_tuple[1]
    from_dom = get_domain(from_addr)
    reply_addr = parseaddr(msg.get('Reply-To', ''))[1]
    return_addr = parseaddr(msg.get('Return-Path', ''))[1].strip('<>')

    # Priority 2a: Impersonation Check (Known Contacts)
    imp = check_contact_impersonation(display_name, from_dom, db)
    if imp:
        score += 20
        findings.append({
            'category': 'Executive / Contact Impersonation',
            'points': 20,
            'evidence': f'Display name matches trusted contact "{imp["contact_name"]}" but sender domain (@{imp["spoofed_domain"]}) does not match authorized domain (@{imp["real_domain"]})'
        })

    # Priority 2b: Known Threat Feed Check
    threat_feed_match = check_known_bad(from_dom) or check_known_bad(get_domain(reply_addr))
    if threat_feed_match:
        score += 25
        findings.append({
            'category': 'Threat Intelligence Database Match',
            'points': 25,
            'evidence': f'Sender domain (@{threat_feed_match["domain"]}) matches known phishing threat feed ({threat_feed_match.get("category", "Malicious")})'
        })

    if reply_addr and from_addr and get_domain(reply_addr) != from_dom:
        score += 15
        findings.append({
            'category': 'Identity & Spoofing',
            'points': 15,
            'evidence': f'Reply-To domain mismatch: From is @{from_dom} but replies route to @{get_domain(reply_addr)}'
        })

    if return_addr and from_addr and get_domain(return_addr) != from_dom:
        score += 8
        findings.append({
            'category': 'Identity & Spoofing',
            'points': 8,
            'evidence': f'Return-Path domain mismatch: Envelope return routes to @{get_domain(return_addr)}'
        })

    subject = msg.get('Subject', '')
    full_content = (subject + '\n' + plain_text).strip()

    if URGENCY_RE.search(full_content):
        score += 8
        findings.append({'category': 'Social Engineering', 'points': 8, 'evidence': 'Psychological urgency or coercion phrasing detected in headers/body'})
    if CREDENTIAL_RE.search(full_content):
        score += 8
        findings.append({'category': 'Social Engineering', 'points': 8, 'evidence': 'Credential harvesting, login redirection, or 2FA/MFA token traps detected'})
    if FINANCIAL_RE.search(full_content):
        score += 6
        findings.append({'category': 'Social Engineering', 'points': 6, 'evidence': 'Financial transfer, billing update, or wire transaction lure detected'})
    if EXTORTION_RE.search(full_content):
        score += 15
        findings.append({'category': 'Social Engineering', 'points': 15, 'evidence': 'Extortion or blackmail ransomware threat language identified'})

    mismatches = find_visible_link_mismatches(html_text)
    if mismatches:
        pts = min(20, 10 * len(mismatches))
        score += pts
        findings.append({
            'category': 'Hyperlink Forensics',
            'points': pts,
            'evidence': f'Visible anchor text misleads to different target destination ({len(mismatches)} instances detected)'
        })

    urls = extract_urls_from_text(plain_text + '\n' + html_text)
    url_details = []
    for u in urls:
        parsed = urlparse(u)
        host = (parsed.hostname or '').lower()
        flags = []
        if host in SHORTENERS: flags.append('shortener')
        if IP_RE.fullmatch(host or ''): flags.append('ip-literal')
        if host.startswith('xn--') or 'xn--' in host: flags.append('punycode')
        if '@' in parsed.netloc: flags.append('userinfo-in-url')
        
        # Check if URL matches threat database
        url_threat = check_known_bad(host)
        if url_threat:
            flags.append('known-malicious')
            score += 15
            findings.append({'category': 'Threat Intelligence Match', 'points': 15, 'evidence': f'URL domain {host} matches known malicious phishing database ({url_threat.get("category", "")})'})

        if flags:
            pts = min(8, len(flags) * 4)
            score += pts
            findings.append({'category': 'Hyperlink Forensics', 'points': pts, 'evidence': f'Deceptive URL host structure on {host}: {", ".join(flags)}'})
        url_details.append({'url': u, 'host': host, 'flags': flags})

    attachments = []
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            filename = part.get_filename() or 'unnamed_payload'
            payload = part.get_payload(decode=True) or b''
            ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
            is_risky = ext in ATTACHMENT_RISK_EXT
            att_item = {
                'filename': filename,
                'size': len(payload),
                'sha256': hashlib.sha256(payload).hexdigest(),
                'risk': is_risky
            }
            attachments.append(att_item)
            if is_risky:
                score += 14
                findings.append({
                    'category': 'Payload & Attachments',
                    'points': 14,
                    'evidence': f'High-risk executable/script payload attached: {filename} ({ext})'
                })

    score = min(100, score)
    level = 'Low' if score <= 25 else 'Moderate' if score <= 50 else 'Suspicious' if score <= 75 else 'Critical Threat'
    confidence = min(100, 42 + len(findings) * 6)

    return score, level, confidence, findings, url_details, attachments, auth

def analyze_rfc822_bytes(raw_bytes: bytes, db: Session) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    plain_parts, html_parts = [], []
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart': continue
        if part.get_content_disposition() == 'attachment': continue
        try: content = part.get_content()
        except Exception: content = ''
        if part.get_content_type() == 'text/html': html_parts.append(content)
        elif part.get_content_type() == 'text/plain': plain_parts.append(content)

    plain_text = '\n'.join(plain_parts)
    html_text = '\n'.join(html_parts)
    score, level, confidence, findings, urls, attachments, auth = score_email_content(msg, plain_text, html_text, db)

    # Extract IPs ONLY from Received: headers (not body), preferring bracketed [IP] notation
    received_headers = msg.get_all('Received', [])
    relay_ips = extract_relay_ips_from_received_headers(received_headers)

    # Real Geolocation resolution for relay hops
    relay_geo_hops = [lookup_ip_geo(ip) for ip in relay_ips]

    sender = parseaddr(msg.get('From', ''))

    case_data = {
        'case_id': 'SENTRY-' + uuid.uuid4().hex[:8].upper(),
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'created_at': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'risk_score': score,
        'risk_level': level,
        'confidence': confidence,
        'threat': 'Potential Phishing / Malicious Spoofing' if score >= 51 else 'Low / Benign Communication',
        'sender': {'display_name': sender[0], 'address': sender[1], 'domain': get_domain(sender[1])},
        'reply_to': msg.get('Reply-To', ''),
        'return_path': msg.get('Return-Path', ''),
        'subject': msg.get('Subject', ''),
        'date': msg.get('Date', ''),
        'message_id': msg.get('Message-ID', ''),
        'authentication': auth,
        'received_count': len(received_headers),
        'relay_ips': relay_ips,
        'relay_geo_hops': relay_geo_hops,
        'urls': urls,
        'url_details': urls,
        'attachments': attachments,
        'findings': findings,
        'evidence_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'body_preview': (plain_text or html_text)[:600] + ('...' if len(plain_text or html_text) > 600 else ''),
        'limitations': [
            'Forensic analysis executed in zero-fetch sandbox mode (no live external links visited).',
            'Relay hop nodes indicate intermediate MTAs, not verified attacker physical coordinates.',
            'SPF/DKIM/DMARC evaluations inspect cryptographic validation stamps within the evidence file.'
        ]
    }
    return case_data

def analyze_pdf_evidence(raw_bytes: bytes, db: Session) -> dict:
    if not PYPDF_AVAILABLE:
        raise HTTPException(500, 'PDF extraction library (pypdf) is unavailable.')
    reader = pypdf.PdfReader(io.BytesIO(raw_bytes))
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
    from_dom = get_domain(from_addr)
    reply_addr = parseaddr(reply_to)[1]

    findings = []
    score = 0

    # Impersonation & Threat Database Checks
    imp = check_contact_impersonation(sender[0], from_dom, db)
    if imp:
        score += 20
        findings.append({
            'category': 'Executive / Contact Impersonation',
            'points': 20,
            'evidence': f'Display name matches trusted contact "{imp["contact_name"]}" but sender domain (@{imp["spoofed_domain"]}) does not match authorized domain (@{imp["real_domain"]})'
        })

    threat_feed_match = check_known_bad(from_dom)
    if threat_feed_match:
        score += 25
        findings.append({
            'category': 'Threat Intelligence Database Match',
            'points': 25,
            'evidence': f'Sender domain (@{threat_feed_match["domain"]}) matches known phishing threat feed ({threat_feed_match.get("category", "Malicious")})'
        })

    auth = {}
    for key in ('spf', 'dkim', 'dmarc'):
        m = re.search(rf'\b{key}=(pass|fail|softfail|neutral|none|temperror|permerror)\b', full_text, re.I)
        auth[key] = m.group(1).lower() if m else 'unknown'

    auth_bad = sum(1 for v in auth.values() if v in {'fail', 'softfail', 'permerror'})
    if auth_bad:
        pts = min(30, auth_bad * 10)
        score += pts
        findings.append({'category': 'Cryptographic Authentication', 'points': pts, 'evidence': f'SPF/DKIM/DMARC validation failures found in PDF text: {auth_bad}'})

    if reply_addr and from_addr and get_domain(reply_addr) != from_dom:
        score += 15
        findings.append({'category': 'Identity & Spoofing', 'points': 15, 'evidence': f'Reply-To domain mismatch: @{get_domain(reply_addr)} vs @{from_dom}'})

    if URGENCY_RE.search(full_text):
        score += 8
        findings.append({'category': 'Social Engineering', 'points': 8, 'evidence': 'Psychological urgency or coercion triggers detected'})
    if CREDENTIAL_RE.search(full_text):
        score += 8
        findings.append({'category': 'Social Engineering', 'points': 8, 'evidence': 'Credential harvesting & account login keywords detected'})
    if FINANCIAL_RE.search(full_text):
        score += 6
        findings.append({'category': 'Social Engineering', 'points': 6, 'evidence': 'Financial transaction or wire lure detected'})

    found_urls = set(URL_RE.findall(full_text)).union(set(pdf_links))
    cleaned_urls = sorted(u.rstrip(').,;]') for u in found_urls)
    url_details = []
    for u in cleaned_urls:
        parsed = urlparse(u)
        host = (parsed.hostname or '').lower()
        flags = []
        if host in SHORTENERS: flags.append('shortener')
        if IP_RE.fullmatch(host or ''): flags.append('ip-literal')
        if host.startswith('xn--') or 'xn--' in host: flags.append('punycode')
        if '@' in parsed.netloc: flags.append('userinfo-in-url')
        if check_known_bad(host): flags.append('known-malicious')
        if flags:
            pts = min(8, len(flags) * 4)
            score += pts
            findings.append({'category': 'Hyperlink Forensics', 'points': pts, 'evidence': f'Suspicious host on {host}: {", ".join(flags)}'})
        url_details.append({'url': u, 'host': host, 'flags': flags})

    attachments = []
    try:
        if hasattr(reader, "attachments") and reader.attachments:
            for name, file_datas in reader.attachments.items():
                items_list = file_datas if isinstance(file_datas, list) else [file_datas]
                for payload in items_list:
                    data_bytes = bytes(payload) if not isinstance(payload, bytes) else payload
                    ext = '.' + name.rsplit('.', 1)[-1].lower() if '.' in name else ''
                    is_risky = ext in ATTACHMENT_RISK_EXT
                    att_item = {'filename': name, 'size': len(data_bytes), 'sha256': hashlib.sha256(data_bytes).hexdigest(), 'risk': is_risky}
                    attachments.append(att_item)
                    if is_risky:
                        score += 14
                        findings.append({'category': 'Payload & Attachments', 'points': 14, 'evidence': f'High-risk embedded PDF attachment: {name}'})
    except Exception:
        pass

    # Extract IPs ONLY from lines starting with 'Received:' in the text.
    # NEVER scan full_text — body content may contain IPs in phishing lure URLs.
    relay_ips = extract_relay_ips_from_text(full_text)
    relay_geo_hops = [lookup_ip_geo(ip) for ip in relay_ips]

    score = min(100, score)
    level = 'Low' if score <= 25 else 'Moderate' if score <= 50 else 'Suspicious' if score <= 75 else 'Critical Threat'
    confidence = min(100, 38 + len(findings) * 7)

    case_data = {
        'case_id': 'SENTRY-' + uuid.uuid4().hex[:8].upper(),
        'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
        'created_at': datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        'risk_score': score,
        'risk_level': level,
        'confidence': confidence,
        'threat': 'Potential Phishing / Malicious Spoofing' if score >= 51 else 'Low / Benign Communication',
        'sender': {'display_name': sender[0], 'address': sender[1], 'domain': from_dom},
        'reply_to': reply_to,
        'return_path': '',
        'subject': subject,
        'date': date_val,
        'message_id': '',
        'authentication': auth,
        'received_count': len(relay_ips),
        'relay_ips': relay_ips,
        'relay_geo_hops': relay_geo_hops,
        'urls': url_details,
        'url_details': url_details,
        'attachments': attachments,
        'findings': findings,
        'evidence_sha256': hashlib.sha256(raw_bytes).hexdigest(),
        'body_preview': full_text[:600] + ('...' if len(full_text) > 600 else ''),
        'limitations': [
            'Evidence analyzed from exported PDF document format. Header cryptographic validation requires raw RFC 822 .eml format.',
            'Forensic analysis executed in zero-fetch sandbox mode (no live external links visited).',
            'IP relay locations represent infrastructure route hops, not physical threat actor coordinates.'
        ]
    }
    return case_data

def persist_case(case_data: dict, db: Session):
    case = CaseModel(
        case_id=case_data['case_id'],
        risk_score=case_data['risk_score'],
        risk_level=case_data['risk_level'],
        confidence=case_data['confidence'],
        threat_category=case_data['threat'],
        subject=case_data.get('subject', ''),
        sender_display=case_data.get('sender', {}).get('display_name', ''),
        sender_address=case_data.get('sender', {}).get('address', ''),
        sender_domain=case_data.get('sender', {}).get('domain', ''),
        reply_to=case_data.get('reply_to', ''),
        return_path=case_data.get('return_path', ''),
        evidence_sha256=case_data.get('evidence_sha256', ''),
        raw_json=json.dumps(case_data)
    )
    db.add(case)
    db.commit()

# ---------------------------------------------------------------------------
# FastAPI Application & REST Endpoints
# ---------------------------------------------------------------------------
app = FastAPI(title="MailSentinel Cyber-Forensics v3", version="3.2.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class RawAnalyzePayload(BaseModel):
    raw_text: str

class ContactCreatePayload(BaseModel):
    name: str
    real_domain: str
    notes: Optional[str] = ""

@app.get("/api/health")
def api_health():
    return {
        "status": "online",
        "service": "MailSentinel Cyber-Forensics Core v3",
        "database": "SQLAlchemy ORM + SQLite (sentrymail_v3.db)",
        "pdf_engine": "Active (pypdf)" if PYPDF_AVAILABLE else "Disabled",
        "threat_intel": "Active (Known Threat Feed + Real IP-API Geolocation)",
        "routes": {
            "landing_page": "/",
            "scanner_dashboard": "/scanner",
            "mobile_showcase": "/mobile"
        }
    }

@app.post("/api/analyze")
async def api_analyze_upload(file: UploadFile = File(...), db: Session = Depends(get_db)):
    filename = (file.filename or '').lower()
    if not (filename.endswith('.eml') or filename.endswith('.pdf')):
        raise HTTPException(400, "Supported formats: .eml and .pdf")
    raw = await file.read()
    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(413, "File exceeds maximum 10 MB forensic upload limit.")
    try:
        if filename.endswith('.pdf'):
            res = analyze_pdf_evidence(raw, db)
        else:
            res = analyze_rfc822_bytes(raw, db)
        res['original_filename'] = file.filename
        persist_case(res, db)
        return JSONResponse(res)
    except Exception as e:
        raise HTTPException(422, f"Forensic parsing failure: {e}")

@app.post("/api/analyze-raw")
def api_analyze_raw(payload: RawAnalyzePayload, db: Session = Depends(get_db)):
    if not payload.raw_text or not payload.raw_text.strip():
        raise HTTPException(400, "Raw email content cannot be empty.")
    try:
        res = analyze_rfc822_bytes(payload.raw_text.encode('utf-8'), db)
        res['original_filename'] = 'Live_Pasted_Payload.eml'
        persist_case(res, db)
        return JSONResponse(res)
    except Exception as e:
        raise HTTPException(422, f"Forensic parsing failure: {e}")

@app.get("/api/cases")
def api_get_cases(db: Session = Depends(get_db)):
    cases = db.query(CaseModel).order_by(desc(CaseModel.created_at)).limit(100).all()
    return [{
        'case_id': c.case_id,
        'created_at': c.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if c.created_at else "",
        'risk_score': c.risk_score,
        'risk_level': c.risk_level,
        'confidence': c.confidence,
        'threat': c.threat_category,
        'subject': c.subject,
        'sender_address': c.sender_address,
        'evidence_sha256': c.evidence_sha256
    } for c in cases]

@app.get("/api/cases/{case_id}")
def api_get_case(case_id: str, db: Session = Depends(get_db)):
    c = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not c:
        raise HTTPException(404, "Case not found")
    return JSONResponse(json.loads(c.raw_json))

@app.delete("/api/cases/{case_id}")
def api_delete_case(case_id: str, db: Session = Depends(get_db)):
    c = db.query(CaseModel).filter(CaseModel.case_id == case_id).first()
    if not c:
        raise HTTPException(404, "Case not found")
    db.delete(c)
    db.commit()
    return {"status": "deleted", "case_id": case_id}

@app.get("/api/contacts")
def api_get_contacts(db: Session = Depends(get_db)):
    contacts = db.query(TrustedContactModel).order_by(TrustedContactModel.name).all()
    return [{
        'id': c.id,
        'name': c.name,
        'real_domain': c.real_domain,
        'notes': c.notes,
        'created_at': c.created_at.strftime("%Y-%m-%d") if c.created_at else ""
    } for c in contacts]

@app.post("/api/contacts")
def api_create_contact(payload: ContactCreatePayload, db: Session = Depends(get_db)):
    dom = payload.real_domain.strip().lower().lstrip('@')
    contact = TrustedContactModel(name=payload.name.strip(), real_domain=dom, notes=payload.notes.strip())
    db.add(contact)
    db.commit()
    db.refresh(contact)
    return {"status": "created", "id": contact.id, "name": contact.name, "real_domain": contact.real_domain}

@app.delete("/api/contacts/{contact_id}")
def api_delete_contact(contact_id: int, db: Session = Depends(get_db)):
    contact = db.query(TrustedContactModel).filter(TrustedContactModel.id == contact_id).first()
    if not contact:
        raise HTTPException(404, "Contact not found")
    db.delete(contact)
    db.commit()
    return {"status": "deleted", "id": contact_id}

@app.get("/api/sender-intelligence")
def api_sender_intelligence(domain: str, address: str = "", risk_score: int = 0):
    """
    On-demand Sender Intelligence for a given domain.
    Activates only when risk_score >= RISK_THRESHOLD (default 70).
    Returns domain registration, DNS, and reputation intelligence.
    Privacy-safe: never fetches suspicious URLs; never exposes personal info.
    """
    if not domain or len(domain) > 255:
        raise HTTPException(400, "Invalid domain")
    # Strip any accidental @ prefix
    domain = domain.lstrip("@").strip().lower()
    try:
        result = run_sender_intelligence(
            domain=domain,
            sender_address=address,
            risk_score=risk_score
        )
        return JSONResponse(result)
    except Exception as e:
        raise HTTPException(500, f"Sender Intelligence query failed: {e}")

# ---------------------------------------------------------------------------
# 1. LANDING PAGE (GET /)
# ---------------------------------------------------------------------------
LANDING_PAGE_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailSentinel — Email Threat Intelligence &amp; Forensics</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#030712',
          900: '#070d1d',
          850: '#0c142b',
          800: '#111c3d',
          700: '#1e2d5a',
          cyan: '#06b6d4',
          blue: '#3b82f6',
          violet: '#a855f7',
          emerald: '#10b981',
          amber: '#f59e0b',
          rose: '#f43f5e'
        }
      },
      fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] },
      animation: {
        'shimmer': 'shimmer 3s linear infinite',
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'float': 'float 6s ease-in-out infinite',
        'scan': 'scanline 2.5s ease-in-out infinite'
      },
      keyframes: {
        shimmer: {
          '0%': { backgroundPosition: '0% 50%' },
          '50%': { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' }
        },
        float: {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-8px)' }
        },
        scanline: {
          '0%': { top: '0%' },
          '50%': { top: '90%' },
          '100%': { top: '0%' }
        }
      }
    }
  }
}
</script>
<style>
body {
  background-color: #030712;
  background-image: 
    radial-gradient(circle at 10% 15%, rgba(6, 182, 212, 0.15) 0%, transparent 40%),
    radial-gradient(circle at 85% 25%, rgba(168, 85, 247, 0.15) 0%, transparent 45%),
    radial-gradient(circle at 50% 65%, rgba(59, 130, 246, 0.12) 0%, transparent 50%),
    radial-gradient(circle at 80% 85%, rgba(16, 185, 129, 0.12) 0%, transparent 40%),
    linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 100% 100%, 100% 100%, 32px 32px, 32px 32px;
}

.glass-card {
  background: rgba(12, 20, 43, 0.78);
  backdrop-filter: blur(18px);
  border: 1px solid rgba(59, 130, 246, 0.22);
}
.glass-card:hover {
  border-color: rgba(6, 182, 212, 0.5);
  box-shadow: 0 10px 30px -10px rgba(6, 182, 212, 0.25);
}

/* 2.5D Unfolding Cyber Envelope Styles */
.envelope-stage {
  perspective: 1200px;
}
.envelope-wrapper {
  position: relative;
  width: 320px;
  height: 200px;
  background: linear-gradient(145deg, #0f172a, #070d1d);
  border: 2px solid rgba(6, 182, 212, 0.4);
  border-radius: 18px;
  box-shadow: 0 20px 50px rgba(0, 0, 0, 0.8), 0 0 30px rgba(6, 182, 212, 0.2);
  transition: all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
}
.envelope-flap {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100px;
  background: linear-gradient(180deg, #1e293b 0%, #0f172a 100%);
  border-top-left-radius: 16px;
  border-top-right-radius: 16px;
  clip-path: polygon(0% 0%, 100% 0%, 50% 100%);
  transform-origin: top;
  transform-style: preserve-3d;
  transition: transform 0.8s cubic-bezier(0.4, 0, 0.2, 1), z-index 0.2s;
  z-index: 20;
  border-top: 1px solid rgba(6, 182, 212, 0.6);
}
.envelope-pocket {
  position: absolute;
  bottom: 0;
  left: 0;
  width: 100%;
  height: 120px;
  background: linear-gradient(0deg, #090e21 0%, #0f172a 100%);
  border-bottom-left-radius: 16px;
  border-bottom-right-radius: 16px;
  clip-path: polygon(0% 100%, 100% 100%, 100% 25%, 50% 65%, 0% 25%);
  z-index: 15;
  border-bottom: 2px solid rgba(6, 182, 212, 0.4);
}
.forensic-letter {
  position: absolute;
  left: 14px;
  right: 14px;
  bottom: 12px;
  height: 240px;
  background: linear-gradient(180deg, #091226 0%, #050b18 100%);
  border: 1.5px solid rgba(6, 182, 212, 0.5);
  border-radius: 12px;
  box-shadow: 0 10px 30px rgba(0, 0, 0, 0.7);
  z-index: 10;
  transform: translateY(0px);
  transition: transform 0.8s cubic-bezier(0.34, 1.25, 0.64, 1), box-shadow 0.6s;
  overflow: hidden;
}

/* Open State */
.envelope-wrapper.is-open .envelope-flap {
  transform: rotateX(180deg);
  z-index: 5;
}
.envelope-wrapper.is-open .forensic-letter {
  transform: translateY(-130px);
  box-shadow: 0 15px 40px rgba(6, 182, 212, 0.35), 0 0 20px rgba(168, 85, 247, 0.25);
}

.laser-beam {
  position: absolute;
  left: 0;
  width: 100%;
  height: 2px;
  background: linear-gradient(90deg, transparent, #06b6d4, #a855f7, #06b6d4, transparent);
  box-shadow: 0 0 12px #06b6d4;
  animation: scanline 2.2s ease-in-out infinite;
}

/* Gradient Shimmer Border Button */
.btn-shimmer {
  background: linear-gradient(90deg, #06b6d4, #3b82f6, #8b5cf6, #ec4899, #06b6d4);
  background-size: 300% 300%;
  animation: shimmer 4s ease infinite;
}
</style>
</head>
<body class="text-slate-100 font-sans min-h-screen selection:bg-cyan-500 selection:text-white flex flex-col justify-between">

  <!-- Navigation Bar -->
  <header class="w-full max-w-7xl mx-auto px-4 md:px-8 py-5 flex justify-between items-center border-b border-slate-800/50 relative z-30">
    <div class="flex items-center gap-3">
      <!-- SVG Logo (Envelope + Shield + Radar) -->
      <svg class="w-8 h-8 text-cyan-400" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4z" fill="url(#shield-grad-hm)" stroke="#06b6d4" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M7 9h10v6H7V9z" fill="#070d1d" stroke="#3b82f6" stroke-width="1.2"/>
        <path d="M7 9l5 3.5L17 9" stroke="#06b6d4" stroke-width="1.2" stroke-linecap="round"/>
        <line x1="4" y1="12" x2="20" y2="12" stroke="#22d3ee" stroke-width="1" stroke-dasharray="2 3" opacity="0.6"/>
        <defs>
          <linearGradient id="shield-grad-hm" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse">
            <stop stop-color="#0e172e" stop-opacity="0.8"/>
            <stop stop-color="#070d1d" stop-opacity="0.95"/>
          </linearGradient>
        </defs>
      </svg>
      <span class="text-lg font-black tracking-wider text-white uppercase bg-clip-text text-transparent bg-gradient-to-r from-white via-slate-100 to-cyan-400">MailSentinel</span>
    </div>
    <nav class="flex items-center gap-6">
      <a href="/" class="text-sm font-bold text-cyan-400 border-b-2 border-cyan-400 pb-1">Home</a>
      <a href="/scanner" class="text-sm font-semibold text-slate-400 hover:text-cyan-300 transition-colors pb-1">Detector</a>
      <a href="/mobile" class="text-sm font-semibold text-slate-400 hover:text-cyan-300 transition-colors pb-1">Mobile</a>
    </nav>
  </header>

  <!-- Hero Section -->
  <section class="max-w-6xl mx-auto px-4 md:px-8 pt-16 pb-12 text-center space-y-6 relative">
    <div class="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-gradient-to-r from-cyan-500/10 via-violet-500/10 to-blue-500/10 border border-cyan-500/30 text-cyan-300 text-xs font-bold uppercase tracking-wider shadow-lg shadow-cyan-500/10">
      <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
      <span>⚡ DETECT. TRACE. DEFEND.</span>
    </div>

    <h1 class="text-4xl md:text-6xl font-black tracking-tight text-white leading-tight max-w-4xl mx-auto">
      Stop Email Fraud Before It <span class="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 via-indigo-400 to-violet-400">Reaches Your Organization</span>
    </h1>

    <p class="text-base md:text-lg text-slate-300 max-w-3xl mx-auto leading-relaxed">
      MailSentinel analyzes email evidence, authentication signals, sender identity, relay infrastructure, and threat intelligence to produce an explainable forensic risk assessment.
    </p>

    <div class="pt-4 flex flex-col sm:flex-row items-center justify-center gap-4">
      <a href="/scanner" class="w-full sm:w-auto p-0.5 rounded-2xl btn-shimmer shadow-xl shadow-cyan-500/30 group transition-all">
        <span class="block px-8 py-4 bg-slate-950 rounded-2xl text-white font-extrabold text-base group-hover:bg-opacity-90 transition-all flex items-center justify-center gap-2">
          <span>🔍</span> ANALYZE AN EMAIL &rarr;
        </span>
      </a>
      <a href="#how-it-works" class="w-full sm:w-auto px-8 py-4 glass-card text-slate-200 hover:text-white font-bold text-base rounded-2xl transition-all border border-slate-700 hover:border-cyan-500/50">
        SEE HOW IT WORKS
      </a>
    </div>
  </section>

  <!-- Interactive 2.5D Unfolding Cyber Envelope Section -->
  <section class="max-w-5xl mx-auto px-4 md:px-8 py-8 w-full flex flex-col items-center">
    <div class="text-center mb-6 space-y-1">
      <span class="text-[11px] font-mono font-bold tracking-widest text-cyan-400 uppercase">Interactive Forensic Visualization</span>
      <p class="text-xs text-slate-400">Hover or scroll to open the cyber envelope &amp; watch the laser scan unfold</p>
    </div>

    <div class="envelope-stage py-10 cursor-pointer" onclick="toggleEnvelope()" onmouseenter="openEnvelope()" onmouseleave="autoEnvelopeCheck()">
      <div id="cyber-envelope" class="envelope-wrapper is-open">
        <div class="envelope-flap">
          <div class="w-8 h-8 rounded-full bg-cyan-500/20 border border-cyan-400/50 mx-auto mt-2 flex items-center justify-center shadow-lg shadow-cyan-500/30 text-cyan-300 text-xs">
            🛡️
          </div>
        </div>

        <div class="envelope-pocket"></div>

        <!-- Unfolding Letter Sheet -->
        <div class="forensic-letter p-3.5 flex flex-col justify-between text-left">
          <div class="laser-beam"></div>
          
          <div class="space-y-2">
            <div class="flex items-center justify-between border-b border-cyan-500/30 pb-1.5">
              <div class="flex items-center gap-1.5 text-[10px] font-mono text-cyan-400 font-bold uppercase tracking-wider">
                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping"></span>
                <span id="env-header-title">EVIDENCE PACKET #26106</span>
              </div>
              <span id="env-status-badge" class="text-[9px] font-mono font-bold px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 border border-cyan-500/40">SANDBOX ACTIVE</span>
            </div>

            <div class="space-y-1 text-[11px] font-mono">
              <div class="text-slate-300 truncate"><span class="text-slate-500">FROM:</span> <span id="env-from-text" class="text-cyan-300">security@update-service-alert.com</span></div>
              <div class="text-slate-300 truncate"><span class="text-slate-500">SUBJ:</span> <span id="env-subj-text" class="text-slate-200">URGENT: Executive Wire Transfer</span></div>
              <div class="text-slate-300 truncate"><span class="text-slate-500">AUTH:</span> <span id="env-auth-text" class="text-rose-400">SPF=FAIL | DKIM=FAIL | DMARC=FAIL</span></div>
            </div>
          </div>

          <div class="p-2 rounded-lg bg-slate-950/80 border border-cyan-500/20 flex items-center justify-between text-[10px] font-mono">
            <span class="text-slate-400" id="env-node-label">NODE: 01 / INGESTION</span>
            <span class="text-emerald-400 font-bold" id="env-verdict-label">RISK: 90/100 [CRITICAL]</span>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Synchronized 6-Stage Interactive Forensic Pipeline -->
  <section id="how-it-works" class="max-w-6xl mx-auto px-4 md:px-8 py-12 w-full">
    <div class="text-center space-y-2 mb-10">
      <h2 class="text-xs uppercase font-bold tracking-widest text-cyan-400">Forensic Investigation Story</h2>
      <h3 class="text-2xl md:text-4xl font-extrabold text-white">How MailSentinel Investigates an Email</h3>
      <p class="text-sm text-slate-400 max-w-xl mx-auto">Click any node to explore the synchronized analysis pipeline step-by-step.</p>
    </div>

    <!-- Progress Indicator Bar -->
    <div class="w-full bg-slate-900/80 rounded-full h-1.5 mb-8 border border-slate-800 overflow-hidden">
      <div id="pipe-progress-bar" class="bg-gradient-to-r from-cyan-500 via-blue-500 via-violet-500 to-emerald-400 h-full w-1/6 transition-all duration-500"></div>
    </div>

    <!-- Interactive Grid: Left 6 Nodes, Right Narrative Story Card -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-stretch">
      
      <!-- Nodes List (5 Cols) -->
      <div class="lg:col-span-5 space-y-3">
        <button onclick="setPipelineStep(0)" id="pipe-node-0" class="w-full p-3.5 rounded-2xl glass-card border-cyan-500 bg-cyan-500/15 text-white transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-0" class="w-8 h-8 rounded-xl bg-cyan-500 text-slate-950 font-extrabold flex items-center justify-center font-mono text-sm">01</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">EMAIL INGESTION</div>
            <div class="text-[11px] text-slate-400 truncate">Evidence drop &amp; sandbox parsing</div>
          </div>
        </button>

        <button onclick="setPipelineStep(1)" id="pipe-node-1" class="w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-1" class="w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm">02</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">AUTHENTICATION</div>
            <div class="text-[11px] text-slate-400 truncate">SPF, DKIM &amp; DMARC seal checks</div>
          </div>
        </button>

        <button onclick="setPipelineStep(2)" id="pipe-node-2" class="w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-2" class="w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm">03</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">RELAY TRACE</div>
            <div class="text-[11px] text-slate-400 truncate">MTA route extraction &amp; IP geocoding</div>
          </div>
        </button>

        <button onclick="setPipelineStep(3)" id="pipe-node-3" class="w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-3" class="w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm">04</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">SENDER INTELLIGENCE</div>
            <div class="text-[11px] text-slate-400 truncate">Domain age, registrar &amp; MX posture</div>
          </div>
        </button>

        <button onclick="setPipelineStep(4)" id="pipe-node-4" class="w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-4" class="w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm">05</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">THREAT ANALYSIS</div>
            <div class="text-[11px] text-slate-400 truncate">Phishing feed &amp; URL link correlation</div>
          </div>
        </button>

        <button onclick="setPipelineStep(5)" id="pipe-node-5" class="w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3">
          <span id="pipe-num-5" class="w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm">06</span>
          <div class="text-left truncate">
            <div class="text-xs font-bold text-slate-100">RISK VERDICT</div>
            <div class="text-[11px] text-slate-400 truncate">Explainable 0–100 risk assessment</div>
          </div>
        </button>
      </div>

      <!-- Synchronized Stage Details Card (7 Cols) -->
      <div class="lg:col-span-7 glass-card rounded-3xl p-8 flex flex-col justify-between space-y-6 border-cyan-500/30 shadow-2xl relative">
        <div class="space-y-4">
          <div class="flex items-center justify-between">
            <span id="pipe-tag" class="text-xs font-mono font-bold tracking-widest text-cyan-400 uppercase">STAGE 01 — EVIDENCE INGESTION</span>
            <span id="pipe-badge" class="text-xs font-mono font-bold px-3 py-1 rounded-full border text-cyan-400 border-cyan-500/30 bg-cyan-500/10">Sandbox Active</span>
          </div>

          <div class="flex items-center gap-4">
            <div id="pipe-icon" class="text-4xl p-3 bg-cyan-500/10 rounded-2xl border border-cyan-500/20">📥</div>
            <h4 id="pipe-title" class="text-2xl font-black text-white">Email Evidence Ingestion</h4>
          </div>

          <p id="pipe-desc" class="text-sm text-slate-300 leading-relaxed min-h-[70px]">
            Ingest raw email evidence via EML/PDF file drop or RFC 822 text paste. The sandbox isolates payload structures, headers, and attachments completely offline without external network triggers.
          </p>
        </div>

        <div class="p-4 rounded-2xl bg-slate-950/80 border border-slate-800 space-y-2">
          <div class="text-[11px] uppercase font-bold text-slate-400 tracking-wider">Synchronized Engine Output</div>
          <div id="pipe-detail" class="text-xs font-mono text-cyan-300">Extracted: Headers, Subject, From, Reply-To, Boundaries, Attachments</div>
        </div>

        <!-- Previous / Next Controls -->
        <div class="flex items-center justify-between pt-2 border-t border-slate-800/80">
          <button onclick="prevPipelineStep()" class="px-3.5 py-1.5 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-700 hover:border-slate-500 text-xs font-semibold text-slate-300 hover:text-white transition-all cursor-pointer flex items-center gap-1.5">
            <span>←</span> Previous Stage
          </button>
          <span class="text-xs font-mono text-slate-500" id="pipe-counter">Stage 1 of 6</span>
          <button onclick="nextPipelineStep()" class="px-3.5 py-1.5 rounded-xl bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-xs font-bold text-cyan-300 transition-all cursor-pointer flex items-center gap-1.5">
            Next Stage <span>→</span>
          </button>
        </div>
      </div>
    </div>
  </section>

  <!-- Capability Cards Overview (Vibrant Cyber Palette) -->
  <section class="max-w-6xl mx-auto px-4 md:px-8 py-12 w-full">
    <div class="text-center space-y-2 mb-10">
      <h2 class="text-xs uppercase font-bold tracking-widest text-cyan-400">Built for Explainable Email Security</h2>
      <h3 class="text-2xl md:text-3xl font-extrabold text-white">Comprehensive Cyber-Forensics Engine</h3>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <div class="glass-card rounded-2xl p-6 space-y-3 border-cyan-500/30 hover:border-cyan-400 transition-all">
        <div class="text-2xl text-cyan-400">🔬</div>
        <h4 class="text-base font-bold text-slate-100">Email Forensics</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Deep parsing of RFC 822 headers and PDF artifacts. Extracts sender metadata, reply-to anomalies, and attachments.
        </p>
      </div>

      <div class="glass-card rounded-2xl p-6 space-y-3 border-indigo-500/30 hover:border-indigo-400 transition-all">
        <div class="text-2xl text-indigo-400">🔑</div>
        <h4 class="text-base font-bold text-slate-100">Authentication Analysis</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Validates SPF, DKIM, and DMARC alignment and cryptographic verification statuses to prevent spoofing.
        </p>
      </div>

      <div class="glass-card rounded-2xl p-6 space-y-3 border-violet-500/30 hover:border-violet-400 transition-all">
        <div class="text-2xl text-violet-400">🔎</div>
        <h4 class="text-base font-bold text-slate-100">Sender Intelligence</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Fetches public registration age, registrar authority, MX posture, and reputation records for high-risk senders.
        </p>
      </div>

      <div class="glass-card rounded-2xl p-6 space-y-3 border-blue-500/30 hover:border-blue-400 transition-all">
        <div class="text-2xl text-blue-400">🌐</div>
        <h4 class="text-base font-bold text-slate-100">Relay/IP Geolocation</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Traces the actual path of SMTP relay hops, filters internal subnets, and geolocates public routing servers.
        </p>
      </div>

      <div class="glass-card rounded-2xl p-6 space-y-3 border-rose-500/30 hover:border-rose-400 transition-all">
        <div class="text-2xl text-rose-400">🖧</div>
        <h4 class="text-base font-bold text-slate-100">Threat Intelligence</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Correlates extracted domains and IP links against active threat feeds and phishing databases.
        </p>
      </div>

      <div class="glass-card rounded-2xl p-6 space-y-3 border-emerald-500/30 hover:border-emerald-400 transition-all">
        <div class="text-2xl text-emerald-400">📊</div>
        <h4 class="text-base font-bold text-slate-100">Explainable Risk Scoring</h4>
        <p class="text-xs text-slate-400 leading-relaxed">
          Transparent, weighted scoring mapping out why each threat score was reached without black-box metrics.
        </p>
      </div>
    </div>
  </section>

  <!-- Interactive Live Product Preview -->
  <section class="max-w-6xl mx-auto px-4 md:px-8 py-12 w-full">
    <div class="text-center space-y-2 mb-10">
      <h2 class="text-xs uppercase font-bold tracking-widest text-cyan-400">Interactive Preview</h2>
      <h3 class="text-2xl md:text-3xl font-extrabold text-white">Live Forensic Report Inspection</h3>
    </div>

    <div class="glass-card rounded-3xl p-6 md:p-8 space-y-6 border-cyan-500/30 shadow-2xl">
      <!-- Top Risk Card -->
      <div class="p-6 rounded-2xl bg-red-950/25 border-l-8 border-rose-500 border border-rose-500/30 grid grid-cols-1 md:grid-cols-2 gap-4 items-center">
        <div>
          <div class="text-xs uppercase font-bold tracking-widest text-slate-400">Forensic Risk Verdict</div>
          <div class="flex items-baseline gap-3 mt-1">
            <span class="text-5xl font-black font-mono text-rose-400">90/100</span>
            <span class="text-xs px-3 py-1 rounded-full font-bold uppercase bg-rose-500/20 text-rose-300 border border-rose-500/40">Critical Threat</span>
          </div>
          <p class="text-xs text-slate-300 mt-2">Executive BEC Impersonation &amp; Authentication Seal Failures</p>
        </div>
        <div class="md:text-right space-y-1">
          <div class="text-xs uppercase font-bold text-slate-400">Heuristic Confidence</div>
          <div class="text-3xl font-black font-mono text-cyan-400">95%</div>
          <p class="text-[11px] text-slate-500">Backed by 4 weighted forensic rules</p>
        </div>
      </div>

      <!-- Grid of Preview Evidence -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div class="font-bold text-slate-200 flex justify-between">
            <span>Identity &amp; Auth</span>
            <span class="text-rose-400 font-mono">+30 pts</span>
          </div>
          <p class="text-slate-400">From display name "John Doe (CEO)" domain mismatch vs actual sender address <code>ceo@attacker-drop.net</code>.</p>
        </div>

        <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div class="font-bold text-slate-200 flex justify-between">
            <span>Relay Geolocation</span>
            <span class="text-amber-400 font-mono">2 Hops</span>
          </div>
          <p class="text-slate-400">Originating server <code>133.242.0.1</code> geolocated to Tokyo, Japan via intermediate relay <code>212.58.244.20</code> London, UK.</p>
        </div>

        <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
          <div class="font-bold text-slate-200 flex justify-between">
            <span>Sender Intelligence</span>
            <span class="text-violet-400 font-mono">Unlocked (70+)</span>
          </div>
          <p class="text-slate-400">Domain <code>attacker-drop.net</code> registered 3 days ago. DMARC policy: <code>none</code>. Threat match found.</p>
        </div>
      </div>
    </div>
  </section>

  <!-- Mobile Showcase Section -->
  <section class="max-w-6xl mx-auto px-4 md:px-8 py-12 w-full">
    <div class="glass-card rounded-3xl p-8 md:p-12 grid grid-cols-1 lg:grid-cols-12 gap-8 items-center border-cyan-500/30 shadow-2xl">
      <div class="lg:col-span-7 space-y-4">
        <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-bold uppercase tracking-wider">
          <span>📱</span> Mobile Intelligence
        </div>
        <h3 class="text-3xl md:text-4xl font-extrabold text-white">MailSentinel, Wherever You Investigate</h3>
        <p class="text-sm text-slate-400 leading-relaxed">
          Access the real-time threat simulator and forensic incident database directly from mobile viewports.
        </p>
        <div class="pt-2">
          <a href="/mobile" class="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-500 via-blue-600 to-violet-600 hover:from-cyan-400 hover:to-violet-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-cyan-500/25 transition-all">
            OPEN MOBILE EXPERIENCE &rarr;
          </a>
        </div>
      </div>
      <div class="lg:col-span-5 flex justify-center">
        <div class="w-64 h-48 bg-slate-950/80 rounded-2xl border border-cyan-500/30 p-4 space-y-3 shadow-2xl">
          <div class="flex items-center justify-between text-xs border-b border-slate-800 pb-2">
            <span class="font-bold text-white">MailSentinel Mobile</span>
            <span class="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
          </div>
          <div class="p-3 rounded-xl bg-slate-900 text-[11px] space-y-1">
            <div class="text-slate-400">Incident Alert</div>
            <div class="text-rose-400 font-bold">Critical Threat (90/100)</div>
          </div>
        </div>
      </div>
    </div>
  </section>

  <!-- Footer -->
  <footer class="w-full max-w-7xl mx-auto px-4 md:px-8 py-8 border-t border-slate-800 text-center text-xs text-slate-500">
    MailSentinel (formerly SentryMail) (SIH26106) — Zero-Dependency Cyber-Forensics &amp; Email Threat Defense Engine.
  </footer>

<script>
const pipelineData = [
  {
    step: 1,
    tag: "STAGE 01 — EVIDENCE INGESTION",
    title: "Email Evidence Ingestion",
    desc: "Ingest raw email evidence via EML/PDF file drop or RFC 822 text paste. The sandbox isolates payload structures, headers, and attachments completely offline without external network triggers.",
    icon: "📥",
    detail: "Extracted: Headers, Subject, From, Reply-To, Boundaries, Attachments",
    badge: "Sandbox Active",
    badgeColor: "text-cyan-400 border-cyan-500/30 bg-cyan-500/10",
    envSubj: "Evidence Ingested #26106",
    envVerdict: "SANDBOX LOCKED",
    envNode: "NODE 01 / INGESTION"
  },
  {
    step: 2,
    tag: "STAGE 02 — CRYPTOGRAPHIC AUTHENTICATION",
    title: "SPF / DKIM / DMARC Verification",
    desc: "Checks cryptographic alignment and domain signatures to verify whether the email genuinely originated from the claimed sending organization or was forged by an attacker.",
    icon: "🔑",
    detail: "Validating: Envelope Return-Path vs Header From & Cryptographic Hashes",
    badge: "Signatures Scanned",
    badgeColor: "text-indigo-400 border-indigo-500/30 bg-indigo-500/10",
    envSubj: "SPF=FAIL | DKIM=FAIL",
    envVerdict: "CRYPTOGRAPHIC MISMATCH",
    envNode: "NODE 02 / AUTHENTICATION"
  },
  {
    step: 3,
    tag: "STAGE 03 — RELAY INFRASTRUCTURE TRACE",
    title: "SMTP Relay Route Geolocation",
    desc: "Extracts sequential Received: headers to trace the path of intermediate Mail Transfer Agents (MTAs). Filters private local subnets (10.x, 192.168.x) and geolocates public routing hops.",
    icon: "🌐",
    detail: "Tracing: IP Hop Sequence ➔ Public Server Resolution (Live ip-api.com)",
    badge: "Relays Geocoded",
    badgeColor: "text-blue-400 border-blue-500/30 bg-blue-500/10",
    envSubj: "Hops: London UK ➔ Tokyo JP",
    envVerdict: "2 PUBLIC HOPS GEOCODED",
    envNode: "NODE 03 / RELAY TRACE"
  },
  {
    step: 4,
    tag: "STAGE 04 — SENDER INTELLIGENCE",
    title: "Domain & Sender Intelligence",
    desc: "Queries public WHOIS/RDAP domain registration dates, registrar authority, MX records, and historical reputation feeds for suspicious senders once the risk threshold (70+) is triggered.",
    icon: "🔎",
    detail: "Evaluating: Domain Age, Expiry, Registrar, MX Mail Posture & Abuse Feeds",
    badge: "Public OSINT Active",
    badgeColor: "text-violet-400 border-violet-500/30 bg-violet-500/10",
    envSubj: "Age: 3 Days Old | Registrar: Unknown",
    envVerdict: "HIGH-RISK DOMAIN",
    envNode: "NODE 04 / SENDER INTEL"
  },
  {
    step: 5,
    tag: "STAGE 05 — THREAT INTELLIGENCE MATCHING",
    title: "Phishing Feed & URL Analysis",
    desc: "Correlates extracted body hyperlinks, shortened links, punycode hosts, and IP literals against active known phishing database indicators in zero-fetch mode.",
    icon: "🖧",
    detail: "Correlating: Hyperlinks, IP-literals & Threat Indicators Database",
    badge: "Threat Feed Synced",
    badgeColor: "text-amber-400 border-amber-500/30 bg-amber-500/10",
    envSubj: "Matched: 1 Phish URL Indicator",
    envVerdict: "FEED MATCH DETECTED",
    envNode: "NODE 05 / THREAT INTEL"
  },
  {
    step: 6,
    tag: "STAGE 06 — FORENSIC RISK VERDICT",
    title: "Explainable Risk Assessment",
    desc: "Combines weighted evidence indicators into a final transparent 0–100 risk score, risk level classification, and itemized evidence ledger.",
    icon: "🛡️",
    detail: "Verdict: 0–100 Risk Score + Heuristic Confidence + Evidence Ledger",
    badge: "Verdict Generated",
    badgeColor: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10",
    envSubj: "URGENT: Executive Wire Transfer",
    envVerdict: "RISK: 90/100 [CRITICAL]",
    envNode: "NODE 06 / FINAL VERDICT"
  }
];

let activeStep = 0;
let autoCycleTimer = null;
let userInteracted = false;

function setPipelineStep(idx, manual = false) {
  if (manual) {
    userInteracted = true;
    if (autoCycleTimer) clearInterval(autoCycleTimer);
  }
  activeStep = Math.max(0, Math.min(5, idx));
  const d = pipelineData[activeStep];
  
  // Update narrative panel
  document.getElementById('pipe-tag').textContent = d.tag;
  document.getElementById('pipe-title').textContent = d.title;
  document.getElementById('pipe-desc').textContent = d.desc;
  document.getElementById('pipe-detail').textContent = d.detail;
  document.getElementById('pipe-icon').textContent = d.icon;
  
  const counterEl = document.getElementById('pipe-counter');
  if (counterEl) counterEl.textContent = `Stage ${activeStep + 1} of 6`;

  const badgeEl = document.getElementById('pipe-badge');
  badgeEl.textContent = d.badge;
  badgeEl.className = `text-xs font-mono font-bold px-3 py-1 rounded-full border ${d.badgeColor}`;
  
  // Update envelope letter sheet telemetry
  document.getElementById('env-subj-text').textContent = d.envSubj;
  document.getElementById('env-verdict-label').textContent = d.envVerdict;
  document.getElementById('env-node-label').textContent = d.envNode;
  
  // Update node buttons styling
  for (let i = 0; i < 6; i++) {
    const btn = document.getElementById(`pipe-node-${i}`);
    const num = document.getElementById(`pipe-num-${i}`);
    if (i === activeStep) {
      btn.className = "w-full p-3.5 rounded-2xl glass-card border-cyan-500 bg-cyan-500/15 text-white shadow-lg shadow-cyan-500/20 scale-[1.02] transition-all cursor-pointer flex items-center gap-3";
      num.className = "w-8 h-8 rounded-xl bg-cyan-500 text-slate-950 font-extrabold flex items-center justify-center font-mono text-sm";
    } else if (i < activeStep) {
      btn.className = "w-full p-3.5 rounded-2xl glass-card border-emerald-500/40 bg-emerald-500/5 text-slate-300 transition-all cursor-pointer flex items-center gap-3";
      num.className = "w-8 h-8 rounded-xl bg-emerald-500/20 text-emerald-400 font-bold flex items-center justify-center font-mono text-sm border border-emerald-500/40";
    } else {
      btn.className = "w-full p-3.5 rounded-2xl glass-card border-slate-800 bg-slate-900/40 text-slate-400 hover:border-slate-700 transition-all cursor-pointer flex items-center gap-3";
      num.className = "w-8 h-8 rounded-xl bg-slate-800 text-slate-400 font-bold flex items-center justify-center font-mono text-sm";
    }
  }

  // Update progress bar width
  const pct = ((activeStep + 1) / 6) * 100;
  document.getElementById('pipe-progress-bar').style.width = pct + '%';
}

function nextPipelineStep() {
  const next = (activeStep + 1) % 6;
  setPipelineStep(next, true);
}

function prevPipelineStep() {
  const prev = (activeStep - 1 + 6) % 6;
  setPipelineStep(prev, true);
}

function openEnvelope() {
  const env = document.getElementById('cyber-envelope');
  if (env) env.classList.add('is-open');
}

function toggleEnvelope() {
  const env = document.getElementById('cyber-envelope');
  if (env) env.classList.toggle('is-open');
}

function autoEnvelopeCheck() {
  const env = document.getElementById('cyber-envelope');
  if (env && window.scrollY < 800) {
    env.classList.add('is-open');
  }
}

function startAutoCycle() {
  if (autoCycleTimer) clearInterval(autoCycleTimer);
  autoCycleTimer = setInterval(() => {
    if (!userInteracted) {
      activeStep = (activeStep + 1) % 6;
      setPipelineStep(activeStep, false);
    }
  }, 6000);
}

window.addEventListener('load', () => {
  setPipelineStep(0);
  startAutoCycle();
});
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_landing_page():
    return HTMLResponse(LANDING_PAGE_HTML)

# ---------------------------------------------------------------------------
# 2. CYBER-FORENSICS DASHBOARD (GET /scanner)
# ---------------------------------------------------------------------------
SCANNER_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailSentinel — Cyber-Forensics Threat Scanner</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" integrity="sha256-p4NxAoJBhIIN+hmNHrzRCf9tD/miZyoHS5obTRR9BMY=" crossorigin=""/>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" integrity="sha256-20nQCchB9co0qIjJZRGuk2/Z9VM+kNiyxNV1lvTlZBo=" crossorigin=""></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: { 950: '#040711', 900: '#070d1d', 800: '#0e172e', 700: '#172344', cyan: '#06b6d4' }
      },
      fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] }
    }
  }
}
</script>
<style>
body {
  background-color: #040711;
  background-image: 
    radial-gradient(circle at 10% 20%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
    radial-gradient(circle at 90% 80%, rgba(59, 130, 246, 0.08) 0%, transparent 40%),
    linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px);
  background-size: 100% 100%, 100% 100%, 36px 36px, 36px 36px;
}
.glass-panel {
  background: rgba(14, 23, 46, 0.75);
  backdrop-filter: blur(16px);
  border: 1px solid rgba(59, 130, 246, 0.2);
}
.glass-panel:hover { border-color: rgba(6, 182, 212, 0.4); }
#map { height: 280px; width: 100%; border-radius: 12px; z-index: 10; }
.leaflet-container { background: #070d1d; }
</style>
</head>
<body class="text-slate-100 font-sans min-h-screen p-4 md:p-8 selection:bg-cyan-500 selection:text-white">
<div class="max-w-[1400px] mx-auto space-y-6">

  <!-- Top Navigation Header -->
  <header class="glass-panel rounded-2xl p-4 md:px-6 flex flex-col md:flex-row justify-between items-center gap-4 shadow-2xl">
    <div class="flex items-center gap-3">
      <!-- SVG Logo (Envelope + Shield + Radar) -->
      <svg class="w-8 h-8 text-cyan-400" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4z" fill="url(#shield-grad-sc)" stroke="#06b6d4" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M7 9h10v6H7V9z" fill="#070d1d" stroke="#3b82f6" stroke-width="1.2"/>
        <path d="M7 9l5 3.5L17 9" stroke="#06b6d4" stroke-width="1.2" stroke-linecap="round"/>
        <line x1="4" y1="12" x2="20" y2="12" stroke="#22d3ee" stroke-width="1" stroke-dasharray="2 3" opacity="0.6"/>
        <defs>
          <linearGradient id="shield-grad-sc" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse">
            <stop stop-color="#0e172e" stop-opacity="0.8"/>
            <stop stop-color="#070d1d" stop-opacity="0.95"/>
          </linearGradient>
        </defs>
      </svg>
      <div>
        <div class="flex items-center gap-2">
          <span class="text-base font-extrabold tracking-wider text-white uppercase">MailSentinel</span>
          <span class="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 font-semibold uppercase tracking-wider">v3.2 Core</span>
        </div>
        <p class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Detect. Trace. Defend.</p>
      </div>
    </div>
    
    <!-- Navigation Tabs -->
    <nav class="flex items-center gap-4">
      <a href="/" class="text-xs md:text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors pb-1">Home</a>
      <a href="/scanner" class="text-xs md:text-sm font-semibold text-cyan-400 border-b-2 border-cyan-400 pb-1">Detector</a>
      <a href="/mobile" class="text-xs md:text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors pb-1">Mobile</a>
    </nav>
  </header>

  <!-- TAB 1: THREAT SCANNER -->
  <div id="view-scanner" class="space-y-6">
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
      
      <!-- Ingestion Panel (8 Cols) -->
      <div class="lg:col-span-8 glass-panel rounded-2xl p-6 md:p-8 shadow-xl space-y-5">
        <div class="flex flex-col sm:flex-row justify-between sm:items-center gap-3 border-b border-slate-800/80 pb-4">
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>📥</span> Evidence Ingestion Engine
          </h2>
          <div class="flex items-center gap-1.5">
            <button onclick="openModal('contacts')" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-[11px] font-semibold text-cyan-400 border border-cyan-500/20 hover:border-cyan-500/40 transition-colors flex items-center gap-1">
              👥 Contacts
            </button>
            <button onclick="openModal('ledger')" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-[11px] font-semibold text-cyan-400 border border-cyan-500/20 hover:border-cyan-500/40 transition-colors flex items-center gap-1">
              🗄️ Case History
            </button>
            <button onclick="openModal('metrics')" class="px-2.5 py-1 rounded-lg bg-slate-900 hover:bg-slate-800 text-[11px] font-semibold text-cyan-400 border border-cyan-500/20 hover:border-cyan-500/40 transition-colors flex items-center gap-1">
              📊 Metrics
            </button>
          </div>
        </div>

        <div class="flex items-center gap-2 p-1 bg-slate-950/80 rounded-xl border border-slate-800/80 w-fit text-xs">
          <button onclick="setInputMode('file')" id="mode-btn-file" class="px-4 py-1.5 rounded-lg font-semibold text-cyan-300 bg-cyan-500/10 border border-cyan-500/30 transition-all">
            📁 File (.eml / .pdf)
          </button>
          <button onclick="setInputMode('raw')" id="mode-btn-raw" class="px-4 py-1.5 rounded-lg font-semibold text-slate-400 hover:text-slate-200 transition-all">
            📝 Raw Paste
          </button>
        </div>

        <!-- File Upload Dropzone -->
        <div id="dropzone-panel" class="w-full">
          <div id="drop-area" onclick="document.getElementById('file-upload').click()" class="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-2xl p-10 text-center cursor-pointer bg-slate-950/40 hover:bg-cyan-500/[0.03] transition-all duration-200 group">
            <input type="file" id="file-upload" class="hidden" accept=".eml,message/rfc822,.pdf,application/pdf">
            <div class="text-4xl mb-3 group-hover:scale-110 transition-transform">📂</div>
            <p id="file-selected-name" class="text-sm font-semibold text-slate-200">
              Drag & Drop <span class="text-cyan-400 font-mono">.eml</span> or <span class="text-cyan-400 font-mono">.pdf</span> email evidence
            </p>
            <p class="text-xs text-slate-400 mt-1">or click to browse files from your disk (Maximum 10 MB)</p>
          </div>
        </div>

        <!-- Raw RFC 822 Text Input -->
        <div id="raw-panel" class="hidden w-full">
          <textarea id="raw-input-box" class="w-full h-56 bg-slate-950/80 border border-slate-700/80 rounded-xl p-4 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500/80 resize-y" placeholder="Paste RFC 822 raw headers &amp; body text here...&#10;&#10;From: John Doe (CEO) &lt;ceo@attacker-drop.net&gt;&#10;Subject: URGENT: Wire Transfer Needed&#10;Authentication-Results: mx; spf=fail; dkim=fail"></textarea>
        </div>

        <!-- Run Analysis Button -->
        <button onclick="executeScan()" id="scan-submit-btn" class="w-full py-4 bg-gradient-to-r from-cyan-600 via-blue-600 to-violet-600 hover:from-cyan-500 hover:to-violet-500 text-white font-bold text-sm rounded-xl shadow-lg shadow-cyan-500/25 transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer">
          <span>🔎</span> Execute Forensic Threat Analysis
        </button>

        <!-- Live Cyber Terminal HUD Drawer -->
        <div id="scan-terminal-hud" class="hidden p-4 rounded-xl bg-slate-950/95 border border-cyan-500/40 space-y-2 font-mono text-[11px] text-slate-300 shadow-xl shadow-cyan-500/10">
          <div class="flex items-center justify-between border-b border-slate-800 pb-1.5 text-cyan-400 font-bold">
            <span class="flex items-center gap-2">
              <span class="w-2 h-2 rounded-full bg-cyan-400 animate-ping"></span>
              LIVE FORENSIC INVESTIGATION HUD
            </span>
            <span id="hud-timer" class="text-slate-500">0.0s</span>
          </div>
          <div id="hud-log-stream" class="space-y-1 text-slate-400 max-h-28 overflow-y-auto"></div>
        </div>

        <!-- Quick Load Scenario Pills -->
        <div class="pt-2 flex flex-wrap items-center gap-2.5 text-xs border-t border-slate-800/60">
          <span class="text-slate-400 font-semibold uppercase tracking-wider text-[11px]">Simulations:</span>
          <button onclick="loadScenario('phish')" class="px-3 py-1.5 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/30 transition-colors font-medium">
            🚨 Phishing Attack
          </button>
          <button onclick="loadScenario('spoof')" class="px-3 py-1.5 rounded-lg bg-amber-500/10 hover:bg-amber-500/20 text-amber-400 border border-amber-500/30 transition-colors font-medium">
            🎭 CEO Impersonation (BEC)
          </button>
          <button onclick="loadScenario('clean')" class="px-3 py-1.5 rounded-lg bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 transition-colors font-medium">
            ✅ Clean Newsletter
          </button>
        </div>
      </div>

      <!-- Quick SOC Summary Panel (4 Cols) -->
      <div class="lg:col-span-4 glass-panel rounded-2xl p-6 shadow-xl space-y-5">
        <div>
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2 mb-4 border-b border-slate-800/80 pb-3">
            <span>🛡️</span> Defensive Matrix Status
          </h2>
          <div class="space-y-3 text-xs">
            <div class="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span class="text-slate-400">Impersonation Engine</span>
              <span class="font-semibold text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-[11px]">Active</span>
            </div>
            <div class="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span class="text-slate-400">Threat Intel Feed</span>
              <span class="font-semibold text-emerald-400 px-2 py-0.5 rounded bg-emerald-500/10 border border-emerald-500/30 text-[11px]">Active</span>
            </div>
            <div class="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span class="text-slate-400">Relay Geolocation</span>
              <span class="font-mono text-cyan-400 px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/30 text-[11px]">Live (ip-api.com)</span>
            </div>
            <div class="flex justify-between items-center py-2 border-b border-slate-800/60">
              <span class="text-slate-400">Database Engine</span>
              <span class="font-mono text-slate-300 text-[11px]">SQLite (sentrymail_v3.db)</span>
            </div>
          </div>
        </div>

        <div class="p-4 rounded-xl bg-cyan-500/[0.05] border border-cyan-500/20 text-xs text-slate-300 space-y-1.5 leading-relaxed">
          <div class="font-bold text-cyan-400 flex items-center gap-1.5 text-[11px] uppercase tracking-wider">
            <span>🔒</span> Zero-Fetch Sandbox Guarantee
          </div>
          <p class="text-[11px] text-slate-400">
            Extracted hyperlinks, shorteners, and IP literals are inspected completely offline without sending outbound network requests to suspect domains.
          </p>
        </div>
      </div>
    </div>

    <!-- Forensic Scan Result Section -->
    <div id="results-display" class="hidden space-y-6">
      
      <!-- Section 2: Forensic Risk Assessment -->
      <div id="risk-banner" class="glass-panel rounded-2xl p-6 md:p-8 grid grid-cols-1 md:grid-cols-12 gap-6 items-center border-l-8">
        <!-- Circular Speedometer Ring (5 Cols) -->
        <div class="md:col-span-5 flex items-center gap-5">
          <div class="relative w-24 h-24 flex items-center justify-center flex-shrink-0">
            <svg class="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="42" stroke="currentColor" stroke-width="8" class="text-slate-800/80" fill="transparent" />
              <circle id="risk-gauge-circle" cx="50" cy="50" r="42" stroke="currentColor" stroke-width="8" class="text-cyan-400 transition-all duration-1000 ease-out" fill="transparent" stroke-dasharray="264" stroke-dashoffset="264" stroke-linecap="round" />
            </svg>
            <div class="absolute inset-0 flex flex-col items-center justify-center">
              <span id="metric-risk-score" class="text-2xl md:text-3xl font-black font-mono tracking-tight text-white">0</span>
              <span class="text-[9px] font-mono text-slate-400 font-bold uppercase">/100</span>
            </div>
          </div>
          <div class="space-y-1">
            <div class="text-[10px] uppercase font-bold tracking-widest text-slate-400">Threat Verdict</div>
            <div><span id="metric-risk-badge" class="text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider bg-slate-800 text-slate-300 border border-slate-700">Low</span></div>
            <p id="metric-threat-desc" class="text-xs text-slate-300 pt-1">No anomalous patterns identified.</p>
          </div>
        </div>

        <!-- Middle Confidence Details (4 Cols) -->
        <div class="md:col-span-4 space-y-1 border-t md:border-t-0 md:border-l border-slate-800 md:pl-6 pt-3 md:pt-0">
          <div class="text-[10px] uppercase font-bold tracking-widest text-slate-400">Heuristic Confidence</div>
          <div class="flex items-baseline gap-2">
            <span id="metric-confidence" class="text-3xl md:text-4xl font-black font-mono text-cyan-400">0%</span>
            <span class="text-xs text-slate-400 font-mono">weighted</span>
          </div>
          <p class="text-[11px] text-slate-400">Deterministic explainable static rule heuristics</p>
        </div>

        <!-- Quick Export Buttons (3 Cols) -->
        <div class="md:col-span-3 flex flex-col gap-2 justify-center border-t md:border-t-0 md:border-l border-slate-800 md:pl-6 pt-3 md:pt-0">
          <button onclick="copyForensicBrief()" class="w-full py-2 px-3 rounded-xl bg-slate-900/90 hover:bg-cyan-500/15 border border-cyan-500/30 hover:border-cyan-500/60 text-cyan-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer">
            <span>📋</span> Copy Incident JSON
          </button>
          <button onclick="copySummaryText()" class="w-full py-2 px-3 rounded-xl bg-slate-900/90 hover:bg-violet-500/15 border border-slate-700 hover:border-violet-500/50 text-slate-300 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer">
            <span>📄</span> Copy Brief Text
          </button>
        </div>
      </div>

      <!-- Flow Connector -->
      <div class="flex justify-center text-slate-600 font-bold my-1 text-sm select-none">↓</div>

      <!-- Section 3: Sender Identity & Authentication -->
      <div class="glass-panel rounded-2xl p-6 space-y-4">
        <h3 class="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <span>👤</span> Sender Identity &amp; Impersonation Audit
        </h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-2 text-xs">
          <div class="flex justify-between py-1.5 border-b border-slate-800/80">
            <span class="text-slate-400">Case ID:</span>
            <span id="out-case-id" class="font-mono text-cyan-300 font-semibold"></span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/80">
            <span class="text-slate-400">Evidence SHA-256:</span>
            <span id="out-sha256" class="font-mono text-slate-400 truncate max-w-[240px]"></span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/80">
            <span class="text-slate-400">From Header:</span>
            <span id="out-from" class="font-semibold text-slate-200"></span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/80">
            <span class="text-slate-400">Reply-To Routing:</span>
            <span id="out-reply" class="font-semibold text-slate-300"></span>
          </div>
          <div class="flex justify-between py-1.5 border-b border-slate-800/80 col-span-1 md:col-span-2">
            <span class="text-slate-400">Subject:</span>
            <span id="out-subject" class="font-semibold text-slate-200 truncate"></span>
          </div>
        </div>
        <div id="out-auth-pills" class="flex flex-wrap gap-2 pt-2"></div>
      </div>

      <!-- Flow Connector -->
      <div class="flex justify-center text-slate-600 font-bold my-1 text-sm select-none">↓</div>

      <!-- Section 4: Relay-Hop Map -->
      <div class="glass-panel rounded-2xl p-6 space-y-4">
        <h3 class="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <span>🌐</span> Animated Relay-Hop Map &amp; Route Sequence
        </h3>
        <div id="map-container" class="space-y-3">
          <div id="map" class="w-full h-80 rounded-xl border border-slate-800"></div>
          <div id="map-hop-legend" class="text-[11px] text-slate-400 font-mono pt-1"></div>
        </div>

        <div class="border-t border-slate-800/50 pt-4">
          <h3 class="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2 mb-2">
            <span>📎</span> Embedded Payloads &amp; Attachments (<span id="out-attach-count">0</span>)
          </h3>
          <div id="out-attach-list" class="space-y-2 text-xs"></div>
        </div>
      </div>

      <!-- Flow Connector -->
      <div class="flex justify-center text-slate-600 font-bold my-1 text-sm select-none">↓</div>

      <!-- Section 5: Sender Intelligence Panel -->
      <div id="sender-intel-panel" class="glass-panel rounded-2xl p-6 space-y-4 border border-cyan-500/15">
        <div class="flex items-center justify-between">
          <h3 class="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <span>🔎</span> Sender Intelligence
          </h3>
          <span id="si-threshold-badge" class="text-xs px-2.5 py-1 rounded-full bg-slate-800 border border-slate-700 text-slate-400 font-mono">Threshold: 70+</span>
        </div>

        <!-- Locked state (risk < threshold) -->
        <div id="si-locked" class="flex flex-col items-center justify-center py-6 space-y-2 text-center">
          <div class="text-3xl">🔒</div>
          <p class="text-sm font-semibold text-slate-400">Sender Intelligence is locked</p>
          <p class="text-xs text-slate-500">Available for high-risk cases (score &ge; <span id="si-locked-threshold">70</span>)</p>
        </div>

        <!-- Active / loading state -->
        <div id="si-active" class="hidden space-y-4">
          <!-- Loading spinner -->
          <div id="si-loading" class="flex items-center gap-2 text-xs text-cyan-400 py-2">
            <span class="animate-spin inline-block">&#9881;&#65039;</span> Querying public intelligence sources...
          </div>

          <!-- Info grid (shown after load) -->
          <div id="si-grid" class="hidden grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1 text-xs">
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Sender Address</span>
              <span id="si-address" class="font-mono text-slate-200 font-semibold truncate max-w-[200px]"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Domain</span>
              <span id="si-domain" class="font-mono text-cyan-300 font-semibold"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Domain Age</span>
              <span id="si-age" class="font-semibold text-slate-200"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Registrar</span>
              <span id="si-registrar" class="text-slate-300 truncate max-w-[200px]"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Created / Expires</span>
              <span id="si-dates" class="text-slate-400 font-mono text-[11px]"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">MX Records</span>
              <span id="si-mx" class="text-slate-300"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">SPF Record</span>
              <span id="si-spf" class="font-mono text-[11px] text-slate-300 truncate max-w-[200px]"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">DMARC Policy</span>
              <span id="si-dmarc" class="font-mono text-slate-300"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Reputation</span>
              <span id="si-reputation" class="font-semibold text-slate-200"></span>
            </div>
            <div class="flex justify-between py-1.5 border-b border-slate-800/60">
              <span class="text-slate-400">Known Threat Match</span>
              <span id="si-threat-match" class="font-bold"></span>
            </div>
          </div>

          <!-- Intelligence Indicators -->
          <div id="si-indicators-section" class="hidden space-y-2">
            <h4 class="text-xs font-bold uppercase tracking-wider text-amber-400 flex items-center gap-2">
              <span>&#9888;&#65039;</span> Intelligence Indicators
            </h4>
            <div id="si-indicators-list" class="space-y-1.5 max-h-48 overflow-y-auto pr-1"></div>
          </div>

          <!-- Error state -->
          <div id="si-error" class="hidden text-xs text-red-400 py-2 px-3 bg-red-900/20 rounded-lg border border-red-500/20"></div>

          <!-- Disclaimer -->
          <div class="text-[11px] text-slate-600 border-t border-slate-800/50 pt-3 leading-relaxed italic">
            Information shown here is based on publicly available technical and threat-intelligence sources. IP/domain locations and registration data may be approximate or incomplete. MailSentinel does not visit, download, or execute content from extracted URLs.
          </div>
        </div>
      </div>

      <!-- Flow Connector -->
      <div class="flex justify-center text-slate-600 font-bold my-1 text-sm select-none">↓</div>

      <!-- Section 6: Extracted URLs & Threat Intelligence -->
      <div class="glass-panel rounded-2xl p-6 space-y-3">
        <h3 class="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <span>🔗</span> Extracted URLs &amp; Threat Database Match (<span id="out-url-count">0</span>)
        </h3>
        <div id="out-url-list" class="max-h-60 overflow-y-auto space-y-2 pr-1"></div>
      </div>

      <!-- Flow Connector -->
      <div class="flex justify-center text-slate-600 font-bold my-1 text-sm select-none">↓</div>

      <!-- Section 7: Weighted Heuristics Evidence Ledger (Final Verdict) -->
      <div class="glass-panel rounded-2xl p-6 space-y-3">
        <h3 class="text-sm font-bold uppercase tracking-wider text-slate-400 flex items-center gap-2">
          <span>📋</span> Weighted Heuristics Evidence Ledger
        </h3>
        <div id="out-findings-list" class="max-h-60 overflow-y-auto space-y-2 pr-1"></div>
      </div>

    </div>
  </div>

  <!-- Modal overlay container for secondary database views -->
  <div id="modal-container" class="fixed inset-0 z-[9999] hidden bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="relative glass-panel rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-y-auto p-6 md:p-8 shadow-2xl space-y-4">
      
      <!-- Close button -->
      <button onclick="closeModal()" class="absolute top-4 right-4 text-slate-400 hover:text-slate-200 text-2xl font-bold transition-colors select-none focus:outline-none">
        &times;
      </button>

      <!-- Inner modal view: Contacts -->
      <div id="modal-contacts" class="hidden space-y-6">
        <div class="border-b border-slate-800 pb-3">
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>👥</span> Trusted Contacts Whitelist
          </h2>
          <p class="text-xs text-slate-400">Manage contacts whose display names are protected against spoofing/BEC lookalike domains.</p>
        </div>

        <!-- Add Contact Form -->
        <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 bg-slate-900/60 p-4 rounded-xl border border-slate-800 text-xs">
          <div>
            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Contact Name</label>
            <input type="text" id="inp-contact-name" class="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500" placeholder="e.g. John Doe (CEO)">
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Authorized Domain</label>
            <input type="text" id="inp-contact-domain" class="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500" placeholder="e.g. corp.com">
          </div>
          <div>
            <label class="block text-[11px] font-semibold text-slate-400 mb-1">Role Notes (Optional)</label>
            <input type="text" id="inp-contact-notes" class="w-full bg-slate-950 border border-slate-700/80 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500" placeholder="e.g. Executive Board">
          </div>
          <div class="flex items-end">
            <button onclick="addTrustedContact()" class="w-full py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs rounded-lg transition-colors">
              + Add Contact
            </button>
          </div>
        </div>

        <!-- Contacts Table -->
        <div class="overflow-x-auto max-h-[40vh] overflow-y-auto pr-1">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-800">
              <tr>
                <th class="py-2.5 px-4">Contact Name</th>
                <th class="py-2.5 px-4">Authorized Domain</th>
                <th class="py-2.5 px-4">Notes</th>
                <th class="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="contacts-table-body" class="divide-y divide-slate-800/60 font-medium">
              <tr><td colspan="4" class="py-6 text-center text-slate-500">Loading contacts...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Inner modal view: Ledger -->
      <div id="modal-ledger" class="hidden space-y-4">
        <div class="flex justify-between items-center border-b border-slate-800 pb-3">
          <div>
            <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
              <span>🗄️</span> SQLite Forensic Case Ledger
            </h2>
            <p class="text-xs text-slate-400">Historical email scans persisted in <code>sentrymail_v3.db</code>.</p>
          </div>
          <button onclick="refreshLedger()" class="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-xs font-semibold rounded-lg text-slate-200 border border-slate-700 transition-colors">
            🔄 Refresh
          </button>
        </div>

        <div class="overflow-x-auto max-h-[50vh] overflow-y-auto pr-1">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/60 uppercase font-semibold text-slate-400 border-b border-slate-800">
              <tr>
                <th class="py-2.5 px-4">Case ID</th>
                <th class="py-2.5 px-4">Subject &amp; Sender</th>
                <th class="py-2.5 px-4">Risk Level</th>
                <th class="py-2.5 px-4">Confidence</th>
                <th class="py-2.5 px-4">Date</th>
                <th class="py-2.5 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="ledger-table-body" class="divide-y divide-slate-800/60 font-medium">
              <tr><td colspan="6" class="py-6 text-center text-slate-500">Loading cases...</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Inner modal view: Metrics -->
      <div id="modal-metrics" class="hidden space-y-6">
        <div class="border-b border-slate-800 pb-3">
          <h2 class="text-base font-bold text-slate-100 flex items-center gap-2">
            <span>📊</span> Security Operations Metrics
          </h2>
          <p class="text-xs text-slate-400">Real-time statistics of analyzed emails and threats detected.</p>
        </div>

        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="glass-panel rounded-xl p-5 space-y-1">
            <div class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Total Scans Executed</div>
            <div id="metric-total-scans" class="text-3xl font-black font-mono text-cyan-400">--</div>
          </div>
          <div class="glass-panel rounded-xl p-5 space-y-1">
            <div class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Critical Threats Intercepted</div>
            <div id="metric-threats-count" class="text-3xl font-black font-mono text-red-400">--</div>
          </div>
          <div class="glass-panel rounded-xl p-5 space-y-1">
            <div class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Impersonation Alerts</div>
            <div id="metric-imp-count" class="text-3xl font-black font-mono text-amber-400">--</div>
          </div>
          <div class="glass-panel rounded-xl p-5 space-y-1">
            <div class="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">Clean Communications</div>
            <div id="metric-clean-count" class="text-3xl font-black font-mono text-emerald-400">--</div>
          </div>
        </div>

        <div class="glass-panel rounded-xl p-5 space-y-3">
          <h3 class="text-xs font-bold text-slate-100 uppercase tracking-wider">MailSentinel Detection Matrix</h3>
          <div class="text-xs leading-relaxed text-slate-400 space-y-1.5">
            <p>• <b>Executive BEC Impersonation:</b> +20 pts on From display name vs trusted domain mismatch.</p>
            <p>• <b>Threat Intelligence Database:</b> +25 pts on known phishing domains.</p>
            <p>• <b>Cryptographic Auth:</b> +10 pts per SPF/DKIM/DMARC failure (capped at 30 pts).</p>
            <p>• <b>Relay Hop Mapping:</b> Geolocates public intermediate MTAs via live ip-api.com.</p>
          </div>
        </div>
      </div>

    </div>
  </div>

</div>

<script>
let currentMode = 'file';
let selectedFile = null;
let leafletMap = null;
let hopMarkers = [];
let routePolyline = null;

function initLeafletMap() {
  if (!leafletMap && document.getElementById('map')) {
    leafletMap = L.map('map').setView([20, 0], 2);
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      attribution: '&copy; CartoDB &copy; OpenStreetMap',
      maxZoom: 18
    }).addTo(leafletMap);
  }
}

function openModal(modalId) {
  const container = document.getElementById('modal-container');
  container.classList.remove('hidden');
  ['contacts', 'ledger', 'metrics'].forEach(m => {
    document.getElementById('modal-' + m).classList.add('hidden');
  });
  document.getElementById('modal-' + modalId).classList.remove('hidden');
  if (modalId === 'contacts') loadContacts();
  if (modalId === 'ledger') refreshLedger();
  if (modalId === 'metrics') updateMetrics();
}

function closeModal() {
  document.getElementById('modal-container').classList.add('hidden');
}

function switchTab(tabId) {
  if (['contacts', 'ledger', 'metrics'].includes(tabId)) {
    openModal(tabId);
  }
}

function setInputMode(mode) {
  currentMode = mode;
  document.getElementById('dropzone-panel').classList.toggle('hidden', mode !== 'file');
  document.getElementById('raw-panel').classList.toggle('hidden', mode !== 'raw');
  
  document.getElementById('mode-btn-file').className = mode === 'file' 
    ? 'px-3 py-1 rounded-lg font-medium text-cyan-300 bg-cyan-500/10 border border-cyan-500/30' 
    : 'px-3 py-1 rounded-lg font-medium text-slate-400 hover:text-slate-200';
  document.getElementById('mode-btn-raw').className = mode === 'raw' 
    ? 'px-3 py-1 rounded-lg font-medium text-cyan-300 bg-cyan-500/10 border border-cyan-500/30' 
    : 'px-3 py-1 rounded-lg font-medium text-slate-400 hover:text-slate-200';
}

const dropArea = document.getElementById('drop-area');
const fileUpload = document.getElementById('file-upload');

['dragenter', 'dragover'].forEach(eventName => {
  dropArea.addEventListener(eventName, (e) => { e.preventDefault(); dropArea.classList.add('border-cyan-500', 'bg-cyan-500/10'); });
});
['dragleave', 'drop'].forEach(eventName => {
  dropArea.addEventListener(eventName, (e) => { e.preventDefault(); dropArea.classList.remove('border-cyan-500', 'bg-cyan-500/10'); });
});
dropArea.addEventListener('drop', (e) => {
  if (e.dataTransfer.files && e.dataTransfer.files[0]) {
    selectedFile = e.dataTransfer.files[0];
    document.getElementById('file-selected-name').innerHTML = `Selected: <span class="text-cyan-400 font-mono">${selectedFile.name}</span>`;
  }
});
fileUpload.addEventListener('change', () => {
  if (fileUpload.files && fileUpload.files[0]) {
    selectedFile = fileUpload.files[0];
    document.getElementById('file-selected-name').innerHTML = `Selected: <span class="text-cyan-400 font-mono">${selectedFile.name}</span>`;
  }
});

let lastAnalysisData = null;

function showToast(msg) {
  let toast = document.getElementById('global-toast');
  if (!toast) {
    toast = document.createElement('div');
    toast.id = 'global-toast';
    toast.className = 'fixed bottom-6 right-6 z-50 px-4 py-2.5 rounded-xl bg-slate-900/95 border border-cyan-500/50 text-cyan-300 font-mono text-xs shadow-2xl shadow-cyan-500/20 transition-all duration-300 transform translate-y-10 opacity-0 flex items-center gap-2';
    document.body.appendChild(toast);
  }
  toast.innerHTML = `<span class="text-emerald-400">✓</span> ${msg}`;
  toast.classList.remove('translate-y-10', 'opacity-0');
  setTimeout(() => {
    toast.classList.add('translate-y-10', 'opacity-0');
  }, 2800);
}

function copyForensicBrief() {
  if (!lastAnalysisData) return;
  const brief = JSON.stringify(lastAnalysisData, null, 2);
  navigator.clipboard.writeText(brief).then(() => {
    showToast('Incident JSON copied to clipboard!');
  }).catch(() => {
    showToast('Copied to clipboard');
  });
}

function copySummaryText() {
  if (!lastAnalysisData) return;
  const d = lastAnalysisData;
  const summary = `[MAILSENTINEL FORENSIC INCIDENT BRIEF]
Case ID: ${d.case_id}
Threat Verdict: ${d.risk_level} (Score: ${d.risk_score}/100)
Confidence: ${d.confidence}%
Threat Summary: ${d.threat}
Sender: ${d.sender.display_name || ''} <${d.sender.address || 'Unknown'}>
Subject: ${d.subject || 'None'}
SPF: ${d.authentication.spf} | DKIM: ${d.authentication.dkim} | DMARC: ${d.authentication.dmarc}
Relay Hops: ${d.relay_geo_hops ? d.relay_geo_hops.length : 0} observed
SHA-256: ${d.evidence_sha256}`;
  navigator.clipboard.writeText(summary).then(() => {
    showToast('Forensic summary text copied!');
  }).catch(() => {
    showToast('Summary copied');
  });
}

async function streamHudLogs() {
  const hud = document.getElementById('scan-terminal-hud');
  const stream = document.getElementById('hud-log-stream');
  const timer = document.getElementById('hud-timer');
  hud.classList.remove('hidden');
  stream.innerHTML = '';
  
  const logs = [
    { t: 80, msg: '⚡ Isolating MIME payload envelope in zero-fetch sandbox...' },
    { t: 220, msg: '🔑 Evaluating SPF, DKIM & DMARC cryptographic seal verification...' },
    { t: 450, msg: '🌐 Extracting SMTP Received: headers & querying relay geolocation...' },
    { t: 650, msg: '🔎 Parsing hyperlinks, shorteners, IP-literals & known threat feeds...' },
    { t: 820, msg: '🛡️ Computing deterministic weighted heuristics & generating verdict...' }
  ];

  let start = Date.now();
  for (const item of logs) {
    await new Promise(r => setTimeout(r, item.t));
    const elapsed = ((Date.now() - start) / 1000).toFixed(1);
    timer.textContent = `${elapsed}s`;
    const line = document.createElement('div');
    line.className = 'flex items-center gap-1.5 text-[11px] animate-fadeIn';
    line.innerHTML = `<span class="text-cyan-400 font-bold">[+${elapsed}s]</span> <span class="text-slate-200">${item.msg}</span>`;
    stream.appendChild(line);
    stream.scrollTop = stream.scrollHeight;
  }
}

async function executeScan() {
  const btn = document.getElementById('scan-submit-btn');
  btn.disabled = true;
  btn.innerHTML = '<span class="animate-spin inline-block mr-2">⚙️</span> Processing Forensic Threat Analysis...';

  try {
    const logPromise = streamHudLogs();
    let res;
    if (currentMode === 'file') {
      if (!selectedFile) throw new Error('Please select or drop an .eml or .pdf file first.');
      const fd = new FormData();
      fd.append('file', selectedFile);
      const r = await fetch('/api/analyze', { method: 'POST', body: fd });
      res = await r.json();
      if (!r.ok) throw new Error(res.detail || 'Forensic analysis failed');
    } else {
      const text = document.getElementById('raw-input-box').value;
      if (!text.trim()) throw new Error('Please paste raw email headers & body text.');
      const r = await fetch('/api/analyze-raw', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ raw_text: text })
      });
      res = await r.json();
      if (!r.ok) throw new Error(res.detail || 'Forensic analysis failed');
    }
    await logPromise;
    lastAnalysisData = res;
    renderForensicReport(res);
  } catch (err) {
    alert(err.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🔍</span> Execute Forensic Threat Analysis';
  }
}

function animateOdometer(el, target, duration = 800) {
  let start = 0;
  let startTime = null;
  function step(timestamp) {
    if (!startTime) startTime = timestamp;
    const progress = Math.min((timestamp - startTime) / duration, 1);
    const current = Math.floor(progress * target);
    el.textContent = `${current}`;
    if (progress < 1) {
      window.requestAnimationFrame(step);
    } else {
      el.textContent = `${target}`;
    }
  }
  window.requestAnimationFrame(step);
}

function renderForensicReport(d) {
  document.getElementById('results-display').classList.remove('hidden');

  const banner = document.getElementById('risk-banner');
  const riskNum = document.getElementById('metric-risk-score');
  const riskBadge = document.getElementById('metric-risk-badge');
  const gaugeCircle = document.getElementById('risk-gauge-circle');

  // Animate Circular Gauge
  const maxDash = 264;
  const offset = maxDash - (maxDash * (d.risk_score / 100));
  gaugeCircle.style.strokeDashoffset = offset;

  if (d.risk_level === 'Critical Threat' || d.risk_level === 'High Risk') {
    banner.className = 'glass-panel rounded-2xl p-6 md:p-8 grid grid-cols-1 md:grid-cols-12 gap-6 items-center border-l-8 border-rose-500 shadow-xl shadow-rose-500/10';
    riskNum.className = 'text-2xl md:text-3xl font-black font-mono tracking-tight text-rose-400';
    riskBadge.className = 'text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/40';
    gaugeCircle.setAttribute('class', 'text-rose-500 transition-all duration-1000 ease-out');
  } else if (d.risk_level === 'Suspicious') {
    banner.className = 'glass-panel rounded-2xl p-6 md:p-8 grid grid-cols-1 md:grid-cols-12 gap-6 items-center border-l-8 border-amber-500 shadow-xl shadow-amber-500/10';
    riskNum.className = 'text-2xl md:text-3xl font-black font-mono tracking-tight text-amber-400';
    riskBadge.className = 'text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider bg-amber-500/20 text-amber-300 border border-amber-500/40';
    gaugeCircle.setAttribute('class', 'text-amber-400 transition-all duration-1000 ease-out');
  } else if (d.risk_level === 'Moderate') {
    banner.className = 'glass-panel rounded-2xl p-6 md:p-8 grid grid-cols-1 md:grid-cols-12 gap-6 items-center border-l-8 border-yellow-500 shadow-xl shadow-yellow-500/10';
    riskNum.className = 'text-2xl md:text-3xl font-black font-mono tracking-tight text-yellow-400';
    riskBadge.className = 'text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider bg-yellow-500/20 text-yellow-300 border border-yellow-500/40';
    gaugeCircle.setAttribute('class', 'text-yellow-400 transition-all duration-1000 ease-out');
  } else {
    banner.className = 'glass-panel rounded-2xl p-6 md:p-8 grid grid-cols-1 md:grid-cols-12 gap-6 items-center border-l-8 border-emerald-500 shadow-xl shadow-emerald-500/10';
    riskNum.className = 'text-2xl md:text-3xl font-black font-mono tracking-tight text-emerald-400';
    riskBadge.className = 'text-xs px-3 py-1 rounded-full font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/40';
    gaugeCircle.setAttribute('class', 'text-emerald-400 transition-all duration-1000 ease-out');
  }

  animateOdometer(riskNum, d.risk_score);
  riskBadge.textContent = d.risk_level;
  document.getElementById('metric-threat-desc').textContent = d.threat;
  document.getElementById('metric-confidence').textContent = `${d.confidence}%`;

  document.getElementById('out-case-id').textContent = d.case_id;
  document.getElementById('out-sha256').textContent = d.evidence_sha256;
  document.getElementById('out-from').textContent = `${d.sender.display_name || ''} <${d.sender.address || 'Unknown'}>`;
  document.getElementById('out-reply').textContent = d.reply_to || 'None (Matches From Domain)';
  document.getElementById('out-subject').textContent = d.subject || 'No Subject';

  const authDiv = document.getElementById('out-auth-pills');
  authDiv.innerHTML = Object.entries(d.authentication).map(([k, v]) => `
    <span class="px-2.5 py-1 rounded-lg text-xs font-mono font-bold uppercase ${v === 'pass' ? 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30' : v === 'fail' ? 'bg-rose-500/15 text-rose-300 border border-rose-500/30' : 'bg-slate-800 text-slate-400 border border-slate-700'}">
      ${k}: ${v}
    </span>
  `).join('');

  // Priority 3: Render Leaflet Map with Real Geolocation Hops
  renderRelayMap(d.relay_geo_hops || []);

  document.getElementById('out-attach-count').textContent = d.attachments.length;
  document.getElementById('out-attach-list').innerHTML = d.attachments.length ? d.attachments.map(a => `
    <div class="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800 flex justify-between items-center">
      <div>
        <span class="font-bold text-slate-200">${a.filename}</span>
        <span class="text-slate-500 ml-1">(${a.size} B)</span>
      </div>
      <div class="font-mono text-xs text-slate-400">
        ${a.risk ? '<span class="px-2 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/40 text-[10px] font-bold mr-2 uppercase">RISKY EXTENSION</span>' : ''}
        ${a.sha256.substring(0, 12)}...
      </div>
    </div>
  `).join('') : '<p class="text-slate-500 italic">No attachments detected in payload</p>';

  document.getElementById('out-url-count').textContent = d.url_details.length;
  document.getElementById('out-url-list').innerHTML = d.url_details.length ? d.url_details.map(u => `
    <div class="p-2.5 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col gap-1">
      <code class="text-xs text-cyan-300 font-mono truncate">${u.url}</code>
      <div class="flex flex-wrap gap-1.5">
        ${u.flags.map(f => `<span class="px-2 py-0.5 rounded ${f === 'known-malicious' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/40' : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'} text-[10px] uppercase font-bold">${f}</span>`).join('')}
      </div>
    </div>
  `).join('') : '<p class="text-slate-500 text-xs italic">No URLs found in email body</p>';

  document.getElementById('out-findings-list').innerHTML = d.findings.length ? d.findings.map(f => `
    <div class="p-3 rounded-xl bg-slate-950/60 border-l-4 ${f.points >= 20 ? 'border-rose-500 bg-rose-950/10' : f.points >= 10 ? 'border-amber-500 bg-amber-950/10' : 'border-cyan-500'} border border-slate-800 space-y-1">
      <div class="flex justify-between items-center">
        <span class="font-bold text-xs text-slate-200">${f.category}</span>
        <span class="font-mono font-bold text-xs text-cyan-400">+${f.points} pts</span>
      </div>
      <p class="text-xs text-slate-400">${f.evidence}</p>
    </div>
  `).join('') : '<p class="text-slate-500 text-xs italic">No weighted suspicious indicators found</p>';

  document.getElementById('results-display').scrollIntoView({ behavior: 'smooth' });

  // Trigger Sender Intelligence panel (threshold-gated)
  triggerSenderIntelligence(d.sender, d.risk_score);
}

// ---------------------------------------------------------------------------
// Sender Intelligence Panel
// ---------------------------------------------------------------------------
const SI_THRESHOLD = 70; // Must match backend RISK_THRESHOLD default

function triggerSenderIntelligence(sender, riskScore) {
  const locked  = document.getElementById('si-locked');
  const active  = document.getElementById('si-active');
  const loading = document.getElementById('si-loading');
  const grid    = document.getElementById('si-grid');
  const errEl   = document.getElementById('si-error');
  const badge   = document.getElementById('si-threshold-badge');
  const threshEl = document.getElementById('si-locked-threshold');

  // Update threshold display
  badge.textContent = `Threshold: ${SI_THRESHOLD}+`;
  threshEl.textContent = SI_THRESHOLD;

  if (riskScore < SI_THRESHOLD) {
    // Show locked state
    locked.classList.remove('hidden');
    active.classList.add('hidden');
    return;
  }

  // Show active state with loading
  locked.classList.add('hidden');
  active.classList.remove('hidden');
  loading.classList.remove('hidden');
  grid.classList.add('hidden');
  errEl.classList.add('hidden');
  document.getElementById('si-indicators-section').classList.add('hidden');

  const domain  = sender.domain || '';
  const address = sender.address || '';
  if (!domain) {
    loading.classList.add('hidden');
    errEl.textContent = 'No sender domain available for intelligence lookup.';
    errEl.classList.remove('hidden');
    return;
  }

  const url = `/api/sender-intelligence?domain=${encodeURIComponent(domain)}&address=${encodeURIComponent(address)}&risk_score=${riskScore}`;
  fetch(url)
    .then(r => r.json())
    .then(si => {
      loading.classList.add('hidden');
      if (si.error) {
        errEl.textContent = `Intelligence error: ${si.error}`;
        errEl.classList.remove('hidden');
        return;
      }

      // --- Populate domain registration ---
      const reg = si.domain_reg || {};
      document.getElementById('si-address').textContent = address || '—';
      document.getElementById('si-domain').textContent  = domain;
      document.getElementById('si-age').textContent     = reg.age_label || reg.note || 'Unknown';

      // Color-code age
      const ageEl = document.getElementById('si-age');
      if (reg.age_days != null && reg.age_days < 30) {
        ageEl.className = 'font-bold text-red-400';
      } else if (reg.age_days != null && reg.age_days < 180) {
        ageEl.className = 'font-semibold text-amber-400';
      } else {
        ageEl.className = 'font-semibold text-slate-200';
      }

      document.getElementById('si-registrar').textContent = reg.registrar || 'Unknown';

      const created = reg.creation_date || '—';
      const expires = reg.expiry_date   || '—';
      document.getElementById('si-dates').textContent = `${created} → ${expires}`;

      // --- Populate DNS ---
      const dns = si.dns || {};
      const mx  = dns.mx  || {};
      document.getElementById('si-mx').textContent = mx.status === 'found'
        ? (mx.records || []).slice(0, 2).join(', ') || 'Found'
        : mx.status === 'source_unavailable' ? 'Source unavailable'
        : 'Not found';

      const spf = dns.spf || {};
      document.getElementById('si-spf').textContent = spf.record
        ? spf.record.substring(0, 40) + (spf.record.length > 40 ? '…' : '')
        : spf.status === 'source_unavailable' ? 'Source unavailable'
        : 'No SPF record';

      const dmarc = dns.dmarc || {};
      const dmarcPolicy = dmarc.policy
        ? `v=DMARC1; p=${dmarc.policy}`
        : dmarc.status === 'found' ? 'Found (no policy)'
        : dmarc.status === 'source_unavailable' ? 'Source unavailable'
        : 'No DMARC';
      const dmarcEl = document.getElementById('si-dmarc');
      dmarcEl.textContent = dmarcPolicy;
      dmarcEl.className = dmarc.status === 'found' && dmarc.policy === 'reject'
        ? 'font-mono text-emerald-400'
        : dmarc.status !== 'found' ? 'font-mono text-red-400'
        : 'font-mono text-amber-400';

      // --- Populate reputation ---
      const rep = si.reputation || {};
      const repLabel = rep.reputation_label || 'Unknown';
      const repEl = document.getElementById('si-reputation');
      repEl.textContent = repLabel;
      repEl.className = repLabel.includes('Malicious') || repLabel.includes('Confirmed')
        ? 'font-bold text-red-400'
        : repLabel.includes('High') ? 'font-bold text-red-400'
        : repLabel.includes('Moderate') ? 'font-bold text-amber-400'
        : 'font-semibold text-emerald-400';

      // --- Known threat match ---
      const localFeed = (rep.local_feed || {});
      const isThreat  = localFeed.status === 'match';
      const tmEl = document.getElementById('si-threat-match');
      tmEl.textContent = isThreat ? `YES — ${localFeed.category || 'Malicious'}` : 'No known matches';
      tmEl.className = isThreat ? 'font-bold text-red-400' : 'font-semibold text-emerald-400';

      // --- Indicators ---
      const indicators = si.indicators || [];
      if (indicators.length > 0) {
        document.getElementById('si-indicators-section').classList.remove('hidden');
        document.getElementById('si-indicators-list').innerHTML = indicators.map(ind => `
          <div class="p-2.5 rounded-lg bg-slate-950/60 border-l-4 ${ind.points >= 15 ? 'border-red-500' : ind.points >= 8 ? 'border-amber-500' : 'border-cyan-500'} border border-slate-800 flex gap-3">
            <span class="font-mono font-bold text-xs ${ind.points >= 15 ? 'text-red-400' : ind.points >= 8 ? 'text-amber-400' : 'text-cyan-400'} shrink-0">+${ind.points}</span>
            <div>
              <div class="text-xs font-semibold text-slate-200">${ind.label}</div>
              <div class="text-[11px] text-slate-400 mt-0.5">${ind.detail || ''}</div>
            </div>
          </div>
        `).join('');
      }

      grid.classList.remove('hidden');
    })
    .catch(err => {
      loading.classList.add('hidden');
      errEl.textContent = `Source unavailable: ${err.message}`;
      errEl.classList.remove('hidden');
    });
}

function renderRelayMap(geoHops) {
  initLeafletMap();
  setTimeout(() => { leafletMap.invalidateSize(); }, 150);

  // Clear previous markers & lines
  hopMarkers.forEach(m => leafletMap.removeLayer(m));
  hopMarkers = [];
  if (routePolyline) leafletMap.removeLayer(routePolyline);

  const geocodedPoints = [];
  const legendEl = document.getElementById('map-hop-legend');
  let legendHtml = '';

  geoHops.forEach((hop, idx) => {
    // A hop is non-public if is_public===false OR is_private===true (backward compat)
    const isNonPublic = hop.is_public === false || hop.is_private === true;

    if (hop.geolocated && hop.lat != null && hop.lon != null) {
      const latlng = [hop.lat, hop.lon];
      geocodedPoints.push(latlng);
      
      const customIcon = L.divIcon({
        className: 'custom-div-icon',
        html: `<div style="background:#06b6d4; width:14px; height:14px; border-radius:50%; border:2px solid white; box-shadow:0 0 12px #06b6d4;"></div>`,
        iconSize: [14, 14],
        iconAnchor: [7, 7]
      });

      const orgLine = [hop.isp, hop.org].filter(Boolean).join(' / ') || hop.org || '';
      const regionLine = [hop.city, hop.region, hop.country].filter(Boolean).join(', ');
      const marker = L.marker(latlng, { icon: customIcon }).addTo(leafletMap)
        .bindPopup(`
          <b>Mail Relay Hop #${idx+1}</b><br>
          <code style="font-size:11px">${hop.ip}</code><br>
          📍 <b>${regionLine}</b><br>
          ${orgLine ? `🏢 <small>${orgLine}</small><br>` : ''}
          ${hop.asn ? `🔗 <small>${hop.asn}</small>` : ''}
        `);
      hopMarkers.push(marker);

      legendHtml += `<span class="inline-block mr-3 mb-1">📍 Hop #${idx+1}: <b class="text-cyan-300">${hop.city}, ${hop.country}</b> <span class="text-slate-400 font-mono text-xs">(${hop.ip})</span></span>`;

    } else if (isNonPublic) {
      // Private/internal — never plotted, clearly labeled
      legendHtml += `<span class="inline-block mr-3 mb-1 text-slate-500">🔒 Hop #${idx+1}: <b class="text-slate-400">Internal/Local Hop</b> <span class="font-mono text-xs">(${hop.ip})</span></span>`;

    } else {
      // Public IP but geolocation failed — show as unavailable, not USA
      legendHtml += `<span class="inline-block mr-3 mb-1 text-amber-400/90">⚠️ Hop #${idx+1}: <b class="text-amber-400">Location unavailable</b> <span class="font-mono text-xs">(${hop.ip})</span></span>`;
    }
  });

  if (geocodedPoints.length > 1) {
    routePolyline = L.polyline(geocodedPoints, {
      color: '#06b6d4',
      weight: 3,
      opacity: 0.8,
      dashArray: '6, 8',
      className: 'pulse-line'
    }).addTo(leafletMap);
    leafletMap.fitBounds(routePolyline.getBounds(), { padding: [30, 30] });
  } else if (geocodedPoints.length === 1) {
    leafletMap.setView(geocodedPoints[0], 5);
  } else {
    leafletMap.setView([20, 0], 2);
  }

  legendEl.innerHTML = legendHtml || '<span class="text-slate-500">No relay IP hops detected in Received: headers</span>';
}


async function loadContacts() {
  const tbody = document.getElementById('contacts-table-body');
  try {
    const r = await fetch('/api/contacts');
    const contacts = await r.json();
    if (!contacts.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="py-6 text-center text-slate-500">No trusted contacts added yet.</td></tr>';
      return;
    }
    tbody.innerHTML = contacts.map(c => `
      <tr class="hover:bg-slate-800/30 transition-colors">
        <td class="py-3 px-4 font-bold text-slate-200">${c.name}</td>
        <td class="py-3 px-4 font-mono text-cyan-300">@${c.real_domain}</td>
        <td class="py-3 px-4 text-slate-400">${c.notes || '—'}</td>
        <td class="py-3 px-4 text-right">
          <button onclick="deleteContact(${c.id})" class="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 rounded text-xs font-semibold">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="4" class="py-6 text-center text-red-400">Failed to load contacts: ${err.message}</td></tr>`;
  }
}

async function addTrustedContact() {
  const name = document.getElementById('inp-contact-name').value.trim();
  const domain = document.getElementById('inp-contact-domain').value.trim();
  const notes = document.getElementById('inp-contact-notes').value.trim();

  if (!name || !domain) {
    alert('Please enter both contact name and authorized domain.');
    return;
  }

  try {
    const r = await fetch('/api/contacts', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, real_domain: domain, notes })
    });
    if (!r.ok) throw new Error('Failed to save contact');
    document.getElementById('inp-contact-name').value = '';
    document.getElementById('inp-contact-domain').value = '';
    document.getElementById('inp-contact-notes').value = '';
    loadContacts();
  } catch (err) {
    alert(err.message);
  }
}

async function deleteContact(id) {
  if (!confirm('Remove this trusted contact?')) return;
  try {
    await fetch(`/api/contacts/${id}`, { method: 'DELETE' });
    loadContacts();
  } catch (err) {
    alert(err.message);
  }
}

async function refreshLedger() {
  const tbody = document.getElementById('ledger-table-body');
  tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500">Querying database...</td></tr>';
  try {
    const r = await fetch('/api/cases');
    const cases = await r.json();
    if (!cases.length) {
      tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500">No cases recorded yet. Perform an analysis first.</td></tr>';
      return;
    }
    tbody.innerHTML = cases.map(c => `
      <tr class="hover:bg-slate-800/30 transition-colors">
        <td class="py-3 px-4 font-mono text-cyan-300 font-semibold">${c.case_id}</td>
        <td class="py-3 px-4">
          <div class="font-semibold text-slate-200 truncate max-w-xs">${c.subject || 'Untitled'}</div>
          <div class="text-[11px] text-slate-400 font-mono">${c.sender_address || 'Unknown'}</div>
        </td>
        <td class="py-3 px-4">
          <span class="px-2.5 py-0.5 rounded-full text-[11px] font-bold ${c.risk_level === 'Critical Threat' || c.risk_level === 'High Risk' ? 'bg-red-500/20 text-red-300 border border-red-500/40' : c.risk_level === 'Suspicious' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'}">
            ${c.risk_score}/100 (${c.risk_level})
          </span>
        </td>
        <td class="py-3 px-4 font-mono text-cyan-400">${c.confidence}%</td>
        <td class="py-3 px-4 text-slate-400">${c.created_at.substring(0, 16)}</td>
        <td class="py-3 px-4 text-right space-x-1.5">
          <button onclick="loadSingleCase('${c.case_id}')" class="px-2.5 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 rounded text-[11px] font-semibold">View</button>
          <button onclick="deleteSingleCase('${c.case_id}')" class="px-2.5 py-1 bg-red-500/10 hover:bg-red-500/20 text-red-300 border border-red-500/30 rounded text-[11px] font-semibold">&times;</button>
        </td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-red-400">Failed to load ledger: ${err.message}</td></tr>`;
  }
}

async function loadSingleCase(caseId) {
  try {
    const r = await fetch(`/api/cases/${caseId}`);
    const d = await r.json();
    switchTab('scanner');
    renderForensicReport(d);
  } catch (err) {
    alert('Failed to load case: ' + err.message);
  }
}

async function deleteSingleCase(caseId) {
  if (!confirm(`Delete case ${caseId} from SQLite database?`)) return;
  try {
    await fetch(`/api/cases/${caseId}`, { method: 'DELETE' });
    refreshLedger();
  } catch (err) {
    alert('Delete failed: ' + err.message);
  }
}

async function updateMetrics() {
  try {
    const r = await fetch('/api/cases');
    const cases = await r.json();
    document.getElementById('metric-total-scans').textContent = cases.length;
    document.getElementById('metric-threats-count').textContent = cases.filter(c => c.risk_score >= 51).length;
    document.getElementById('metric-clean-count').textContent = cases.filter(c => c.risk_score <= 25).length;
    document.getElementById('metric-imp-count').textContent = cases.filter(c => c.risk_score >= 51 && c.threat.includes('Phishing')).length;
  } catch (err) {}
}

function loadScenario(type) {
  setInputMode('raw');
  const box = document.getElementById('raw-input-box');
  if (type === 'phish') {
    box.value = `From: Security Alert <security@update-service-alert.com>
Reply-To: security-team@attacker-drop.net
To: victim@example.com
Subject: URGENT: Your Account Has Been Suspended - Verify Immediately
Date: Fri, 28 Aug 2026 15:30:00 +0000
Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail
Received: from mx.internal-boundary.lan (192.168.1.100) by mx.local with ESMTP
Received: from mail-relay.frankfurt.de (194.25.0.68) by mx.internal-boundary.lan with ESMTPS
Received: from vps-gateway.paris.cloud (13.38.0.1) by mail-relay.frankfurt.de with ESMTP

Dear Customer,
We detected unauthorized login attempts on your banking account. Please act now and confirm your credentials immediately to avoid permanent account termination.

Login Portal: http://192.168.1.100/login-fake

Thank you,
Fraud Prevention Team`;
  } else if (type === 'spoof') {
    box.value = `From: John Doe (CEO) <john.doe@attacker-drop.net>
Reply-To: confidential-executive@protonmail-drop.com
To: finance@trusted-corporation.com
Subject: URGENT: Confidential Acquisition Wire Payment
Date: Fri, 28 Aug 2026 14:00:00 +0000
Authentication-Results: mx.trusted-corporation.com; spf=fail; dkim=none; dmarc=fail
Received: from internal-lan (10.0.4.12) by mx.local
Received: from relay.london-hub.co.uk (212.58.244.20) by internal-lan
Received: from mail.tokyo-gateway.jp (133.242.0.1) by relay.london-hub.co.uk

Team,
I am currently in an executive board meeting. Please immediately execute the confidential wire payment of $45,000 to the overseas partner invoice attached.

Confirm invoice details: http://bit.ly/confidential-wire-invoice

Thanks,
John Doe
Chief Executive Officer`;
  } else {
    box.value = `From: Open Source Weekly <newsletter@techweekly.org>
Reply-To: newsletter@techweekly.org
To: developer@example.com
Subject: Tech Weekly Digest: Issue #104
Date: Fri, 28 Aug 2026 09:00:00 +0000
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
Received: from office-lan (172.16.0.25) by mx.google.com
Received: from mail-dispatcher.london.uk (212.58.244.20) by office-lan
Received: from staging.mumbai-isp.in (182.79.0.1) by mail-dispatcher.london.uk

Hi Developers,
Here is this week's curated roundup of Python releases and cloud security architectures.

Read full issue: https://techweekly.org/digest-104

Best,
Tech Weekly Team`;
  }
}

</script>
</body>
</html>
"""

@app.get("/scanner", response_class=HTMLResponse)
def serve_scanner_dashboard():
    return HTMLResponse(SCANNER_DASHBOARD_HTML)

# ---------------------------------------------------------------------------
# 3. MOBILE APP SHOWCASE & INTERACTIVE SIMULATOR (GET /app / GET /mobile)
# ---------------------------------------------------------------------------
MOBILE_APP_HTML = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MailSentinel Mobile — Threat Defense App Showcase</title>
<script src="https://cdn.tailwindcss.com"></script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet">
<script>
tailwind.config = {
  darkMode: 'class',
  theme: {
    extend: {
      colors: { cyber: { 950: '#040711', 900: '#070d1d', 800: '#0e172e', 700: '#172344', cyan: '#06b6d4' } },
      fontFamily: { sans: ['Inter', 'sans-serif'], mono: ['JetBrains Mono', 'monospace'] }
    }
  }
}
</script>
<style>
body {
  background-color: #040711;
  background-image: 
    radial-gradient(circle at 20% 20%, rgba(6, 182, 212, 0.08) 0%, transparent 40%),
    radial-gradient(circle at 80% 80%, rgba(59, 130, 246, 0.08) 0%, transparent 40%);
}
.phone-frame {
  width: 360px; height: 720px;
  background: #070d1d;
  border: 10px solid #1e293b;
  border-radius: 44px;
  box-shadow: 0 25px 60px rgba(0, 0, 0, 0.8), 0 0 35px rgba(6, 182, 212, 0.2);
  position: relative;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}
.notch {
  width: 140px; height: 22px;
  background: #1e293b;
  border-bottom-left-radius: 14px;
  border-bottom-right-radius: 14px;
  margin: 0 auto;
}
</style>
</head>
<body class="text-slate-100 font-sans min-h-screen p-4 md:p-8 flex flex-col justify-between">

  <!-- Header -->
  <header class="w-full max-w-6xl mx-auto flex justify-between items-center py-4 border-b border-slate-800/40">
    <div class="flex items-center gap-3">
      <!-- SVG Logo (Envelope + Shield + Radar) -->
      <svg class="w-7 h-7 text-cyan-400" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
        <path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4z" fill="url(#shield-grad-mb)" stroke="#06b6d4" stroke-width="1.5" stroke-linejoin="round"/>
        <path d="M7 9h10v6H7V9z" fill="#070d1d" stroke="#3b82f6" stroke-width="1.2"/>
        <path d="M7 9l5 3.5L17 9" stroke="#06b6d4" stroke-width="1.2" stroke-linecap="round"/>
        <line x1="4" y1="12" x2="20" y2="12" stroke="#22d3ee" stroke-width="1" stroke-dasharray="2 3" opacity="0.6"/>
        <defs>
          <linearGradient id="shield-grad-mb" x1="12" y1="2" x2="12" y2="24" gradientUnits="userSpaceOnUse">
            <stop stop-color="#0e172e" stop-opacity="0.8"/>
            <stop stop-color="#070d1d" stop-opacity="0.95"/>
          </linearGradient>
        </defs>
      </svg>
      <span class="text-base font-extrabold tracking-wider text-white uppercase">MailSentinel</span>
    </div>
    <nav class="flex items-center gap-6">
      <a href="/" class="text-xs md:text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors pb-1">Home</a>
      <a href="/scanner" class="text-xs md:text-sm font-semibold text-slate-400 hover:text-slate-200 transition-colors pb-1">Detector</a>
      <a href="/mobile" class="text-xs md:text-sm font-semibold text-cyan-400 border-b-2 border-cyan-400 pb-1">Mobile</a>
    </nav>
  </header>

  <!-- Showcase Content -->
  <main class="max-w-6xl mx-auto w-full my-auto grid grid-cols-1 lg:grid-cols-12 gap-12 items-center py-8">
    
    <!-- Left Pitch (6 Cols) -->
    <div class="lg:col-span-6 space-y-6">
      <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-bold uppercase tracking-wider">
        <span>📱</span> Mobile App Experience Showcase
      </div>
      <h1 class="text-3xl md:text-5xl font-black text-white leading-tight">
        Real-Time Email Forensics In Your Pocket
      </h1>
      <p class="text-sm text-slate-400 leading-relaxed">
        Experience MailSentinel on mobile. Interact with the live simulator on the right — it connects directly to our real SQLite database (<code>sentrymail_v3.db</code>) to display actual case records.
      </p>

      <!-- App Store Badges (Coming Soon) -->
      <div class="pt-4 space-y-3">
        <p class="text-xs font-semibold uppercase tracking-wider text-slate-500">Native Mobile Apps:</p>
        <div class="flex flex-wrap gap-4 items-center">
          <div class="px-5 py-3 rounded-2xl bg-slate-900/90 border border-slate-700/80 flex items-center gap-3 shadow-lg opacity-80 cursor-not-allowed">
            <span class="text-2xl">🍏</span>
            <div class="text-left">
              <div class="text-[10px] text-slate-400 uppercase font-semibold">Download on the</div>
              <div class="text-xs font-bold text-white">Apple App Store <span class="text-[10px] text-cyan-400 font-mono">(Coming Soon)</span></div>
            </div>
          </div>

          <div class="px-5 py-3 rounded-2xl bg-slate-900/90 border border-slate-700/80 flex items-center gap-3 shadow-lg opacity-80 cursor-not-allowed">
            <span class="text-2xl">🤖</span>
            <div class="text-left">
              <div class="text-[10px] text-slate-400 uppercase font-semibold">Get it on</div>
              <div class="text-xs font-bold text-white">Google Play Store <span class="text-[10px] text-cyan-400 font-mono">(Coming Soon)</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Right Interactive Phone Mockup (6 Cols) -->
    <div class="lg:col-span-6 flex justify-center">
      <div class="phone-frame">
        <div class="notch"></div>
        
        <!-- App Header -->
        <div class="px-5 py-3 border-b border-slate-800 flex justify-between items-center bg-slate-950/60">
          <div class="flex items-center gap-2">
            <!-- SVG Logo for phone screen -->
            <svg class="w-4 h-4 text-cyan-400" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6l-9-4z" fill="#070d1d" stroke="#06b6d4" stroke-width="1.5" stroke-linejoin="round"/>
            </svg>
            <span class="text-xs font-bold text-white tracking-tight">MailSentinel</span>
          </div>
          <span class="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 font-semibold font-mono">LIVE</span>
        </div>

        <!-- Phone App Views Container -->
        <div id="phone-content" class="flex-1 p-4 overflow-y-auto space-y-4">
          <!-- Screen 1: Status & Summary Screen -->
          <div id="app-screen-home" class="space-y-4">
            <div class="p-4 rounded-2xl bg-gradient-to-br from-cyan-950/40 to-slate-900 border border-cyan-500/30 space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-[11px] font-bold text-cyan-400 uppercase">Protection Status</span>
                <span class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse"></span>
              </div>
              <div class="text-xl font-extrabold text-white">Shield Active</div>
              <p class="text-[11px] text-slate-400">Zero-Fetch heuristic analysis guarding incoming communications.</p>
            </div>

            <div class="grid grid-cols-2 gap-2.5">
              <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-0.5">
                <div class="text-[10px] text-slate-400 font-semibold uppercase">Total Scans</div>
                <div id="app-metric-scans" class="text-xl font-bold font-mono text-cyan-400">--</div>
              </div>
              <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-0.5">
                <div class="text-[10px] text-slate-400 font-semibold uppercase">Threats Blocked</div>
                <div id="app-metric-threats" class="text-xl font-bold font-mono text-red-400">--</div>
              </div>
            </div>

            <div class="space-y-2">
              <div class="text-xs font-bold text-slate-300 flex justify-between items-center">
                <span>Recent Threat Alerts</span>
                <button onclick="setAppScreen('alerts')" class="text-[10px] text-cyan-400 hover:underline">View All &rarr;</button>
              </div>
              <div id="app-recent-list" class="space-y-2">
                <div class="p-3 rounded-xl bg-slate-900/60 text-center text-xs text-slate-500">Querying database cases...</div>
              </div>
            </div>
          </div>

          <!-- Screen 2: Alerts List Screen -->
          <div id="app-screen-alerts" class="hidden space-y-3">
            <div class="flex items-center justify-between pb-2 border-b border-slate-800">
              <span class="text-xs font-bold text-slate-200">All Flagged Incidents</span>
              <button onclick="setAppScreen('home')" class="text-[11px] text-cyan-400 font-semibold">&larr; Back</button>
            </div>
            <div id="app-all-alerts" class="space-y-2 text-xs"></div>
          </div>

          <!-- Screen 3: Detail Screen -->
          <div id="app-screen-detail" class="hidden space-y-3">
            <div class="flex items-center justify-between pb-2 border-b border-slate-800">
              <span class="text-xs font-bold text-slate-200">Incident Details</span>
              <button onclick="setAppScreen('home')" class="text-[11px] text-cyan-400 font-semibold">&larr; Back</button>
            </div>
            <div id="app-detail-body" class="space-y-3"></div>
          </div>

          <!-- Screen 4: Trusted Contacts -->
          <div id="app-screen-contacts" class="hidden space-y-3">
            <div class="flex items-center justify-between pb-2 border-b border-slate-800">
              <span class="text-xs font-bold text-slate-200">Trusted Whitelist</span>
              <button onclick="setAppScreen('home')" class="text-[11px] text-cyan-400 font-semibold">&larr; Back</button>
            </div>
            <div id="app-contacts-list" class="space-y-2 text-xs"></div>
          </div>
        </div>

        <!-- Phone Bottom App Navigation -->
        <div class="p-3 border-t border-slate-800 bg-slate-950 flex justify-around text-xs">
          <button onclick="setAppScreen('home')" class="flex flex-col items-center gap-0.5 text-cyan-400 font-semibold">
            <span>🏠</span>
            <span class="text-[9px]">Home</span>
          </button>
          <button onclick="setAppScreen('alerts')" class="flex flex-col items-center gap-0.5 text-slate-400 hover:text-cyan-300">
            <span>🚨</span>
            <span class="text-[9px]">Alerts</span>
          </button>
          <button onclick="setAppScreen('contacts')" class="flex flex-col items-center gap-0.5 text-slate-400 hover:text-cyan-300">
            <span>👥</span>
            <span class="text-[9px]">Contacts</span>
          </button>
        </div>
      </div>
    </div>
  </main>

  <!-- Footer -->
  <footer class="max-w-6xl mx-auto w-full text-center text-xs text-slate-500 py-4">
    MailSentinel Mobile App Prototype — Connected to live SQLite database.
  </footer>

<script>
let currentCases = [];

function setAppScreen(scr) {
  ['home', 'alerts', 'detail', 'contacts'].forEach(s => {
    document.getElementById('app-screen-' + s).classList.add('hidden');
  });
  document.getElementById('app-screen-' + scr).classList.remove('hidden');
  if (scr === 'contacts') loadAppContacts();
}

async function loadAppData() {
  try {
    const r = await fetch('/api/cases');
    currentCases = await r.json();

    document.getElementById('app-metric-scans').textContent = currentCases.length;
    document.getElementById('app-metric-threats').textContent = currentCases.filter(c => c.risk_score >= 51).length;

    const recentEl = document.getElementById('app-recent-list');
    const allAlertsEl = document.getElementById('app-all-alerts');

    if (!currentCases.length) {
      recentEl.innerHTML = '<div class="p-3 rounded-xl bg-slate-900/60 text-center text-xs text-slate-500">No cases recorded yet.</div>';
      allAlertsEl.innerHTML = '<div class="p-3 rounded-xl bg-slate-900/60 text-center text-xs text-slate-500">No cases recorded yet.</div>';
      return;
    }

    recentEl.innerHTML = currentCases.slice(0, 3).map(c => `
      <div onclick="openAppDetail('${c.case_id}')" class="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 flex justify-between items-center cursor-pointer transition-colors">
        <div class="truncate max-w-[190px]">
          <div class="font-bold text-xs text-slate-200 truncate">${c.subject || 'Untitled'}</div>
          <div class="text-[10px] text-slate-400 truncate">${c.sender_address || 'Unknown'}</div>
        </div>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${c.risk_score >= 51 ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/20 text-emerald-300'}">
          ${c.risk_score}/100
        </span>
      </div>
    `).join('');

    allAlertsEl.innerHTML = currentCases.map(c => `
      <div onclick="openAppDetail('${c.case_id}')" class="p-3 rounded-xl bg-slate-900/80 hover:bg-slate-800/80 border border-slate-800 flex justify-between items-center cursor-pointer transition-colors">
        <div class="truncate max-w-[190px]">
          <div class="font-bold text-xs text-slate-200 truncate">${c.subject || 'Untitled'}</div>
          <div class="text-[10px] text-slate-400 truncate">${c.sender_address || 'Unknown'} &bull; ${c.created_at.substring(0, 10)}</div>
        </div>
        <span class="px-2 py-0.5 rounded-full text-[10px] font-bold ${c.risk_score >= 51 ? 'bg-red-500/20 text-red-300' : 'bg-emerald-500/20 text-emerald-300'}">
          ${c.risk_score}/100
        </span>
      </div>
    `).join('');
  } catch (err) {}
}

async function openAppDetail(caseId) {
  try {
    const r = await fetch(`/api/cases/${caseId}`);
    const d = await r.json();
    setAppScreen('detail');

    const detailEl = document.getElementById('app-detail-body');
    detailEl.innerHTML = `
      <div class="p-4 rounded-2xl ${d.risk_score >= 51 ? 'bg-red-950/30 border-red-500/40' : 'bg-emerald-950/30 border-emerald-500/40'} border space-y-1">
        <div class="text-[10px] uppercase font-bold text-slate-400">Risk Assessment</div>
        <div class="text-3xl font-black font-mono ${d.risk_score >= 51 ? 'text-red-400' : 'text-emerald-400'}">${d.risk_score}/100</div>
        <div class="text-xs font-bold text-slate-200">${d.threat}</div>
      </div>

      <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-[11px] space-y-1.5">
        <div><span class="text-slate-400">From:</span> <span class="font-semibold text-slate-200">${d.sender.display_name || ''} &lt;${d.sender.address}&gt;</span></div>
        <div><span class="text-slate-400">Subject:</span> <span class="font-semibold text-slate-200">${d.subject || 'N/A'}</span></div>
        <div><span class="text-slate-400">Case ID:</span> <code class="text-cyan-300">${d.case_id}</code></div>
      </div>

      <div class="space-y-1.5">
        <div class="text-[11px] font-bold text-slate-400 uppercase">Top Heuristic Findings</div>
        <div class="space-y-1.5">
          ${d.findings.length ? d.findings.slice(0, 3).map(f => `
            <div class="p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[10px] space-y-0.5">
              <div class="font-bold text-slate-200 flex justify-between">
                <span>${f.category}</span>
                <span class="text-cyan-400">+${f.points} pts</span>
              </div>
              <div class="text-slate-400">${f.evidence}</div>
            </div>
          `).join('') : '<p class="text-[10px] text-slate-500">No high risk findings.</p>'}
        </div>
      </div>
    `;
  } catch (err) {
    alert('Failed to load incident detail: ' + err.message);
  }
}

async function loadAppContacts() {
  const container = document.getElementById('app-contacts-list');
  try {
    const r = await fetch('/api/contacts');
    const contacts = await r.json();
    if (!contacts.length) {
      container.innerHTML = '<div class="p-3 rounded-xl bg-slate-900/60 text-center text-xs text-slate-500">No trusted contacts added.</div>';
      return;
    }
    container.innerHTML = contacts.map(c => `
      <div class="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-0.5">
        <div class="font-bold text-xs text-slate-200">${c.name}</div>
        <div class="font-mono text-[10px] text-cyan-300">Authorized: @${c.real_domain}</div>
        <div class="text-[10px] text-slate-400">${c.notes || ''}</div>
      </div>
    `).join('');
  } catch (err) {}
}

loadAppData();
</script>
</body>
</html>
"""

@app.get("/app", response_class=HTMLResponse)
@app.get("/mobile", response_class=HTMLResponse)
def serve_mobile_app_showcase():
    return HTMLResponse(MOBILE_APP_HTML)

# ---------------------------------------------------------------------------
# Direct Execution Entrypoint
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("==================================================================")
    print("  MailSentinel v3.2 — Cyber-Forensics Threat Platform")
    print("  Landing (/) | Detector (/scanner) | Mobile Showcase (/mobile)")
    print("  SQLAlchemy + SQLite + Leaflet.js + ip-api.com Geolocation")
    print("==================================================================")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
