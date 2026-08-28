from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from urllib.parse import urlparse
import hashlib, html, re, uuid, os, io
from fastapi.staticfiles import StaticFiles
import pypdf

app = FastAPI(title='Email Threat Forensics API', version='0.1.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_methods=['*'], allow_headers=['*'])

MAX_FILE = 5 * 1024 * 1024
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URGENCY = re.compile(r'\b(urgent|immediately|act now|verify|suspend|suspended|final warning|expire|limited time|confirm)\b', re.I)
CREDENTIAL = re.compile(r'\b(password|otp|one[- ]time password|login|sign in|verify your account|credentials)\b', re.I)
FINANCIAL = re.compile(r'\b(invoice|payment|bank|account number|wire|transfer|refund|gift card|crypto|upi)\b', re.I)
ATTACHMENT_RISK = {'.exe','.scr','.js','.vbs','.bat','.cmd','.ps1','.hta','.jar','.iso','.img','.lnk'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','is.gd','ow.ly','buff.ly','cutt.ly'}


def domain(addr):
    return addr.rsplit('@',1)[-1].lower() if '@' in addr else ''

def parse_auth(msg):
    raw = ' '.join(msg.get_all('Authentication-Results', []) + msg.get_all('Received-SPF', []))
    out = {}
    for key in ('spf','dkim','dmarc'):
        m = re.search(rf'\b{key}=(pass|fail|softfail|neutral|none|temperror|permerror)\b', raw, re.I)
        out[key] = m.group(1).lower() if m else 'unknown'
    return out

def extract_urls(text):
    urls = set(URL_RE.findall(text or ''))
    return sorted(u.rstrip(').,;]') for u in urls)

def visible_link_mismatches(html_body):
    findings=[]
    for href, label in re.findall(r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', html_body or '', re.I|re.S):
        label_text = re.sub(r'<[^>]+>', ' ', label).strip()
        if label_text and re.match(r'https?://', label_text, re.I) and label_text.rstrip('/') != href.rstrip('/'):
            findings.append({'visible': label_text, 'actual': href})
    return findings

def score_email(msg, body, html_body):
    findings=[]; score=0
    auth=parse_auth(msg)
    auth_bad=sum(1 for v in auth.values() if v in {'fail','softfail','permerror'})
    if auth_bad:
        add=min(30, auth_bad*10); score += add
        findings.append({'category':'Authentication','points':add,'evidence':f'SPF/DKIM/DMARC failures: {auth_bad}'})
    from_addr=parseaddr(msg.get('From',''))[1]
    reply_addr=parseaddr(msg.get('Reply-To',''))[1]
    return_addr=parseaddr(msg.get('Return-Path',''))[1].strip('<>')
    if reply_addr and domain(reply_addr) != domain(from_addr):
        score += 12; findings.append({'category':'Sender / Identity','points':12,'evidence':'Reply-To domain differs from From domain'})
    if return_addr and domain(return_addr) != domain(from_addr):
        score += 8; findings.append({'category':'Sender / Identity','points':8,'evidence':'Return-Path domain differs from From domain'})
    subject=msg.get('Subject','')
    text=(subject+'\n'+body).strip()
    if URGENCY.search(text):
        score += 8; findings.append({'category':'AI / Content','points':8,'evidence':'Urgency or pressure language detected'})
    if CREDENTIAL.search(text):
        score += 8; findings.append({'category':'AI / Content','points':8,'evidence':'Credential or verification language detected'})
    if FINANCIAL.search(text):
        score += 5; findings.append({'category':'AI / Content','points':5,'evidence':'Financial/payment language detected'})
    urls=extract_urls(body+'\n'+html_body)
    mismatch=visible_link_mismatches(html_body)
    if mismatch:
        score += min(15, 7*len(mismatch)); findings.append({'category':'URL','points':min(15,7*len(mismatch)),'evidence':'Visible link destination differs from actual href'})
    url_details=[]
    for u in urls:
        p=urlparse(u); host=(p.hostname or '').lower()
        flags=[]
        if host in SHORTENERS: flags.append('shortener')
        if IP_RE.fullmatch(host or ''): flags.append('ip-literal')
        if host.startswith('xn--') or 'xn--' in host: flags.append('punycode')
        if '@' in p.netloc: flags.append('userinfo-in-url')
        if flags:
            score += min(6, len(flags)*3); findings.append({'category':'URL','points':min(6,len(flags)*3),'evidence':f'{host}: {", ".join(flags)}'})
        url_details.append({'url':u,'host':host,'flags':flags})
    attachments=[]
    for part in msg.walk():
        if part.get_content_disposition() == 'attachment':
            name=part.get_filename() or 'unnamed'
            payload=part.get_payload(decode=True) or b''
            ext='.'+name.rsplit('.',1)[-1].lower() if '.' in name else ''
            item={'filename':name,'size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'risk':ext in ATTACHMENT_RISK}
            attachments.append(item)
            if item['risk']:
                score += 8; findings.append({'category':'Attachment','points':8,'evidence':f'Potentially risky attachment type: {ext}'})
    score=min(100,score)
    level='Low' if score<=25 else 'Moderate' if score<=50 else 'Suspicious' if score<=75 else 'High Risk'
    confidence=min(100, 35 + len(findings)*8)
    return score,level,confidence,findings,url_details,attachments,auth

def analyze(raw: bytes):
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    plain=[]; html_parts=[]
    for part in msg.walk():
        if part.get_content_maintype()=='multipart': continue
        if part.get_content_disposition()=='attachment': continue
        try: content=part.get_content()
        except Exception: content=''
        if part.get_content_type()=='text/html': html_parts.append(content)
        elif part.get_content_type()=='text/plain': plain.append(content)
    body='\n'.join(plain); html_body='\n'.join(html_parts)
    score,level,confidence,findings,urls,attachments,auth=score_email(msg,body,html_body)
    received=msg.get_all('Received', [])
    relay_ips=[]
    for r in received:
        relay_ips.extend(IP_RE.findall(r))
    sender=parseaddr(msg.get('From',''))
    return {
      'case_id':'CASE-'+uuid.uuid4().hex[:8].upper(),
      'evidence_id':'EV-'+uuid.uuid4().hex[:8].upper(),
      'risk_score':score,'risk_level':level,'confidence':confidence,
      'threat':'Potential phishing / email fraud' if score>=51 else 'No high-confidence threat detected',
      'sender':{'display_name':sender[0],'address':sender[1],'domain':domain(sender[1])},
      'reply_to':msg.get('Reply-To',''),'return_path':msg.get('Return-Path',''),
      'subject':msg.get('Subject',''),'date':msg.get('Date',''),'message_id':msg.get('Message-ID',''),
      'authentication':auth,
      'received_count':len(received),'relay_ips':list(dict.fromkeys(relay_ips)),
      'urls':urls,'url_details':urls,'attachments':attachments,
      'findings':findings,
      'evidence_sha256':hashlib.sha256(raw).hexdigest(),
      'limitations':['Geolocation is not inferred locally; external intelligence is required.','IP infrastructure location is not attacker physical location.','Authentication failure is weighted evidence, not proof of fraud.','Suspicious URLs are never fetched by this MVP.']
    }

def analyze_pdf(raw: bytes):
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
        score += 12
        findings.append({'category': 'Sender / Identity', 'points': 12, 'evidence': 'Reply-To domain differs from From domain'})

    if URGENCY.search(full_text):
        score += 8
        findings.append({'category': 'AI / Content', 'points': 8, 'evidence': 'Urgency or pressure language detected'})
    if CREDENTIAL.search(full_text):
        score += 8
        findings.append({'category': 'AI / Content', 'points': 8, 'evidence': 'Credential or verification language detected'})
    if FINANCIAL.search(full_text):
        score += 5
        findings.append({'category': 'AI / Content', 'points': 5, 'evidence': 'Financial/payment language detected'})

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
            score += min(6, len(flags) * 3)
            findings.append({'category': 'URL', 'points': min(6, len(flags) * 3), 'evidence': f'{host}: {", ".join(flags)}'})
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
                        score += 8
                        findings.append({'category': 'Attachment', 'points': 8, 'evidence': f'Potentially risky embedded attachment: {ext}'})
    except Exception:
        pass

    relay_ips = list(dict.fromkeys(IP_RE.findall(full_text)))

    score = min(100, score)
    level = 'Low' if score <= 25 else 'Moderate' if score <= 50 else 'Suspicious' if score <= 75 else 'High Risk'
    confidence = min(100, 30 + len(findings) * 8)

    return {
      'case_id': 'CASE-' + uuid.uuid4().hex[:8].upper(),
      'evidence_id': 'EV-' + uuid.uuid4().hex[:8].upper(),
      'risk_score': score,
      'risk_level': level,
      'confidence': confidence,
      'threat': 'Potential phishing / email fraud' if score >= 51 else 'No high-confidence threat detected',
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
      'limitations': [
          'Document analyzed from PDF export. Cryptographic header verification (DKIM/ARC) requires original .eml message.',
          'Geolocation is not inferred locally; external intelligence is required.',
          'IP infrastructure location is not attacker physical location.',
          'Suspicious URLs are never fetched by this MVP.'
      ]
    }

@app.get('/api/health')
def health(): return {'status':'ok','service':'email-threat-forensics','version':'0.1.0'}

@app.post('/api/analyze')
async def analyze_upload(file: UploadFile=File(...)):
    filename = (file.filename or '').lower()
    if not (filename.endswith('.eml') or filename.endswith('.pdf')):
        raise HTTPException(400,'Only .eml and .pdf files are accepted in the MVP.')
    raw = await file.read()
    if len(raw) > MAX_FILE:
        raise HTTPException(413,'File exceeds 5 MB limit.')
    try:
        if filename.endswith('.pdf'):
            result = analyze_pdf(raw)
        else:
            result = analyze(raw)
    except Exception as e:
        raise HTTPException(422, f'Unable to parse file safely: {e}')
    result['original_filename'] = file.filename
    return JSONResponse(result)


frontend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend"))
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")

