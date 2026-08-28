import os
import sys
import uuid
import hashlib
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session, sessionmaker

# Resolve workspace root dynamically and inject it into Python paths
WORKSPACE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

from backend.app.models.schemas import init_database, ForensicCase, SMTPHop
from backend.app.parser.email_parser import parse_incoming_email
from backend.app.osint.enrichment import run_reverse_email_lookup, trace_smtp_routing

app = FastAPI(
    title="AI-Powered Email Threat Forensics & Intelligence API",
    description="SIH26106 Blockchain & Cybersecurity Platform Core Backend Services",
    version="1.0.0"
)

# Enable Cross-Origin Resource Sharing (CORS) for local frontend dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connect to database session relative to our workspace directory
DB_URL = f"sqlite:///{os.path.join(WORKSPACE, 'email_forensics.db')}"
engine = init_database(DB_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Pydantic Schemas for Input Validation ---
class ReceivedHopInput(BaseModel):
    ip: str
    by: str
    isp: Optional[str] = "Deutsche Telekom AG"
    city: Optional[str] = "Frankfurt"
    country: Optional[str] = "Germany"

class EmailAnalysisRequest(BaseModel):
    headers: Dict[str, str]
    body: str
    received: List[ReceivedHopInput]

# --- API Endpoints ---

@app.post("/api/analyze", response_model=Dict[str, Any])
def analyze_incoming_email(payload: EmailAnalysisRequest, db: Session = Depends(get_db)):
    """
    Ingests an email, runs PyTorch classification, extracts headers, 
    executes OSINT checks, maps SMTP routing, and commits evidence to database.
    """
    try:
        # 1. Cryptographic hashing of raw inputs to maintain Chain-of-Custody
        raw_string = f"{payload.headers}{payload.body}{[h.dict() for h in payload.received]}"
        evidence_hash = hashlib.sha256(raw_string.encode('utf-8')).hexdigest()
        
        # 2. Layer 1: Run Header Parsing and PyTorch Text Inference
        raw_json_dict = {
            "headers": payload.headers,
            "body": payload.body
        }
        parsed_meta = parse_incoming_email(raw_json_dict)
        
        # 3. Layer 2: Run Spokeo-Style Reverse Identity Profiling (OSINT)
        osint_meta = run_reverse_email_lookup(parsed_meta["sender"])
        
        # 4. Layer 3: Reconstruct Physical SMTP Routing & Trusted Boundary Trace
        received_hops_list = [h.dict() for h in payload.received]
        route_trace = trace_smtp_routing(received_hops_list, trusted_gateways=["target-firm.com"])
        
        # 5. Core Threat Scoring Engine Logic
        final_score = 0
        if parsed_meta['reply_to_mismatch']: final_score += 20
        if parsed_meta['auth_status']['spf'] == "FAIL": final_score += 15
        if parsed_meta['auth_status']['dkim'] == "FAIL": final_score += 15
        if osint_meta['domain_age_days'] < 90: final_score += 15
        if parsed_meta['ai_threat_probability'] > 0.85: final_score += 15
        
        # Determine classification category
        classification = "BEC / Identity Fraud" if parsed_meta['reply_to_mismatch'] else "Phishing"
        if final_score < 30:
            classification = "Legitimate"
        elif final_score < 60:
            classification = "Suspicious Link / Insecure"
            
        case_id = str(uuid.uuid4())[:8]
        mock_blockchain_tx = f"0x389e91{str(uuid.uuid4()).replace('-', '')[:16]}cec3aec49416f8d6106546029d1acef5e8a0294a"
        
        # 6. Save case record to Database
        new_case = ForensicCase(
            id=case_id,
            blockchain_tx=mock_blockchain_tx,
            evidence_hash=evidence_hash,
            risk_score=final_score,
            classification=classification,
            sender=parsed_meta['sender'],
            subject=parsed_meta['subject'],
            reply_to_anomaly=parsed_meta['reply_to_mismatch'],
            spf_passed=(parsed_meta['auth_status']['spf'] == "PASS"),
            dkim_passed=(parsed_meta['auth_status']['dkim'] == "PASS"),
            dmarc_passed=(parsed_meta['auth_status']['dmarc'] == "PASS"),
            body_content_exerpt=payload.body[:150] + "..."
        )
        db.add(new_case)
        
        # Save individual trace hops
        for hop in route_trace:
            new_hop = SMTPHop(
                case_id=case_id,
                hop_number=hop['hop_number'],
                ip_address=hop['ip'],
                mail_server=hop['mail_server'],
                location=hop['location'],
                verification_status=hop['verification_status']
            )
            db.add(new_hop)
            
        db.commit()
        
        # Return full report JSON back to caller
        return {
            "status": "success",
            "case_id": case_id,
            "evidence_hash": evidence_hash,
            "blockchain_tx": mock_blockchain_tx,
            "risk_score": final_score,
            "classification": classification,
            "parsed_indicators": parsed_meta,
            "osint_footprint": osint_meta,
            "routing_trace": route_trace
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Forensic pipeline execution error: {str(e)}")

@app.get("/api/cases", response_model=List[Dict[str, Any]])
def get_all_forensic_cases(db: Session = Depends(get_db)):
    """
    Returns a comprehensive list of all historical forensic investigation cases.
    """
    cases = db.query(ForensicCase).all()
    results = []
    for c in cases:
        results.append({
            "id": c.id,
            "blockchain_tx": c.blockchain_tx,
            "evidence_hash": c.evidence_hash,
            "risk_score": c.risk_score,
            "classification": c.classification,
            "sender": c.sender,
            "subject": c.subject,
            "reply_to_anomaly": c.reply_to_anomaly,
            "spf_passed": c.spf_passed,
            "dkim_passed": c.dkim_passed,
            "dmarc_passed": c.dmarc_passed,
            "excerpt": c.body_content_exerpt
        })
    return results

@app.get("/api/cases/{case_id}", response_model=Dict[str, Any])
def get_case_by_id(case_id: str, db: Session = Depends(get_db)):
    """
    Drills down on a single forensic case, returning detailed OSINT data and transit hops.
    """
    case = db.query(ForensicCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Forensic case not found")
        
    hops = db.query(SMTPHop).filter_by(case_id=case_id).order_by(SMTPHop.hop_number).all()
    hops_data = []
    for h in hops:
        hops_data.append({
            "hop_number": h.hop_number,
            "ip_address": h.ip_address,
            "mail_server": h.mail_server,
            "location": h.location,
            "verification_status": h.verification_status
        })
        
    return {
        "id": case.id,
        "blockchain_tx": case.blockchain_tx,
        "evidence_hash": case.evidence_hash,
        "risk_score": case.risk_score,
        "classification": case.classification,
        "sender": case.sender,
        "subject": case.subject,
        "reply_to_anomaly": case.reply_to_anomaly,
        "spf_passed": case.spf_passed,
        "dkim_passed": case.dkim_passed,
        "dmarc_passed": case.dmarc_passed,
        "excerpt": case.body_content_exerpt,
        "transit_hops": hops_data
    }

@app.get("/api/network-graph", response_model=Dict[str, Any])
def get_campaign_network_graph(db: Session = Depends(get_db)):
    """
    Generates node-link schemas representing relationship mappings between cases, sender domains, 
    and IP networks to plot real-time campaign force graphs on Next.js frontend.
    ```
    nodes: Array of {id, label, group, risk}
    links: Array of {source, target, relationship}
    ```
    """
    cases = db.query(ForensicCase).all()
    
    nodes = []
    links = []
    registered_entities = set()
    
    for c in cases:
        # Add the case node
        case_node_id = f"case_{c.id}"
        if case_node_id not in registered_entities:
            nodes.append({
                "id": case_node_id,
                "label": f"Case #{c.id}",
                "group": "case",
                "risk": c.risk_score
            })
            registered_entities.add(case_node_id)
            
        # Extract and add Domain Node
        domain = c.sender.split("@")[-1] if "@" in c.sender else "unknown.com"
        domain_node_id = f"domain_{domain}"
        if domain_node_id not in registered_entities:
            nodes.append({
                "id": domain_node_id,
                "label": domain,
                "group": "domain",
                "risk": 80 if c.risk_score > 60 else 10
            })
            registered_entities.add(domain_node_id)
            
        # Connect Case Node to Domain Node
        links.append({
            "source": case_node_id,
            "target": domain_node_id,
            "relationship": "sent_from"
        })
        
        # Fetch related SMTP hops and connect IP nodes
        hops = db.query(SMTPHop).filter_by(case_id=c.id).all()
        for h in hops:
            ip_node_id = f"ip_{h.ip_address}"
            if ip_node_id not in registered_entities:
                nodes.append({
                    "id": ip_node_id,
                    "label": h.ip_address,
                    "group": "ip_address",
                    "risk": 100 if h.verification_status == "UNVERIFIED" else 0
                })
                registered_entities.add(ip_node_id)
                
            # Connect Domain or Case node to IP Hops
            links.append({
                "source": domain_node_id,
                "target": ip_node_id,
                "relationship": "routed_through"
            })
            
    return {"nodes": nodes, "links": links}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
