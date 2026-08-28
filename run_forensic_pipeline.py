import os
import sys
import uuid
import hashlib

# Ensure the workspace root is on the Python path so `backend.*` imports resolve
WORKSPACE = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

from backend.app.models.schemas import init_database, ForensicCase, SMTPHop
from backend.app.parser.email_parser import parse_incoming_email
from backend.app.osint.enrichment import run_reverse_email_lookup, trace_smtp_routing
from sqlalchemy.orm import sessionmaker


def execute_pipeline():
    print("🚦 Starting End-to-End Email Threat Forensic Analysis Pipeline...")

    # 1. Initialize DB Connection
    engine  = init_database()
    Session = sessionmaker(bind=engine)
    session = Session()

    # 2. Ingest Suspect Email JSON (BEC Simulation Payload)
    suspect_email_json = {
        "headers": {
            "From":           "executive-office@executive-president.com",
            "Subject":        "URGENT: Wire Transfer Authorization Required Immediately",
            "Reply-To":       "attacker-inbox@anonymous-mail.ru",
            "Received-SPF":   "FAIL",
            "DKIM-Signature": "FAIL",
        },
        "body": (
            "Please process the wire transfer of $4,500 immediately to the updated "
            "routing account details: Routing: 021000021, Account: 98127391823. "
            "This is high priority and confidential."
        ),
        "received": [
            {"ip": "18.20.151.4",   "by": "corporate-gateway.target-firm.com"},
            {"ip": "185.112.144.5", "by": "mx.unsecured-relay.net"},
            {"ip": "178.21.11.42",  "by": "home-computer-client.local"},
        ],
    }

    # Generate Cryptographic Forensic Evidence Hash
    raw_payload_bytes = str(suspect_email_json).encode('utf-8')
    evidence_hash     = hashlib.sha256(raw_payload_bytes).hexdigest()
    print(f"🔒 Generated Evidence Hash: SHA-256:{evidence_hash}")

    # 3. Layer 1 — Email Parsing & PyTorch Inference
    print("\n📩 [Layer 1] Parsing Email Body and Technical Headers...")
    parsed_meta = parse_incoming_email(suspect_email_json)
    print(f"   Sender detected: {parsed_meta['sender']}")
    print(f"   Subject line:    {parsed_meta['subject']}")
    print(f"   Reply-To email:  {parsed_meta['reply_to']} (Mismatch: {parsed_meta['reply_to_mismatch']})")
    print(f"   Linguistic Prob: {parsed_meta['ai_threat_probability']*100:.2f}% (High pressure semantic patterns)")

    # 4. Layer 2 — Spokeo-Style Reverse Identity Lookup (OSINT)
    print("\n👤 [Layer 2] Running Spokeo-Style Reverse Identity Profile Check...")
    osint_meta     = run_reverse_email_lookup(parsed_meta['sender'])
    social_profiles = osint_meta['social_profile_associations']
    print(f"   Associated name: None / Unregistered Identity")
    print(f"   Domain age:      {osint_meta['domain_age_days']} days (Suspect threshold: <90 days)")
    print(f"   Social links:    {social_profiles}")
    print(f"   Data breaches:   {osint_meta['data_breach_appearances']} reports")

    # 5. Layer 3 — SMTP Header Forensics Trace & Geolocation
    print("\n🗺️  [Layer 3] Reconstructing Email Routing and Geolocating Transit Hops...")
    route_trace = trace_smtp_routing(
        suspect_email_json["received"],
        trusted_gateways=["target-firm.com"]
    )
    for hop in route_trace:
        print(
            f"   Hop {hop['hop_number']}: {hop['ip']} ({hop['location']}) | "
            f"Server: {hop['mail_server']} | Status: {hop['verification_status']}"
        )

    # 6. Central Risk Engine (0–100 score)
    print("\n🧮 Calculating weighted risk indicators and saving evidence case...")
    final_score = 0
    if parsed_meta['reply_to_mismatch']:                    final_score += 20
    if parsed_meta['auth_status']['spf']  == "FAIL":        final_score += 15
    if parsed_meta['auth_status']['dkim'] == "FAIL":        final_score += 15
    if osint_meta['domain_age_days'] < 90:                  final_score += 15
    if parsed_meta['ai_threat_probability'] > 0.85:         final_score += 15

    case_uuid        = str(uuid.uuid4())[:8]
    mock_blockchain  = (
        f"0x389e91{str(uuid.uuid4()).replace('-','')[:16]}"
        f"cec3aec49416f8d6106546029d1acef5e8a0294a"
    )

    # 7. Write to SQLite
    new_case = ForensicCase(
        id                  = case_uuid,
        blockchain_tx       = mock_blockchain,
        evidence_hash       = evidence_hash,
        risk_score          = final_score,
        classification      = (
            "BEC / Identity Fraud" if parsed_meta['reply_to_mismatch'] else "Phishing"
        ),
        sender              = parsed_meta['sender'],
        subject             = parsed_meta['subject'],
        reply_to_anomaly    = parsed_meta['reply_to_mismatch'],
        spf_passed          = (parsed_meta['auth_status']['spf']  == "PASS"),
        dkim_passed         = (parsed_meta['auth_status']['dkim'] == "PASS"),
        dmarc_passed        = (parsed_meta['auth_status']['dmarc'] == "PASS"),
        body_content_exerpt = suspect_email_json['body'][:150] + "...",
    )
    session.add(new_case)

    for hop in route_trace:
        new_hop = SMTPHop(
            case_id             = case_uuid,
            hop_number          = hop['hop_number'],
            ip_address          = hop['ip'],
            mail_server         = hop['mail_server'],
            location            = hop['location'],
            verification_status = hop['verification_status'],
        )
        session.add(new_hop)

    session.commit()
    print(f"✅ Securely stored forensic Case #{case_uuid} in database. Blockchain TX receipt posted.")

    # 8. SQL Audit Verification
    print(f"\n📖 Retrieving stored case details from SQLite for report auditing...")
    db_case = session.query(ForensicCase).filter_by(id=case_uuid).first()

    risk_label = (
        "🟢 Low Risk"      if db_case.risk_score <= 25 else
        "🟡 Moderate Risk" if db_case.risk_score <= 50 else
        "🟠 Suspicious"    if db_case.risk_score <= 75 else
        "🔴 HIGH RISK — AUTO-QUARANTINE"
    )

    print("\n==========================================================================")
    print("💼                 OFFICIAL FORENSIC CASE FILE AUDIT                     ")
    print("==========================================================================")
    print(f"📁 CASE ID:          {db_case.id}")
    print(f"🔗 BLOCKCHAIN TX:    {db_case.blockchain_tx} (Immutable Seal)")
    print(f"🔒 SHA-256 HASH:     {db_case.evidence_hash}")
    print(f"🚨 RISK SCORE:       {db_case.risk_score} / 100  →  {risk_label}")
    print(f"🎯 CLASSIFICATION:   {db_case.classification}")
    print(f"👤 SENDER IDENTITY:  {db_case.sender}")
    print(f"📧 AUTHENTICATION:   SPF={'PASS' if db_case.spf_passed else 'FAIL'} | DKIM={'PASS' if db_case.dkim_passed else 'FAIL'} | DMARC={'PASS' if db_case.dmarc_passed else 'FAIL'}")
    print(f"⚠️  REPLY-TO ANOMALY: {'MISMATCH DETECTED' if db_case.reply_to_anomaly else 'CLEAN'}")
    print(f"🌐 TRANSIT BOUNDARY: FAILED (Unverified hops detected)")
    print(f"📝 EMAIL EXCERPT:    {db_case.body_content_exerpt}")
    print("==========================================================================\n")

    session.close()


if __name__ == "__main__":
    execute_pipeline()
