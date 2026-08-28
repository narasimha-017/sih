import os

def create_simple_pdf(filename, lines):
    stream_content = "BT\n/F1 12 Tf\n50 780 Td\n16 TL\n"
    for line in lines:
        escaped = line.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')
        stream_content += f"({escaped}) '\n"
    stream_content += "ET\n"
    
    stream_bytes = stream_content.encode('latin1')
    length = len(stream_bytes)
    
    header = b"%PDF-1.4\n"
    obj1 = b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    obj2 = b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    obj3 = b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>\nendobj\n"
    obj4_head = f"4 0 obj\n<< /Length {length} >>\nstream\n".encode('latin1')
    obj4_tail = b"endstream\nendobj\n"
    obj4 = obj4_head + stream_bytes + obj4_tail
    obj5 = b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n"
    
    pos1 = len(header)
    pos2 = pos1 + len(obj1)
    pos3 = pos2 + len(obj2)
    pos4 = pos3 + len(obj3)
    pos5 = pos4 + len(obj4)
    xref_pos = pos5 + len(obj5)
    
    xref = f"xref\n0 6\n0000000000 65535 f \n{pos1:010d} 00000 n \n{pos2:010d} 00000 n \n{pos3:010d} 00000 n \n{pos4:010d} 00000 n \n{pos5:010d} 00000 n \n".encode('latin1')
    trailer = f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode('latin1')
    
    with open(filename, "wb") as f:
        f.write(header + obj1 + obj2 + obj3 + obj4 + obj5 + xref + trailer)


os.makedirs("samples", exist_ok=True)

phish_lines = [
    "From: Account Security <security@update-service-alert.com>",
    "Reply-To: security-team@attacker-drop.net",
    "To: victim@example.com",
    "Subject: URGENT: Your Account Has Been Suspended - Verify Immediately",
    "Date: Fri, 28 Aug 2026 15:30:00 +0000",
    "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail",
    "Received: from 194.25.0.68 (Frankfurt MTA)",
    "Received: from 13.38.0.1 (Paris Node)",
    "Received: from 192.168.1.100 (Internal Boundary)",
    "",
    "Dear Customer,",
    "We detected unauthorized login attempts on your banking account.",
    "Please act now and confirm your credentials immediately to avoid suspension.",
    "",
    "Visit: http://192.168.1.100/login-fake",
    "Official website: https://secure.yourbank.com/account/login",
    "",
    "Fraud Prevention Team"
]
create_simple_pdf("samples/sample_phishing_email.pdf", phish_lines)

clean_lines = [
    "From: Newsletter Team <newsletter@techweekly.org>",
    "Reply-To: newsletter@techweekly.org",
    "To: subscriber@example.com",
    "Subject: Tech Weekly Digest: Issue #42",
    "Date: Fri, 28 Aug 2026 10:00:00 +0000",
    "Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass",
    "Received: from 212.58.244.20 (London Dispatcher)",
    "Received: from 182.79.0.1 (Mumbai Gateway)",
    "Received: from 10.0.12.5 (Internal LAN)",
    "",
    "Hi everyone,",
    "Here is your weekly technology digest covering open source updates.",
    "Read full articles on https://techweekly.org/digest-42",
    "",
    "Best regards,",
    "The TechWeekly Team"
]
create_simple_pdf("samples/sample_clean_email.pdf", clean_lines)
print("Sample PDFs created successfully!")
