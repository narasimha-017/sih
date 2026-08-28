import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# Resolve workspace root (two levels up from this file: backend/app/models/ → workspace)
WORKSPACE = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
DEFAULT_DB_URL = f"sqlite:///{os.path.join(WORKSPACE, 'email_forensics.db')}"

Base = declarative_base()


class ForensicCase(Base):
    __tablename__ = 'forensic_cases'

    id                  = Column(String,  primary_key=True)
    blockchain_tx       = Column(String)
    evidence_hash       = Column(String)
    risk_score          = Column(Integer)
    classification      = Column(String)
    sender              = Column(String)
    subject             = Column(String)
    reply_to_anomaly    = Column(Boolean)
    spf_passed          = Column(Boolean)
    dkim_passed         = Column(Boolean)
    dmarc_passed        = Column(Boolean)
    body_content_exerpt = Column(String)   # intentional spelling kept from original spec

    hops = relationship("SMTPHop", back_populates="case")


class SMTPHop(Base):
    __tablename__ = 'smtp_hops'

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    case_id             = Column(String,  ForeignKey('forensic_cases.id'))
    hop_number          = Column(Integer)
    ip_address          = Column(String)
    mail_server         = Column(String)
    location            = Column(String)
    verification_status = Column(String)

    case = relationship("ForensicCase", back_populates="hops")


def init_database(db_url=None):
    if db_url is None:
        db_url = DEFAULT_DB_URL
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    print(f"🗄️ Database tables created successfully at: {db_url}")
    return engine


if __name__ == "__main__":
    init_database()
