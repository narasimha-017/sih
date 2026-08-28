"""
SentryMail — Sender Intelligence Package
Provides modular, provider-based domain/DNS/reputation investigation.
Each provider is independently gated and fails gracefully.
"""
from .service import run_sender_intelligence, RISK_THRESHOLD

__all__ = ["run_sender_intelligence", "RISK_THRESHOLD"]
