"""
HandshakeOS — Security Module
Advanced security features for the Agentic Future:
  • Audit Logger         — Structured, append-only security event trail
  • Rate Limiter         — Per-agent and per-IP rate limiting
  • Prompt Injection Shield — Multi-layer prompt injection detection
  • Replay Guard         — Nonce/timestamp-based replay attack protection
  • Anomaly Detector     — Time-series behavioral anomaly detection
  • Honeypot / Canary    — Deception-based rogue agent trapping
"""

from security.audit_logger import AuditLogger, AuditEvent, AuditSeverity, AuditCategory
from security.rate_limiter import RateLimiter, RateLimitResult
from security.prompt_injection_shield import PromptInjectionShield, InjectionDetectionResult
from security.replay_guard import ReplayGuard, ReplayCheckResult
from security.anomaly_detector import AnomalyDetector, AnomalyResult
from security.honeypot import HoneypotCanary, CanaryAlert

__all__ = [
    "AuditLogger", "AuditEvent", "AuditSeverity", "AuditCategory",
    "RateLimiter", "RateLimitResult",
    "PromptInjectionShield", "InjectionDetectionResult",
    "ReplayGuard", "ReplayCheckResult",
    "AnomalyDetector", "AnomalyResult",
    "HoneypotCanary", "CanaryAlert",
]

