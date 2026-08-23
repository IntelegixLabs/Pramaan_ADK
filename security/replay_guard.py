"""
HandshakeOS — Replay Attack Guard
===================================
Nonce and timestamp-based replay attack protection for governance envelopes.

Prevents:
  • Exact replay of previously-used governance envelopes
  • Stale envelope submission (timestamp drift beyond tolerance)
  • Nonce reuse across handshake sessions
  • Trust Receipt replay (one-time-use enforcement at protocol level)
"""

import hashlib
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Lock
from typing import Optional


@dataclass
class ReplayCheckResult:
    allowed: bool
    reason: str = ""
    check_type: str = ""   # "nonce", "timestamp", "receipt", "envelope_hash"


class ReplayGuard:
    """
    Nonce-based replay protection with timestamp validation.
    Uses an LRU cache to track seen nonces efficiently.
    """

    def __init__(
        self,
        max_nonce_cache: int = 50000,
        timestamp_tolerance_seconds: float = 300.0,  # 5 minutes
        envelope_ttl_seconds: float = 1800.0,        # 30 minutes
    ):
        self._nonce_cache: OrderedDict[str, float] = OrderedDict()
        self._receipt_cache: OrderedDict[str, float] = OrderedDict()
        self._envelope_hash_cache: OrderedDict[str, float] = OrderedDict()
        self._max_cache = max_nonce_cache
        self._timestamp_tolerance = timestamp_tolerance_seconds
        self._envelope_ttl = envelope_ttl_seconds
        self._lock = Lock()
        self._replay_attempts = 0
        self._total_checks = 0

    def check_envelope(self, envelope: dict) -> ReplayCheckResult:
        """
        Full replay check on a governance envelope:
          1. Nonce uniqueness
          2. Timestamp freshness
          3. Envelope hash uniqueness
        """
        with self._lock:
            self._total_checks += 1

            # 1. Check nonce
            nonce = envelope.get("nonce", "")
            if not nonce:
                self._replay_attempts += 1
                return ReplayCheckResult(
                    allowed=False,
                    reason="Missing nonce in governance envelope",
                    check_type="nonce",
                )

            if nonce in self._nonce_cache:
                self._replay_attempts += 1
                return ReplayCheckResult(
                    allowed=False,
                    reason=f"Nonce already used (replay detected): {nonce[:16]}...",
                    check_type="nonce",
                )

            # 2. Check timestamp freshness
            expires_at = envelope.get("expiresAt", "")
            if expires_at:
                try:
                    exp_dt = datetime.fromisoformat(expires_at)
                    if exp_dt.tzinfo is None:
                        exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    if now > exp_dt:
                        self._replay_attempts += 1
                        return ReplayCheckResult(
                            allowed=False,
                            reason=f"Governance envelope expired at {expires_at}",
                            check_type="timestamp",
                        )
                except (ValueError, TypeError):
                    pass

            # Check handshake timestamp isn't too old
            handshake_id = envelope.get("handshakeId", "")
            if handshake_id:
                # Extract year from handshake ID format: hs-YYYY-XXXXXX
                parts = handshake_id.split("-")
                if len(parts) >= 2:
                    try:
                        hs_year = int(parts[1])
                        current_year = datetime.now(timezone.utc).year
                        if abs(current_year - hs_year) > 1:
                            self._replay_attempts += 1
                            return ReplayCheckResult(
                                allowed=False,
                                reason=f"Handshake ID year {hs_year} is stale",
                                check_type="timestamp",
                            )
                    except ValueError:
                        pass

            # 3. Check envelope hash uniqueness (prevent content-identical replays)
            envelope_str = f"{nonce}:{handshake_id}:{envelope.get('requester', {}).get('agentDid', '')}:{envelope.get('target', {}).get('agentDid', '')}:{envelope.get('intent', {}).get('action', '')}:{envelope.get('expiresAt', '')}"
            envelope_hash = hashlib.sha256(envelope_str.encode()).hexdigest()

            if envelope_hash in self._envelope_hash_cache:
                self._replay_attempts += 1
                return ReplayCheckResult(
                    allowed=False,
                    reason="Duplicate envelope content detected (replay)",
                    check_type="envelope_hash",
                )

            # Record nonce and envelope hash
            self._nonce_cache[nonce] = time.time()
            self._envelope_hash_cache[envelope_hash] = time.time()

            # Evict old entries
            self._evict_expired()

            return ReplayCheckResult(allowed=True, check_type="all_passed")

    def check_trust_receipt(self, receipt_id: str) -> ReplayCheckResult:
        """Check if a Trust Receipt has already been used."""
        with self._lock:
            self._total_checks += 1

            if receipt_id in self._receipt_cache:
                self._replay_attempts += 1
                return ReplayCheckResult(
                    allowed=False,
                    reason=f"Trust Receipt {receipt_id} already used (replay)",
                    check_type="receipt",
                )

            self._receipt_cache[receipt_id] = time.time()
            self._evict_expired()

            return ReplayCheckResult(allowed=True, check_type="receipt")

    def _evict_expired(self):
        """Remove expired entries from caches."""
        now = time.time()
        cutoff = now - self._envelope_ttl

        # Evict old nonces
        while self._nonce_cache and len(self._nonce_cache) > self._max_cache:
            self._nonce_cache.popitem(last=False)
        expired_nonces = [k for k, v in self._nonce_cache.items() if v < cutoff]
        for k in expired_nonces:
            del self._nonce_cache[k]

        # Evict old envelope hashes
        while self._envelope_hash_cache and len(self._envelope_hash_cache) > self._max_cache:
            self._envelope_hash_cache.popitem(last=False)
        expired_hashes = [k for k, v in self._envelope_hash_cache.items() if v < cutoff]
        for k in expired_hashes:
            del self._envelope_hash_cache[k]

        # Evict old receipt IDs
        while self._receipt_cache and len(self._receipt_cache) > self._max_cache:
            self._receipt_cache.popitem(last=False)
        expired_receipts = [k for k, v in self._receipt_cache.items() if v < cutoff]
        for k in expired_receipts:
            del self._receipt_cache[k]

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_checks": self._total_checks,
                "replay_attempts_blocked": self._replay_attempts,
                "nonce_cache_size": len(self._nonce_cache),
                "receipt_cache_size": len(self._receipt_cache),
                "envelope_hash_cache_size": len(self._envelope_hash_cache),
            }

    def reset(self):
        """Clear all caches."""
        with self._lock:
            self._nonce_cache.clear()
            self._receipt_cache.clear()
            self._envelope_hash_cache.clear()
            self._replay_attempts = 0
            self._total_checks = 0

