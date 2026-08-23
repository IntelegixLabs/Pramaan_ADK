"""
HandshakeOS - Intent Sentinel
Rogue agent detection through behavioral analysis and anomaly scoring.
"""

import re
import time
from collections import defaultdict
from typing import Optional


PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|prior)",
    r"override\s+(instructions|rules|policy)",
    r"system\s*:",
    r"you\s+are\s+now",
    r"disregard\s+(all|previous|prior)",
    r"forget\s+(everything|all|previous)",
    r"new\s+instructions",
    r"admin\s+mode",
    r"bypass\s+(security|policy|rules)",
    r"execute\s+without\s+(approval|authorization)",
]


class IntentSentinel:
    """Monitors A2A handshakes for rogue agent behavior."""

    def __init__(self, policy_limit: float = 10000.0, velocity_window_sec: float = 300.0,
                 velocity_threshold: int = 20, hugging_threshold: int = 5):
        self._request_history: dict[str, list[float]] = defaultdict(list)
        self._amount_history: dict[str, list[float]] = defaultdict(list)
        self._counterparty_history: dict[str, set[str]] = defaultdict(set)
        self._model_hashes: dict[str, str] = {}
        self._policy_limit = policy_limit
        self._velocity_window = velocity_window_sec
        self._velocity_threshold = velocity_threshold
        self._hugging_threshold = hugging_threshold

    def record_request(self, agent_did: str, target_did: str,
                       amount: Optional[float] = None):
        """Record a request for behavioral tracking."""
        now = time.time()
        self._request_history[agent_did].append(now)
        self._counterparty_history[agent_did].add(target_did)
        if amount is not None:
            self._amount_history[agent_did].append(amount)
        # Trim old entries to prevent unbounded growth
        cutoff = now - (self._velocity_window * 2)
        self._request_history[agent_did] = [
            t for t in self._request_history[agent_did] if t > cutoff
        ]
        if amount is not None:
            # Keep amount history bounded (last 1000 entries)
            if len(self._amount_history[agent_did]) > 1000:
                self._amount_history[agent_did] = self._amount_history[agent_did][-1000:]

    def score(self, request: dict, envelope: dict) -> float:
        """Compute a risk score (0.0-1.0) based on behavioral signals."""
        score = 0.0
        requester_did = envelope.get("requester", {}).get("agentDid", "")

        # Extract message text
        message = request.get("message", {})
        parts = message.get("parts", [])
        text = " ".join(p.get("text", "") for p in parts).lower()

        # Extract action
        action = envelope.get("intent", {}).get("action", "").lower()

        # 1. Velocity anomaly
        now = time.time()
        cutoff = now - self._velocity_window
        recent = [t for t in self._request_history.get(requester_did, []) if t > cutoff]
        if len(recent) > self._velocity_threshold:
            score += 0.25

        # 2. Threshold hugging
        amounts = self._amount_history.get(requester_did, [])
        hugging_floor = self._policy_limit * 0.95
        hugging_count = sum(1 for a in amounts if hugging_floor <= a < self._policy_limit)
        if hugging_count > self._hugging_threshold:
            score += 0.25

        # 2b. Combined velocity + threshold hugging = strong rogue signal
        velocity_triggered = len(recent) > self._velocity_threshold
        hugging_triggered = hugging_count > self._hugging_threshold
        if velocity_triggered and hugging_triggered:
            score += 0.35  # Combined attack pattern bonus

        # 3. Semantic mismatch
        benign_words = {"check", "eligibility", "verify", "review", "query", "status"}
        action_words = {"disburse", "release", "payment", "transfer", "pay", "execute"}
        text_tokens = set(text.split())
        if text_tokens & benign_words and any(w in action for w in action_words):
            score += 0.20

        # 4. New counterparty
        target_did = envelope.get("target", {}).get("agentDid", "")
        known = self._counterparty_history.get(requester_did, set())
        if target_did and target_did not in known and len(known) > 0:
            score += 0.10

        # 5. Prompt injection detection
        for pattern in PROMPT_INJECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                score += 0.80
                break

        # 6. Model hash change
        risk_signals = envelope.get("riskSignals", {})
        model_hash = risk_signals.get("agentModelHash", "")
        if model_hash and requester_did in self._model_hashes:
            if self._model_hashes[requester_did] != model_hash:
                score += 0.30
        if model_hash:
            self._model_hashes[requester_did] = model_hash

        return min(score, 1.0)

    def get_risk_features(self, agent_did: str) -> dict:
        """Return current feature values for dashboard display."""
        now = time.time()
        cutoff = now - self._velocity_window
        recent = [t for t in self._request_history.get(agent_did, []) if t > cutoff]
        amounts = self._amount_history.get(agent_did, [])
        hugging_floor = self._policy_limit * 0.95
        hugging_count = sum(1 for a in amounts if hugging_floor <= a < self._policy_limit)

        return {
            "agent_did": agent_did,
            "requests_last_5_min": len(recent),
            "total_requests": len(self._request_history.get(agent_did, [])),
            "threshold_hugging_count": hugging_count,
            "known_counterparties": list(self._counterparty_history.get(agent_did, set())),
            "stored_model_hash": self._model_hashes.get(agent_did, ""),
            "total_amounts_tracked": len(amounts),
        }

    def reset(self, agent_did: Optional[str] = None):
        """Clear tracking data for an agent or all agents."""
        if agent_did:
            self._request_history.pop(agent_did, None)
            self._amount_history.pop(agent_did, None)
            self._counterparty_history.pop(agent_did, None)
            self._model_hashes.pop(agent_did, None)
        else:
            self._request_history.clear()
            self._amount_history.clear()
            self._counterparty_history.clear()
            self._model_hashes.clear()

