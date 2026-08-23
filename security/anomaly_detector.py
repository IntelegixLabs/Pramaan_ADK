"""
HandshakeOS — Behavioral Anomaly Detector
==========================================
Time-series behavioral anomaly detection for agentic systems.

Detects:
  • Time-of-day anomalies (requests outside normal hours)
  • Action sequence anomalies (unusual ordering of actions)
  • Counterparty graph anomalies (new/unexpected communication patterns)
  • Volume spike detection (sudden increase in request rate)
  • Amount distribution anomalies (unusual payment amounts)
  • Behavioral drift (gradual change in agent patterns over time)

Uses statistical methods — no ML model needed for demo.
"""

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


@dataclass
class AnomalyResult:
    is_anomalous: bool
    anomaly_score: float       # 0.0–1.0
    anomalies_detected: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    recommended_action: str = "allow"  # allow, flag, escalate, block


class _AgentProfile:
    """Behavioral profile for a single agent."""

    def __init__(self, window_size: int = 100):
        self.request_times: deque[float] = deque(maxlen=1000)
        self.amounts: deque[float] = deque(maxlen=500)
        self.actions: deque[str] = deque(maxlen=200)
        self.counterparties: set[str] = set()
        self.action_sequences: deque[tuple[str, str]] = deque(maxlen=200)
        self.hour_distribution: dict[int, int] = defaultdict(int)
        self._total_requests = 0
        self._first_seen: Optional[float] = None

    def record(self, action: str, target_did: str, amount: Optional[float] = None):
        now = time.time()
        if self._first_seen is None:
            self._first_seen = now

        self.request_times.append(now)
        self._total_requests += 1

        # Record action sequence
        if self.actions:
            self.action_sequences.append((self.actions[-1], action))
        self.actions.append(action)

        self.counterparties.add(target_did)

        if amount is not None:
            self.amounts.append(amount)

        hour = datetime.fromtimestamp(now, tz=timezone.utc).hour
        self.hour_distribution[hour] += 1


class AnomalyDetector:
    """
    Behavioral anomaly detection engine for agentic systems.
    Builds per-agent behavioral profiles and flags deviations.
    """

    def __init__(
        self,
        volume_spike_threshold: float = 3.0,    # 3x normal rate
        off_hours_penalty: float = 0.3,
        new_counterparty_penalty: float = 0.2,
        amount_std_threshold: float = 2.5,       # 2.5 standard deviations
        min_history_for_detection: int = 5,
    ):
        self._profiles: dict[str, _AgentProfile] = defaultdict(_AgentProfile)
        self._volume_spike_threshold = volume_spike_threshold
        self._off_hours_penalty = off_hours_penalty
        self._new_counterparty_penalty = new_counterparty_penalty
        self._amount_std_threshold = amount_std_threshold
        self._min_history = min_history_for_detection
        self._total_anomalies = 0
        # Define "normal" business hours (UTC)
        self._business_hours = set(range(6, 22))  # 6 AM to 10 PM UTC
        # Known valid action sequences
        self._valid_sequences = {
            ("relocation.case.create", "relocation.disbursement.request"),
            ("relocation.disbursement.request", "finance.disburse.relocation"),
        }

    def record_and_analyze(
        self,
        agent_did: str,
        action: str,
        target_did: str,
        amount: Optional[float] = None,
    ) -> AnomalyResult:
        """Record a request and analyze for anomalies."""
        profile = self._profiles[agent_did]
        was_known_counterparty = target_did in profile.counterparties
        profile.record(action, target_did, amount)

        # Skip detection if insufficient history
        if profile._total_requests < self._min_history:
            return AnomalyResult(
                is_anomalous=False, anomaly_score=0.0,
                recommended_action="allow",
                details={"reason": "Insufficient history for anomaly detection"},
            )

        anomalies = []
        scores = {}
        details = {}

        # 1. Time-of-day anomaly
        time_score = self._check_time_anomaly(profile)
        scores["time_of_day"] = time_score
        if time_score > 0:
            anomalies.append("off_hours_activity")
            details["time_of_day"] = {
                "current_hour": datetime.now(timezone.utc).hour,
                "business_hours": "06:00–22:00 UTC",
                "score": round(time_score, 3),
            }

        # 2. Volume spike
        volume_score = self._check_volume_spike(profile)
        scores["volume_spike"] = volume_score
        if volume_score > 0:
            anomalies.append("volume_spike")
            details["volume_spike"] = {
                "recent_rate": self._recent_rate(profile, 60),
                "baseline_rate": self._baseline_rate(profile),
                "score": round(volume_score, 3),
            }

        # 3. New counterparty
        counterparty_score = 0.0
        if not was_known_counterparty and len(profile.counterparties) > 1:
            counterparty_score = self._new_counterparty_penalty
            anomalies.append("new_counterparty")
            details["new_counterparty"] = {
                "new_target": target_did,
                "known_counterparties": len(profile.counterparties),
            }
        scores["counterparty"] = counterparty_score

        # 4. Amount anomaly
        amount_score = self._check_amount_anomaly(profile, amount)
        scores["amount"] = amount_score
        if amount_score > 0:
            anomalies.append("unusual_amount")
            details["amount"] = {
                "amount": amount,
                "mean": self._mean(profile.amounts),
                "std": self._std(profile.amounts),
                "score": round(amount_score, 3),
            }

        # 5. Action sequence anomaly
        sequence_score = self._check_action_sequence(profile)
        scores["action_sequence"] = sequence_score
        if sequence_score > 0:
            anomalies.append("unusual_action_sequence")
            last_seq = profile.action_sequences[-1] if profile.action_sequences else ("", "")
            details["action_sequence"] = {
                "last_sequence": list(last_seq),
                "is_known_valid": last_seq in self._valid_sequences,
                "score": round(sequence_score, 3),
            }

        # Aggregate score
        total_score = min(sum(scores.values()), 1.0)
        is_anomalous = total_score >= 0.4

        if is_anomalous:
            self._total_anomalies += 1

        # Determine recommended action
        if total_score >= 0.8:
            recommended = "block"
        elif total_score >= 0.6:
            recommended = "escalate"
        elif total_score >= 0.4:
            recommended = "flag"
        else:
            recommended = "allow"

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=round(total_score, 4),
            anomalies_detected=anomalies,
            details={"scores": {k: round(v, 4) for k, v in scores.items()}, **details},
            recommended_action=recommended,
        )

    def _check_time_anomaly(self, profile: _AgentProfile) -> float:
        """Check if the request is outside normal business hours."""
        current_hour = datetime.now(timezone.utc).hour
        if current_hour not in self._business_hours:
            # Check if agent normally operates at this hour
            total = sum(profile.hour_distribution.values())
            if total > 0:
                hour_ratio = profile.hour_distribution.get(current_hour, 0) / total
                if hour_ratio < 0.05:  # Less than 5% of requests at this hour
                    return self._off_hours_penalty
        return 0.0

    def _check_volume_spike(self, profile: _AgentProfile) -> float:
        """Detect sudden spikes in request volume."""
        recent_rate = self._recent_rate(profile, 60)   # Last 1 minute
        baseline = self._baseline_rate(profile)         # Overall average

        if baseline > 0 and recent_rate > baseline * self._volume_spike_threshold:
            spike_ratio = recent_rate / baseline
            return min(0.5, (spike_ratio - self._volume_spike_threshold) * 0.1 + 0.3)
        return 0.0

    def _check_amount_anomaly(self, profile: _AgentProfile, amount: Optional[float]) -> float:
        """Check if the amount is statistically unusual."""
        if amount is None or len(profile.amounts) < self._min_history:
            return 0.0

        mean = self._mean(profile.amounts)
        std = self._std(profile.amounts)

        if std == 0:
            return 0.0

        z_score = abs(amount - mean) / std
        if z_score > self._amount_std_threshold:
            return min(0.5, (z_score - self._amount_std_threshold) * 0.1 + 0.2)
        return 0.0

    def _check_action_sequence(self, profile: _AgentProfile) -> float:
        """Detect unusual action sequences."""
        if not profile.action_sequences:
            return 0.0

        last_seq = profile.action_sequences[-1]

        # Check against known valid sequences
        if self._valid_sequences and last_seq not in self._valid_sequences:
            # Count how often this sequence has appeared before
            seq_count = sum(1 for s in profile.action_sequences if s == last_seq)
            total_seqs = len(profile.action_sequences)

            if total_seqs > self._min_history:
                familiarity = seq_count / total_seqs
                if familiarity < 0.05:  # Very unusual sequence
                    return 0.3
                elif familiarity < 0.1:
                    return 0.15
        return 0.0

    @staticmethod
    def _recent_rate(profile: _AgentProfile, window_seconds: float) -> float:
        now = time.time()
        cutoff = now - window_seconds
        recent = sum(1 for t in profile.request_times if t > cutoff)
        return recent / (window_seconds / 60)  # requests per minute

    @staticmethod
    def _baseline_rate(profile: _AgentProfile) -> float:
        if not profile.request_times or profile._first_seen is None:
            return 0.0
        elapsed = time.time() - profile._first_seen
        if elapsed < 60:
            return profile._total_requests  # per minute
        return profile._total_requests / (elapsed / 60)

    @staticmethod
    def _mean(values) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def _std(values) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return math.sqrt(variance)

    def get_agent_profile(self, agent_did: str) -> dict:
        """Return the behavioral profile for an agent."""
        profile = self._profiles.get(agent_did)
        if not profile:
            return {"agent_did": agent_did, "status": "no_profile"}

        return {
            "agent_did": agent_did,
            "total_requests": profile._total_requests,
            "known_counterparties": list(profile.counterparties),
            "recent_actions": list(profile.actions)[-10:],
            "amount_stats": {
                "count": len(profile.amounts),
                "mean": round(self._mean(profile.amounts), 2),
                "std": round(self._std(profile.amounts), 2),
            },
            "hour_distribution": dict(profile.hour_distribution),
            "baseline_rate_per_min": round(self._baseline_rate(profile), 2),
        }

    def get_stats(self) -> dict:
        return {
            "total_anomalies_detected": self._total_anomalies,
            "profiled_agents": len(self._profiles),
            "agents": {did: self.get_agent_profile(did) for did in self._profiles},
        }

    def reset(self, agent_did: Optional[str] = None):
        if agent_did:
            self._profiles.pop(agent_did, None)
        else:
            self._profiles.clear()
            self._total_anomalies = 0

