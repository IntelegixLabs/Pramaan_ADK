"""
HandshakeOS — API Rate Limiter
===============================
Per-agent and per-IP sliding-window rate limiter.
Prevents denial-of-service and brute-force attacks against the governance gateway.

Implements:
  • Per-agent DID rate limiting (governance requests)
  • Per-IP rate limiting (API-level)
  • Graduated penalties (warn → throttle → block)
  • Configurable burst and sustained limits
"""

import time
from collections import defaultdict
from dataclasses import dataclass
from threading import Lock
from typing import Optional


@dataclass
class RateLimitResult:
    allowed: bool
    reason: str = ""
    remaining: int = 0
    retry_after_seconds: float = 0.0
    penalty_level: str = "none"   # none, warn, throttle, block


class _SlidingWindow:
    """Sliding window counter for rate limiting."""

    def __init__(self, window_seconds: float, max_requests: int):
        self.window_seconds = window_seconds
        self.max_requests = max_requests
        self._timestamps: list[float] = []

    def record(self) -> int:
        """Record a request and return current count in window."""
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        self._timestamps.append(now)
        return len(self._timestamps)

    def count(self) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        return len(self._timestamps)

    def oldest_in_window(self) -> Optional[float]:
        if not self._timestamps:
            return None
        now = time.time()
        cutoff = now - self.window_seconds
        self._timestamps = [t for t in self._timestamps if t > cutoff]
        return self._timestamps[0] if self._timestamps else None


class RateLimiter:
    """
    Sliding-window rate limiter with graduated penalties.

    Thresholds:
      - Below warn_ratio:     ALLOW
      - warn_ratio–1.0:       ALLOW + warning
      - 1.0–block_ratio:      THROTTLE (allow but flag)
      - Above block_ratio:    BLOCK
    """

    def __init__(
        self,
        agent_requests_per_minute: int = 30,
        agent_requests_per_hour: int = 200,
        ip_requests_per_minute: int = 60,
        ip_requests_per_hour: int = 500,
        warn_ratio: float = 0.8,
        block_ratio: float = 1.5,
        penalty_duration_seconds: float = 300.0,
    ):
        self._agent_minute_limit = agent_requests_per_minute
        self._agent_hour_limit = agent_requests_per_hour
        self._ip_minute_limit = ip_requests_per_minute
        self._ip_hour_limit = ip_requests_per_hour
        self._warn_ratio = warn_ratio
        self._block_ratio = block_ratio
        self._penalty_duration = penalty_duration_seconds

        self._agent_minute_windows: dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(60, agent_requests_per_minute)
        )
        self._agent_hour_windows: dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(3600, agent_requests_per_hour)
        )
        self._ip_minute_windows: dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(60, ip_requests_per_minute)
        )
        self._ip_hour_windows: dict[str, _SlidingWindow] = defaultdict(
            lambda: _SlidingWindow(3600, ip_requests_per_hour)
        )

        # Penalty tracking
        self._blocked_until: dict[str, float] = {}
        self._lock = Lock()

    def check_agent(self, agent_did: str) -> RateLimitResult:
        """Check rate limit for an agent DID."""
        with self._lock:
            # Check if agent is in penalty block
            block_until = self._blocked_until.get(f"agent:{agent_did}", 0)
            if time.time() < block_until:
                return RateLimitResult(
                    allowed=False,
                    reason=f"Agent {agent_did} is rate-limited (penalty block)",
                    retry_after_seconds=block_until - time.time(),
                    penalty_level="block",
                )

            # Check counts first without recording (to avoid inflating counts for blocked requests)
            minute_count = self._agent_minute_windows[agent_did].count()
            hour_count = self._agent_hour_windows[agent_did].count()

            # Include the pending request in the ratio calculation
            minute_ratio = (minute_count + 1) / self._agent_minute_limit
            hour_ratio = (hour_count + 1) / self._agent_hour_limit

            worst_ratio = max(minute_ratio, hour_ratio)
            remaining_minute = max(0, self._agent_minute_limit - minute_count - 1)

            if worst_ratio >= self._block_ratio:
                # Block and apply penalty — do NOT record
                self._blocked_until[f"agent:{agent_did}"] = time.time() + self._penalty_duration
                return RateLimitResult(
                    allowed=False,
                    reason=f"Agent rate limit exceeded ({minute_count + 1}/min, {hour_count + 1}/hr). Penalty applied.",
                    remaining=0,
                    retry_after_seconds=self._penalty_duration,
                    penalty_level="block",
                )

            # Record the request only for allowed requests
            self._agent_minute_windows[agent_did].record()
            self._agent_hour_windows[agent_did].record()

            if worst_ratio >= 1.0:
                return RateLimitResult(
                    allowed=True,
                    reason=f"Agent approaching rate limit ({minute_count + 1}/{self._agent_minute_limit}/min)",
                    remaining=remaining_minute,
                    penalty_level="throttle",
                )

            if worst_ratio >= self._warn_ratio:
                return RateLimitResult(
                    allowed=True,
                    reason=f"Agent nearing rate limit ({minute_count + 1}/{self._agent_minute_limit}/min)",
                    remaining=remaining_minute,
                    penalty_level="warn",
                )

            return RateLimitResult(
                allowed=True,
                remaining=remaining_minute,
                penalty_level="none",
            )

    def check_ip(self, ip_address: str) -> RateLimitResult:
        """Check rate limit for an IP address."""
        with self._lock:
            block_until = self._blocked_until.get(f"ip:{ip_address}", 0)
            if time.time() < block_until:
                return RateLimitResult(
                    allowed=False,
                    reason=f"IP {ip_address} is rate-limited",
                    retry_after_seconds=block_until - time.time(),
                    penalty_level="block",
                )

            # Check counts first without recording
            minute_count = self._ip_minute_windows[ip_address].count()
            hour_count = self._ip_hour_windows[ip_address].count()

            minute_ratio = (minute_count + 1) / self._ip_minute_limit
            hour_ratio = (hour_count + 1) / self._ip_hour_limit
            worst_ratio = max(minute_ratio, hour_ratio)
            remaining = max(0, self._ip_minute_limit - minute_count - 1)

            if worst_ratio >= self._block_ratio:
                self._blocked_until[f"ip:{ip_address}"] = time.time() + self._penalty_duration
                return RateLimitResult(
                    allowed=False,
                    reason=f"IP rate limit exceeded ({minute_count + 1}/min)",
                    remaining=0,
                    retry_after_seconds=self._penalty_duration,
                    penalty_level="block",
                )

            # Record the request only for allowed requests
            self._ip_minute_windows[ip_address].record()
            self._ip_hour_windows[ip_address].record()

            if worst_ratio >= 1.0:
                return RateLimitResult(
                    allowed=True,
                    reason=f"IP nearing rate limit ({minute_count + 1}/min)",
                    remaining=remaining,
                    penalty_level="throttle",
                )

            return RateLimitResult(allowed=True, remaining=remaining, penalty_level="none")

    def get_status(self) -> dict:
        """Return current rate limiter status."""
        now = time.time()
        blocked_agents = {
            k.replace("agent:", ""): v - now
            for k, v in self._blocked_until.items()
            if k.startswith("agent:") and v > now
        }
        blocked_ips = {
            k.replace("ip:", ""): v - now
            for k, v in self._blocked_until.items()
            if k.startswith("ip:") and v > now
        }
        return {
            "blocked_agents": blocked_agents,
            "blocked_ips": blocked_ips,
            "tracked_agents": len(self._agent_minute_windows),
            "tracked_ips": len(self._ip_minute_windows),
        }

    def reset(self, identifier: Optional[str] = None):
        """Reset rate limiting state."""
        with self._lock:
            if identifier:
                self._blocked_until.pop(f"agent:{identifier}", None)
                self._blocked_until.pop(f"ip:{identifier}", None)
                self._agent_minute_windows.pop(identifier, None)
                self._agent_hour_windows.pop(identifier, None)
                self._ip_minute_windows.pop(identifier, None)
                self._ip_hour_windows.pop(identifier, None)
            else:
                self._blocked_until.clear()
                self._agent_minute_windows.clear()
                self._agent_hour_windows.clear()
                self._ip_minute_windows.clear()
                self._ip_hour_windows.clear()

