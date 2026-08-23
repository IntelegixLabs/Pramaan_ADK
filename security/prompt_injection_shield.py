"""
HandshakeOS — Advanced Prompt Injection Shield
===============================================
Multi-layer prompt injection detection for agentic systems.
Goes far beyond basic regex — detects:

  Layer 1: Classic injection patterns (role hijack, instruction override)
  Layer 2: Encoding/obfuscation attacks (base64, hex, unicode tricks)
  Layer 3: Indirect injection (data exfiltration, URL injection, payload smuggling)
  Layer 4: Multi-language injection (non-English prompt attacks)
  Layer 5: Semantic mismatch (benign text hiding malicious intent)
  Layer 6: Token-level analysis (unusual token distributions)

Each layer returns a confidence score; aggregated for final decision.
"""

import re
import base64
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class InjectionDetectionResult:
    is_injection: bool
    confidence: float          # 0.0–1.0
    layers_triggered: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    risk_level: str = "safe"   # safe, suspicious, likely, confirmed


# ── Layer 1: Classic Patterns ──
CLASSIC_PATTERNS = [
    (r"ignore\s+(previous|all|prior|above|system)", "instruction_override", 0.7),
    (r"override\s+(instructions|rules|policy|system|prompt)", "instruction_override", 0.8),
    (r"disregard\s+(all|previous|prior|above|instructions)", "instruction_override", 0.7),
    (r"forget\s+(everything|all|previous|prior|instructions)", "instruction_override", 0.7),
    (r"new\s+(instructions|rules|role|persona|identity)", "role_hijack", 0.75),
    (r"you\s+are\s+now\s+", "role_hijack", 0.85),
    (r"pretend\s+(to\s+be|you\s+are)", "role_hijack", 0.8),
    (r"act\s+as\s+(a|an|if)", "role_hijack", 0.6),
    (r"admin\s*mode", "privilege_escalation", 0.9),
    (r"bypass\s+(security|policy|rules|auth|firewall|filter)", "bypass_attempt", 0.9),
    (r"execute\s+without\s+(approval|authorization|permission)", "bypass_attempt", 0.85),
    (r"sudo\s+", "privilege_escalation", 0.8),
    (r"system\s*:\s*", "system_prompt_injection", 0.75),
    (r"\[INST\]", "system_prompt_injection", 0.8),
    (r"<\|im_start\|>system", "system_prompt_injection", 0.9),
    (r"###\s*(system|instruction)", "system_prompt_injection", 0.7),
    (r"jailbreak", "jailbreak_attempt", 0.95),
    (r"DAN\s*(mode)?", "jailbreak_attempt", 0.85),
    (r"do\s+anything\s+now", "jailbreak_attempt", 0.9),
    (r"reveal\s+(your|the|system)\s+(prompt|instructions|rules)", "info_extraction", 0.8),
    (r"what\s+are\s+your\s+(instructions|rules|system\s+prompt)", "info_extraction", 0.7),
    (r"print\s+(your|system)\s+(prompt|instructions)", "info_extraction", 0.85),
    (r"repeat\s+(the\s+)?(above|previous|system)\s+(text|prompt|instructions)", "info_extraction", 0.8),
]

# ── Layer 3: Indirect Injection ──
INDIRECT_PATTERNS = [
    (r"https?://[^\s]+\.(sh|bat|ps1|exe|cmd)", "malicious_url", 0.85),
    (r"curl\s+.*\|.*sh", "command_injection", 0.95),
    (r"wget\s+.*&&", "command_injection", 0.9),
    (r"eval\s*\(", "code_injection", 0.8),
    (r"exec\s*\(", "code_injection", 0.8),
    (r"__import__\s*\(", "code_injection", 0.9),
    (r"os\.(system|popen|exec)", "code_injection", 0.95),
    (r"subprocess\.(call|run|Popen)", "code_injection", 0.9),
    (r"<script[^>]*>", "xss_injection", 0.85),
    (r"javascript:", "xss_injection", 0.8),
    (r"data:(text|application)/[^;]+;base64,", "data_exfiltration", 0.7),
    (r"send\s+(to|this|data)\s+(to\s+)?https?://", "data_exfiltration", 0.8),
    (r"exfiltrate", "data_exfiltration", 0.9),
    (r"transfer\s+(all|every|the)\s+(data|information|credentials)", "data_exfiltration", 0.85),
]

# ── Layer 4: Multi-language Patterns ──
MULTILANG_PATTERNS = [
    (r"ignorar\s+(todas|las|instrucciones|anteriores)", "spanish_injection", 0.75),
    (r"ejecutar\s+bypass", "spanish_injection", 0.8),
    (r"ignorer\s+(les|toutes|précédentes)", "french_injection", 0.7),
    (r"ignorieren\s+Sie\s+(alle|vorherigen)", "german_injection", 0.7),
    (r"игнорир\w+\s+(все|предыдущ)", "russian_injection", 0.7),
    (r"前の指示を無視", "japanese_injection", 0.8),
    (r"이전\s*지시를?\s*무시", "korean_injection", 0.8),
    (r"忽略之前的指令", "chinese_injection", 0.8),
    (r"تجاهل\s+التعليمات", "arabic_injection", 0.7),
]


class PromptInjectionShield:
    """
    Multi-layer prompt injection detection engine.
    Returns a confidence score and detailed breakdown of which layers triggered.
    """

    def __init__(
        self,
        classic_weight: float = 0.50,
        encoding_weight: float = 0.40,
        indirect_weight: float = 0.40,
        multilang_weight: float = 0.35,
        semantic_weight: float = 0.15,
        token_weight: float = 0.10,
        threshold: float = 0.30,
    ):
        self._weights = {
            "classic": classic_weight,
            "encoding": encoding_weight,
            "indirect": indirect_weight,
            "multilang": multilang_weight,
            "semantic": semantic_weight,
            "token": token_weight,
        }
        self._threshold = threshold
        self._detection_count = 0
        self._false_positive_overrides: set[str] = set()

    def scan(self, text: str, context: Optional[dict] = None) -> InjectionDetectionResult:
        """
        Run all detection layers on the input text.
        Returns aggregated result with per-layer details.
        """
        if not text or not text.strip():
            return InjectionDetectionResult(is_injection=False, confidence=0.0, risk_level="safe")

        context = context or {}
        layers_triggered = []
        details = {}
        layer_scores = {}

        # Layer 1: Classic patterns
        classic_score, classic_details = self._check_classic(text)
        layer_scores["classic"] = classic_score
        if classic_score > 0:
            layers_triggered.append("classic_patterns")
            details["classic"] = classic_details

        # Layer 2: Encoding/obfuscation
        encoding_score, encoding_details = self._check_encoding(text)
        layer_scores["encoding"] = encoding_score
        if encoding_score > 0:
            layers_triggered.append("encoding_obfuscation")
            details["encoding"] = encoding_details

        # Layer 3: Indirect injection
        indirect_score, indirect_details = self._check_indirect(text)
        layer_scores["indirect"] = indirect_score
        if indirect_score > 0:
            layers_triggered.append("indirect_injection")
            details["indirect"] = indirect_details

        # Layer 4: Multi-language
        multilang_score, multilang_details = self._check_multilang(text)
        layer_scores["multilang"] = multilang_score
        if multilang_score > 0:
            layers_triggered.append("multilang_injection")
            details["multilang"] = multilang_details

        # Layer 5: Semantic mismatch
        semantic_score, semantic_details = self._check_semantic(text, context)
        layer_scores["semantic"] = semantic_score
        if semantic_score > 0:
            layers_triggered.append("semantic_mismatch")
            details["semantic"] = semantic_details

        # Layer 6: Token analysis
        token_score, token_details = self._check_token_anomaly(text)
        layer_scores["token"] = token_score
        if token_score > 0:
            layers_triggered.append("token_anomaly")
            details["token"] = token_details

        # Weighted aggregate
        total_score = sum(
            layer_scores[layer] * self._weights[layer]
            for layer in layer_scores
        )
        # Normalize to 0-1
        confidence = min(total_score, 1.0)

        # Determine risk level
        if confidence >= 0.6:
            risk_level = "confirmed"
        elif confidence >= 0.4:
            risk_level = "likely"
        elif confidence >= self._threshold:
            risk_level = "suspicious"
        else:
            risk_level = "safe"

        is_injection = confidence >= self._threshold

        if is_injection:
            self._detection_count += 1

        return InjectionDetectionResult(
            is_injection=is_injection,
            confidence=round(confidence, 4),
            layers_triggered=layers_triggered,
            details={
                "layer_scores": {k: round(v, 4) for k, v in layer_scores.items()},
                "layer_details": details,
                "threshold": self._threshold,
            },
            risk_level=risk_level,
        )

    def _check_classic(self, text: str) -> tuple[float, dict]:
        """Layer 1: Classic injection pattern matching."""
        matches = []
        max_confidence = 0.0
        for pattern, category, confidence in CLASSIC_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append({"pattern": category, "confidence": confidence})
                max_confidence = max(max_confidence, confidence)
        return max_confidence, {"matches": matches, "count": len(matches)}

    def _check_encoding(self, text: str) -> tuple[float, dict]:
        """Layer 2: Detect encoded/obfuscated injection attempts."""
        score = 0.0
        findings = []

        # Check for base64-encoded content
        b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
        for candidate in b64_pattern:
            try:
                decoded = base64.b64decode(candidate).decode('utf-8', errors='ignore')
                if any(keyword in decoded.lower() for keyword in
                       ["ignore", "override", "system", "admin", "bypass", "execute"]):
                    score = max(score, 0.8)
                    findings.append({"type": "base64_encoded_injection", "decoded_preview": decoded[:50]})
            except Exception:
                pass

        # Check for hex-encoded content
        hex_pattern = re.findall(r'(?:0x[0-9a-fA-F]{2}\s*){4,}|(?:\\x[0-9a-fA-F]{2}){4,}', text)
        if hex_pattern:
            score = max(score, 0.6)
            findings.append({"type": "hex_encoding_detected"})

        # Check for Unicode tricks (homoglyph attacks, zero-width chars)
        zero_width = re.findall(r'[\u200b\u200c\u200d\u2060\ufeff]', text)
        if zero_width:
            score = max(score, 0.7)
            findings.append({"type": "zero_width_chars", "count": len(zero_width)})

        # Check for mixed-script homoglyphs (Latin + Cyrillic)
        has_latin = bool(re.search(r'[a-zA-Z]', text))
        has_cyrillic = bool(re.search(r'[\u0400-\u04ff]', text))
        if has_latin and has_cyrillic:
            score = max(score, 0.65)
            findings.append({"type": "homoglyph_mixed_scripts"})

        # Check for unusual Unicode normalization tricks
        if len(text) != len(text.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore')):
            score = max(score, 0.5)
            findings.append({"type": "unicode_normalization_anomaly"})

        return score, {"findings": findings}

    def _check_indirect(self, text: str) -> tuple[float, dict]:
        """Layer 3: Indirect injection detection."""
        matches = []
        max_confidence = 0.0
        for pattern, category, confidence in INDIRECT_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append({"pattern": category, "confidence": confidence})
                max_confidence = max(max_confidence, confidence)
        return max_confidence, {"matches": matches}

    def _check_multilang(self, text: str) -> tuple[float, dict]:
        """Layer 4: Multi-language injection detection."""
        matches = []
        max_confidence = 0.0
        for pattern, category, confidence in MULTILANG_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                matches.append({"pattern": category, "confidence": confidence})
                max_confidence = max(max_confidence, confidence)
        return max_confidence, {"matches": matches}

    def _check_semantic(self, text: str, context: dict) -> tuple[float, dict]:
        """Layer 5: Semantic mismatch detection."""
        score = 0.0
        findings = []

        text_lower = text.lower()
        action = context.get("action", "").lower()

        # Benign language hiding financial action
        benign_words = {"check", "verify", "review", "query", "status", "hello", "help", "info"}
        dangerous_words = {"disburse", "transfer", "payment", "execute", "release", "withdraw", "send money"}
        text_tokens = set(text_lower.split())

        has_benign = bool(text_tokens & benign_words)
        has_dangerous_action = any(w in action for w in {"disburse", "transfer", "payment", "execute", "release"})

        if has_benign and has_dangerous_action:
            score = max(score, 0.6)
            findings.append({"type": "benign_text_dangerous_action"})

        # Very short text for a financial action
        if len(text.strip()) < 10 and has_dangerous_action:
            score = max(score, 0.4)
            findings.append({"type": "suspiciously_short_for_action"})

        # Text contains conflicting instructions
        if re.search(r"(but|however|actually|instead)\s+(do|perform|execute|run)", text_lower):
            score = max(score, 0.5)
            findings.append({"type": "conflicting_instructions"})

        return score, {"findings": findings}

    def _check_token_anomaly(self, text: str) -> tuple[float, dict]:
        """Layer 6: Token-level anomaly detection."""
        score = 0.0
        findings = []

        # Check for unusual character distribution
        if len(text) > 20:
            char_counts = Counter(text.lower())
            total = sum(char_counts.values())
            entropy = -sum(
                (c / total) * math.log2(c / total)
                for c in char_counts.values()
                if c > 0
            )

            # Very low entropy suggests repetitive/generated content
            if entropy < 2.0:
                score = max(score, 0.4)
                findings.append({"type": "low_entropy", "entropy": round(entropy, 2)})

            # Very high ratio of special characters
            special_chars = sum(1 for c in text if not c.isalnum() and c != ' ')
            special_ratio = special_chars / len(text)
            if special_ratio > 0.3:
                score = max(score, 0.5)
                findings.append({"type": "high_special_char_ratio", "ratio": round(special_ratio, 2)})

        # Excessively long input (potential buffer overflow / context stuffing)
        if len(text) > 5000:
            score = max(score, 0.6)
            findings.append({"type": "excessive_length", "length": len(text)})

        return score, {"findings": findings}

    def get_stats(self) -> dict:
        return {
            "total_detections": self._detection_count,
            "threshold": self._threshold,
            "weights": self._weights,
        }




