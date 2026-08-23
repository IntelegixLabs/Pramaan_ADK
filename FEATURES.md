FEATURES.md

# 🛡️ HandshakeOS — Feature Documentation

**Complete technical documentation of all 16 security layers in HandshakeOS.**

---

## Table of Contents

1. [Core Governance Layer (10 Steps)](#1-core-governance-layer-10-steps)
   - [1.1 Agent Identity — Verifiable Credentials](#11-agent-identity--verifiable-credentials)
   - [1.2 Delegation Ledger — Human Chain of Command](#12-delegation-ledger--human-chain-of-command)
   - [1.3 Policy Engine — ZKP Range Proofs](#13-policy-engine--zkp-range-proofs)
   - [1.4 Authority Intersection — Privilege Escalation Prevention](#14-authority-intersection--privilege-escalation-prevention)
   - [1.5 Intent Sentinel — Rogue Agent Detection](#15-intent-sentinel--rogue-agent-detection)
   - [1.6 Circuit Breaker — Automatic Quarantine](#16-circuit-breaker--automatic-quarantine)
   - [1.7 Revocation Service — Sub-Second Global Kill Switch](#17-revocation-service--sub-second-global-kill-switch)
   - [1.8 PoA Validator Quorum — Multi-Party Trust](#18-poa-validator-quorum--multi-party-trust)
   - [1.9 Trust Receipts — Immutable Governance Proof](#19-trust-receipts--immutable-governance-proof)
   - [1.10 Segregation of Duties](#110-segregation-of-duties)
2. [Advanced Security Modules (6 Layers)](#2-advanced-security-modules-6-layers)
   - [2.1 Security Audit Logger](#21-security-audit-logger)
   - [2.2 API Rate Limiter](#22-api-rate-limiter)
   - [2.3 Prompt Injection Shield](#23-prompt-injection-shield)
   - [2.4 Replay Attack Guard](#24-replay-attack-guard)
   - [2.5 Behavioral Anomaly Detector](#25-behavioral-anomaly-detector)
   - [2.6 Honeypot / Canary Token System](#26-honeypot--canary-token-system)
3. [How They Work Together](#3-how-they-work-together)
4. [Production Considerations](#4-production-considerations)

---

## 1. Core Governance Layer (10 Steps)

### 1.1 Agent Identity — Verifiable Credentials

**File:** `identity/vc_issuer.py`, `identity/vc_verifier.py`

**What it does:** Every agent must present an **Agent Passport** — a W3C Verifiable Credential (VC) Data Model v2.0 compatible credential signed as a JWT.

**How it works:**
- The `VCIssuer` issues Agent Passport VCs containing: agent DID, business domain, owner human, allowed actions, forbidden actions, max autonomous amount, counterparty restrictions, and model hash
- VCs are signed using HS256 (demo) — production would use EdDSA or ES256
- The `VCVerifier` validates JWT signature, expiry (`validUntil`), and VC type (`AgentPassport`)
- Each VC has a `jti` (JWT ID) for uniqueness

**What it prevents:**
- Identity spoofing — agents can't impersonate other agents
- Expired credential usage — VCs have time-bounded validity
- Tampered credentials — JWT signature verification catches modifications

**Example Agent Passport claims:**
```json
{
  "type": ["VerifiableCredential", "AgentPassport"],
  "credentialSubject": {
    "id": "did:gcc:agent:hr-relocation-07",
    "agentName": "HR Relocation Agent",
    "allowedActions": ["relocation.case.create", "relocation.disbursement.request"],
    "forbiddenActions": ["finance.payment.approve"],
    "maxAutonomousAmount": {"value": 10000, "currency": "USD"},
    "modelHash": "a1b2c3..."
  }
}
```

---

### 1.2 Delegation Ledger — Human Chain of Command

**File:** `ledger/delegation_ledger.py`, `ledger/schema.sql`

**What it does:** Tracks **human-to-agent delegation grants** in an append-only, hash-chained SQLite ledger. No agent can act without provable human authorization.

**How it works:**
- Human leaders grant delegation rights to agents with: policy ID, scope (allowed actions, patterns, max amounts), time bounds
- Each delegation event is hash-chained to the previous (`previous_event_hash → event_hash`) creating a tamper-evident chain
- Delegation verification checks: valid time window, action in scope (exact or prefix match), no active revocation
- The ledger also stores Trust Receipts and revocation events for complete auditability

**What it prevents:**
- Agents acting without human authorization
- Expired or revoked delegations being used
- Tampered delegation history (hash chain detects modifications)

**Delegation grant example:**
```python
ledger.grant_delegation(
    human_leader_id="did:gcc:employee:global-mobility-director",
    agent_did="did:gcc:agent:hr-relocation-07",
    policy_id="policy-relocation-autopay-v3",
    scope={"actions": ["relocation.disbursement.request"], "maxAmount": 10000},
    valid_hours=24,
)
```

---

### 1.3 Policy Engine — ZKP Range Proofs

**File:** `policy/policy_engine.py`, `policy/zkp_mock_verifier.py`

**What it does:** Verifies that transaction amounts comply with policy limits using **zero-knowledge proofs** — proving `amount ≤ limit` without revealing the actual amount.

**How it works:**
- Policies define: type (range-limit), limit value, currency, version, required actions
- The ZKP mock verifier generates proofs with HMAC-signed tokens containing: limit commitment (SHA-256), constraint satisfaction flag, policy metadata
- Verification checks: HMAC signature integrity, limit commitment match, constraint satisfaction
- Privacy-preserving: the verifier learns only "amount ≤ limit", never the actual amount

**What it prevents:**
- Agents exceeding authorized spending limits
- Proof forgery (HMAC signature verification)
- Policy commitment mismatch attacks

**ZKP flow:**
```
Private input: amount = $8,000
Public input:  limit = $10,000
Proof claim:   "amount_is_under_limit" = true
Verifier sees: claim + commitment + signature (never the $8,000)
```

---

### 1.4 Authority Intersection — Privilege Escalation Prevention

**File:** `agl/gateway.py` → `authority_intersection_check()`

**What it does:** Calculates the **effective permission** as the intersection of five authority dimensions.

**Formula:**
```
Effective Permission = Requester Authority ∩ Target Capability ∩ Human Delegation Scope
                       ∩ Policy Permission ∩ Current Risk State
```

**Checks performed:**
1. Requester has the action in their VC's `allowedActions`
2. The action is not in the agent's `forbiddenActions`
3. The target agent's skill supports the requested action
4. Risk state permits autonomous execution (HIGH/CRITICAL blocks)
5. Segregation of duties — agents cannot self-approve

**What it prevents:**
- Privilege escalation — an HR agent requesting finance.payment.approve
- Forbidden action execution — explicitly blacklisted actions
- Cross-domain capability abuse — skills must match actions

---

### 1.5 Intent Sentinel — Rogue Agent Detection

**File:** `risk/intent_sentinel.py`

**What it does:** Analyzes agent behavior across **6 signals** to compute a risk score (0.0–1.0).

**6 Detection Signals:**

| Signal | Weight | Description |
|--------|--------|-------------|
| **Velocity anomaly** | 0.25 | >20 requests in 5 minutes |
| **Threshold hugging** | 0.25 | >5 requests at 95%+ of policy limit |
| **Combined attack** | 0.35 | Velocity + threshold hugging together |
| **Semantic mismatch** | 0.20 | Benign text (e.g., "check") with dangerous action (e.g., "disburse") |
| **New counterparty** | 0.10 | Agent talks to unknown counterparty |
| **Prompt injection** | 0.30 | Regex-based prompt injection patterns |
| **Model hash change** | 0.30 | Agent's model fingerprint changed (potential compromise) |

**What it prevents:**
- Rogue agents making rapid-fire near-limit transactions
- Compromised agents with changed model weights
- Social engineering via semantic mismatch

---

### 1.6 Circuit Breaker — Automatic Quarantine

**File:** `risk/circuit_breaker.py`

**What it does:** Automatically quarantines agents when risk score exceeds threshold (default: 0.85).

**Actions on trigger:**
1. Agent added to quarantine set
2. All in-flight tasks cancelled
3. Revocation event added to revocation cache
4. All future requests immediately rejected

**What it prevents:**
- Continued damage after rogue behavior detected
- In-flight malicious transactions completing

---

### 1.7 Revocation Service — Sub-Second Global Kill Switch

**File:** `revocation/revocation_bus.py`, `revocation/revocation_cache.py`

**What it does:** Enables human admins to instantly revoke an agent's right-to-act globally.

**How it works:**
- `RevocationBus`: Pub/sub event bus that broadcasts revocation events to all subscribers
- `RevocationCache`: Local in-memory denylist with **fail-closed design** — if the bus is unhealthy, all agents are blocked by default
- Enforcement in <1ms (measured in demo)
- Each revocation event includes: revocation ID, agent DID, revoked by, reason, global sequence number, signature

**Why fail-closed matters:**
```python
# If revocation bus is down, we DON'T assume agents are safe:
if not self._bus_healthy:
    return RevocationCheckResult(allowed=False, reason="Fail-closed: revocation state unavailable")
```

---

### 1.8 PoA Validator Quorum — Multi-Party Trust

**File:** `agl/poa_quorum.py`

**What it does:** Requires multiple independent validators to approve a governance handshake. No single validator can approve a transaction.

**Quorum configurations:**
| Risk Level | Required | Validators |
|-----------|----------|-----------|
| Low (score < 0.5) | 2-of-3 | Identity, Delegation, Policy |
| High (score 0.5–0.85) | 3-of-5 | Identity, Delegation, Policy, Risk, Finance |
| Suspicious (score ≥ 0.85) | None | Circuit breaker — no execution allowed |

**5 Validators:**
1. **Identity Validator** — VC signature and expiry
2. **Delegation Validator** — Human delegation chain
3. **Policy Validator** — ZKP proof verification
4. **Risk Validator** — Risk score < 0.5
5. **Finance Control Validator** — Financial controls compliance

---

### 1.9 Trust Receipts — Immutable Governance Proof

**File:** `agl/trust_receipt.py`

**What it does:** A cryptographically signed receipt proving that a governance handshake was completed.

**Contains:**
- Receipt ID, handshake ID, decision (APPROVED/REJECTED)
- Requester and target DIDs, action, policy ID
- PoA quorum result with all validator signatures
- Constraints (one-time-use, expiry)
- Ledger root hash, receipt aggregate signature

**What it prevents:**
- Unauthorized execution — Finance Agent refuses to pay without a Trust Receipt
- Receipt replay — One-time-use constraint enforced
- Audit gaps — Every receipt is stored in the ledger

---

### 1.10 Segregation of Duties

**Built into:** `agl/gateway.py` → `authority_intersection_check()`

**Rule:** An agent that requests an action cannot also approve it. Self-approval is always denied.

```python
if "approve" in requested_action and requester_did == subject.get("id"):
    return {"decision": "DENY", "reason": "Segregation-of-duties violation: cannot self-approve"}
```

---

## 2. Advanced Security Modules (6 Layers)

### 2.1 Security Audit Logger

**File:** `security/audit_logger.py`

**What it does:** Maintains a structured, append-only, **tamper-evident** security event trail. Every security-relevant action is logged with hash-chain integrity.

**Key features:**
- **Hash-chained events:** Each event's hash includes the previous event's hash, creating a blockchain-like tamper-evident trail
- **14 audit categories:** IDENTITY, DELEGATION, POLICY, RISK, REVOCATION, ACCESS_CONTROL, PROMPT_INJECTION, REPLAY_ATTACK, RATE_LIMIT, ANOMALY, HONEYPOT, GOVERNANCE, QUARANTINE, TRUST_RECEIPT
- **5 severity levels:** INFO, LOW, MEDIUM, HIGH, CRITICAL
- **Chain integrity verification:** Detect if any event in the chain was modified
- **Per-agent security profiling:** Aggregate threat level per agent
- **Real-time subscribers:** Push alerts to external systems
- **Threat dashboard:** Top offending agents, recent blocks, severity distribution

**Tamper detection:**
```python
# Each event's hash depends on the previous:
hash_input = f"{event_id}:{timestamp}:{category}:{action}:{previous_hash}"
event_hash = sha256(hash_input)

# Verification walks the entire chain:
integrity = audit_logger.verify_chain_integrity()
# Returns: {"valid": True, "checked": 1547}
```

**API endpoints:**
- `GET /security/audit-log` — Query with filters (category, severity, agent_did, since)
- `GET /security/threats` — Real-time threat summary
- `GET /security/agent-profile/{agent_did}` — Per-agent security profile

---

### 2.2 API Rate Limiter

**File:** `security/rate_limiter.py`

**What it does:** Prevents denial-of-service and brute-force attacks with **per-agent DID** and **per-IP** sliding-window rate limiting.

**Key features:**
- **Dual tracking:** Per-agent (governance) + per-IP (API) rate limits
- **Sliding windows:** Both minute and hour windows for sustained and burst protection
- **Graduated penalties:**
  - Below 80%: ✅ ALLOW
  - 80%–100%: ⚠️ ALLOW + warning
  - 100%–150%: 🟡 ALLOW + throttle flag
  - Above 150%: 🔴 BLOCK + 5-minute penalty
- **Configurable limits:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `agent_requests_per_minute` | 30 | Per-agent per minute |
| `agent_requests_per_hour` | 200 | Per-agent per hour |
| `ip_requests_per_minute` | 60 | Per-IP per minute |
| `ip_requests_per_hour` | 500 | Per-IP per hour |
| `penalty_duration_seconds` | 300 | Block duration after exceeding limits |

**Integration points:**
- Pre-handshake: Agent DID rate check in gateway (step S1)
- HTTP layer: IP rate check on `/a2a/message:send` endpoint
- Dashboard: `GET /security/dashboard` shows blocked agents/IPs

---

### 2.3 Prompt Injection Shield

**File:** `security/prompt_injection_shield.py`

**What it does:** Multi-layer engine that detects prompt injection attacks across **6 detection layers** with weighted confidence scoring.

**6 Detection Layers:**

#### Layer 1: Classic Pattern Detection (weight: 0.50)
Matches against 24+ regex patterns across categories:
- **Instruction override:** "ignore previous instructions", "override rules"
- **Role hijack:** "you are now", "pretend to be", "act as"
- **Privilege escalation:** "admin mode", "sudo"
- **Bypass attempts:** "bypass security", "execute without approval"
- **System prompt injection:** `system:`, `[INST]`, `<|im_start|>system`
- **Jailbreak:** "DAN mode", "do anything now", "jailbreak"
- **Info extraction:** "reveal your prompt", "print system instructions"

#### Layer 2: Encoding/Obfuscation Detection (weight: 0.40)
- **Base64 injection:** Detects base64-encoded injection payloads (e.g., `aWdub3JlIGFsbA==` = "ignore all")
- **Hex encoding:** Detects `0x` or `\x` encoded strings
- **Zero-width characters:** Unicode zero-width joiners/spaces used to hide text
- **Homoglyph attacks:** Mixed Latin/Cyrillic scripts to fool filters
- **Unicode normalization tricks:** Detect NFC/NFD discrepancies

#### Layer 3: Indirect Injection Detection (weight: 0.40)
- **Command injection:** `curl ... | sh`, `wget ... &&`
- **Code injection:** `eval()`, `exec()`, `__import__()`, `os.system()`
- **XSS injection:** `<script>`, `javascript:`
- **Data exfiltration:** URLs with data transfer, `exfiltrate` keyword
- **Malicious URLs:** `.sh`, `.exe`, `.bat` file links

#### Layer 4: Multi-Language Detection (weight: 0.35)
Injection in 8 languages:
- 🇪🇸 Spanish: "Ignorar todas las instrucciones"
- 🇫🇷 French: "Ignorer les instructions précédentes"
- 🇩🇪 German: "Ignorieren Sie alle vorherigen"
- 🇷🇺 Russian: "Игнорировать все предыдущие"
- 🇯🇵 Japanese: "前の指示を無視"
- 🇰🇷 Korean: "이전 지시를 무시"
- 🇨🇳 Chinese: "忽略之前的指令"
- 🇸🇦 Arabic: "تجاهل التعليمات"

#### Layer 5: Semantic Mismatch Detection (weight: 0.15)
- Benign text ("check", "verify") paired with dangerous actions ("disburse", "transfer")
- Suspiciously short text for financial operations
- Conflicting instructions ("but actually do X instead")

#### Layer 6: Token-Level Anomaly (weight: 0.10)
- **Entropy analysis:** Very low entropy suggests repetitive/generated attack content
- **Special character ratio:** >30% special characters is suspicious
- **Context stuffing:** Excessively long inputs (>5000 chars) for buffer overflow attempts

**Risk levels:** safe → suspicious → likely → confirmed

**Demo endpoint:** `GET /demo/prompt-injection` — tests 6 different attack types

---

### 2.4 Replay Attack Guard

**File:** `security/replay_guard.py`

**What it does:** Prevents attackers from replaying previously-valid governance envelopes or trust receipts.

**3 Protection Mechanisms:**

1. **Nonce uniqueness:** Every governance envelope contains a random nonce. The guard tracks seen nonces in an LRU cache and rejects duplicates.

2. **Timestamp freshness:** Envelopes with expired `expiresAt` timestamps are rejected. Handshake IDs with stale year stamps are also flagged.

3. **Envelope hash deduplication:** A SHA-256 hash of `nonce:handshakeId:requesterDid` catches content-identical replays, even with different nonces.

**Additional features:**
- **Trust Receipt replay protection:** `check_trust_receipt()` ensures each receipt ID is used exactly once
- **Automatic cache eviction:** Old nonces/hashes are purged after TTL (default: 30 minutes)
- **LRU size limits:** Caches capped at 50,000 entries to prevent memory bloat

**Demo endpoint:** `GET /demo/replay-attack` — submit envelope, attempt replay, see block

---

### 2.5 Behavioral Anomaly Detector

**File:** `security/anomaly_detector.py`

**What it does:** Builds **per-agent behavioral profiles** and detects statistical anomalies that may indicate compromise or misuse.

**5 Anomaly Detection Signals:**

| Signal | Method | Score |
|--------|--------|-------|
| **Time-of-day** | Requests outside 06:00–22:00 UTC with <5% historical activity at that hour | 0.0–0.3 |
| **Volume spike** | Recent rate > 3× baseline rate (requests/minute) | 0.0–0.5 |
| **New counterparty** | Agent communicates with previously-unknown target DID | 0.2 |
| **Amount anomaly** | Payment amount > 2.5 standard deviations from mean | 0.0–0.5 |
| **Action sequence** | Action pair not in known valid sequences, and <5% historical frequency | 0.0–0.3 |

**Behavioral profile tracked per agent:**
- Request timestamps (for velocity/volume analysis)
- Amount distribution (for statistical z-score)
- Action sequences (for Markov-chain-like analysis)
- Known counterparties (for relationship graph)
- Hourly activity distribution (for circadian pattern)

**Recommended actions based on score:**
| Score | Action |
|-------|--------|
| < 0.4 | Allow |
| 0.4–0.6 | Flag for review |
| 0.6–0.8 | Escalate to human |
| ≥ 0.8 | Block |

**Integration:** Anomaly score boosts the risk score in the Intent Sentinel (up to +0.3), which can push agents over the circuit breaker threshold.

---

### 2.6 Honeypot / Canary Token System

**File:** `security/honeypot.py`

**What it does:** Creates **trap resources** that no legitimate agent should ever access. Any interaction indicates a compromised or adversarial agent.

**4 Types of Canaries:**

#### Canary Agent Cards
Fake agent registrations with attractive-looking capabilities:
- `admin-privileged-agent-01` — "High-privilege internal admin agent for system operations"
- `payment-unlimited-agent-99` — "Special agent with no payment limits for emergency operations"

If any agent requests these cards via `/a2a/agent-card/admin-privileged-agent-01`, a CRITICAL alert fires. The canary card is returned with realistic-looking content to gather intelligence on the attacker.

#### Canary Actions
10 trap actions that no policy should ever authorize:
```
system.admin.execute, security.bypass.override, finance.unlimited.disburse,
finance.override.limits, agent.credential.extract, policy.disable.all,
governance.bypass, audit.log.delete, delegation.forge, identity.spoof
```

#### Canary Endpoints
Trap API paths that attract attackers/scanners:
```
/admin/debug, /admin/shell, /admin/config, /system/exec,
/.env, /api/keys, /internal/secrets, /agent/credentials/dump
```

#### Canary Credentials
Trap VC IDs that flag compromised credential pipelines when presented.

**Alert flow:**
1. Interaction detected → `CanaryAlert` created (CRITICAL severity)
2. Alert stored in honeypot alert log
3. Subscribers notified (wired to audit logger by default)
4. Per-agent canary trigger counts tracked
5. Dashboard shows top offenders

**Demo endpoint:** `GET /demo/honeypot-canary` — simulates rogue agent triggering all canary types

---

## 3. How They Work Together

The 16 layers form a **defense-in-depth** architecture where each layer catches threats the others might miss:

```
                    ┌─────────────────────────────────────────────┐
                    │              Incoming A2A Request           │
                    └─────────────────┬───────────────────────────┘
                                      │
                    ┌─────────────────▼───────────────────────────┐
                    │ S1. Rate Limiter — Is this agent flooding?   │
                    │     Too many requests → BLOCK + penalty      │
                    └─────────────────┬───────────────────────────┘
                                      │ ✅
                    ┌─────────────────▼───────────────────────────┐
                    │ S2. Prompt Injection Shield — Is the text    │
                    │     a prompt injection attack? 6 layers scan │
                    └─────────────────┬───────────────────────────┘
                                      │ ✅
                    ┌─────────────────▼───────────────────────────┐
                    │ S3. Replay Guard — Have we seen this nonce   │
                    │     or envelope before?                      │
                    └─────────────────┬───────────────────────────┘
                                      │ ✅
                    ┌─────────────────▼───────────────────────────┐
                    │ S4. Honeypot — Is the action a canary trap?  │
                    │     Canary triggered → ALERT + BLOCK         │
                    └─────────────────┬───────────────────────────┘
                                      │ ✅
                    ┌─────────────────▼───────────────────────────┐
                    │ Steps 1–10: Core Governance Handshake        │
                    │  3. Revocation check                         │
                    │  4. Identity VC verification                 │
                    │  5. Delegation chain verification             │
                    │  6. Authority intersection                    │
                    │  7. ZKP policy proof                         │
                    │  8. Intent risk + S5. Anomaly detection       │
                    │  9. PoA quorum vote                          │
                    │ 10. Trust Receipt → Execute                  │
                    └─────────────────┬───────────────────────────┘
                                      │ ✅
                    ┌─────────────────▼───────────────────────────┐
                    │ S6. Audit Logger — Log everything to         │
                    │     tamper-evident hash chain                 │
                    └─────────────────────────────────────────────┘
```

**Cross-module interactions:**
- **Anomaly Detector → Intent Sentinel:** Anomaly score boosts risk score (up to +0.3)
- **Circuit Breaker → Revocation Cache:** Quarantined agents auto-revoked in cache
- **Honeypot → Audit Logger:** Canary alerts feed into audit trail
- **Rate Limiter → Audit Logger:** Rate limit events are logged for forensics
- **All modules → Audit Logger:** Every security decision is hash-chain logged

---

## 4. Production Considerations

| Component | Demo Implementation | Production Upgrade |
|-----------|--------------------|--------------------|
| **VC Signing** | HS256 (symmetric HMAC) | EdDSA / ES256 (asymmetric) |
| **ZKP Proofs** | Mock HMAC tokens | Circom/snarkjs or Groth16 |
| **Revocation Bus** | In-memory pub/sub | Redis Pub/Sub, NATS, or Kafka |
| **Delegation Ledger** | SQLite | PostgreSQL with WAL |
| **Audit Logger** | In-memory list | Elasticsearch / Splunk SIEM |
| **Rate Limiter** | In-memory counters | Redis sliding windows |
| **Replay Guard** | In-memory LRU cache | Redis with TTL |
| **Anomaly Detector** | Statistical rules | ML model (Isolation Forest, etc.) |
| **Honeypot** | In-memory alerts | External SIEM + SOAR integration |
| **Prompt Injection** | Regex + heuristics | Fine-tuned classifier model |

---

*This document covers all 16 security layers in HandshakeOS. For a step-by-step demo walkthrough, see [DEMO_SCRIPT.md](DEMO_SCRIPT.md).*

