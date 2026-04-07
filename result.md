# CS5321 Project Results: Session-Bound Capability Chain Defence

## 1. Vulnerability Overview

RFC 8693 (OAuth 2.0 Token Exchange) does not mandate that a Security Token Service (STS) verify the full delegation path when processing a token exchange request. The vulnerable STS only checks that the caller matches the actor field in the presented token:

```python
# vulnerable_sts.py — the only check performed
if caller != act_claims["act"]["sub"]:
    raise ValueError(...)
# subject_token.aud vs actor_token.act.sub is never verified
```

This omission allows a **cross-session token splicing attack**: an attacker who obtains a stolen token can pair it with their own legitimately-issued token, forge a delegation path that never existed, and receive a new token with escalated scope.

A valid delegation must satisfy:

```
subject_token.aud == actor_token.act.sub
```

The vulnerable implementation ignores this invariant entirely.

---

## 2. Vulnerable Demo Output

```
[+] Legitimate chain: Alice authorises Agent A, Agent A delegates to Agent B
[+] STS issues token: sub = alice, aud = agent-a, scope = ['A', 'B', 'C']
[+] Agent A delegates to Agent B: sub = alice, aud = agent-b, scope = ['A', 'B']
[+] Legitimate act chain: {'sub': 'agent-b', 'act': {'sub': 'agent-a'}}

[+] Attacker steals agent_b.token and splices it with their own token:
[+]   subject_token = agent_b.token: aud = agent-b
[+]   actor_token   = attacker_token: act.sub = attacker
[+]   aud/sub mismatch: agent-b != attacker, STS does not check path integrity

[+] Vulnerable STS issued token, forged delegation path accepted
[+]   sub   = alice
[+]   aud   = attacker
[+]   scope = ['A', 'B', 'C'], scope escalated, agent-b only had ['A', 'B']
[+]   act chain: {'sub': 'attacker', 'act': {'sub': 'attacker'}}
[+]   path Alice -> Agent A -> Agent B -> Attacker never existed
```

**What happened:** The attacker obtained their own token via `initial_grant`, then presented `agent_b.token` (stolen) as the `subject_token` and their own token as the `actor_token`. The STS validated each token individually, but because it never checked whether `agent_b.token.aud` matched `attacker_token.act.sub`, it issued a token on behalf of Alice to the attacker — with scope `['A', 'B', 'C']`, wider than the `['A', 'B']` that Agent B was ever authorised to hold.

---

## 3. Defence: Session-Bound Capability Chain

The defence operates at two layers.

### 3.1 Layer 1 — Path Integrity Check (Direct Fix)

A single additional check in `exchange()` closes the core vulnerability:

```python
# secure_sts.py:47
if sub_claims["aud"] != act_claims["act"]["sub"]:
    raise ValueError("Path integrity check failed: ...")
```

This enforces that the token being presented was actually issued to the agent presenting it. An attacker holding a stolen token whose `aud` does not match their own `act.sub` is rejected immediately.

### 3.2 Layer 2 — Capability Chain (Cryptographic Path History)

Path integrity alone is insufficient if the attacker is already a participant in some delegation chain. The capability chain provides an unforgeable, signed record of every delegation hop from the original grant onward.

#### Token Structure

Each token now carries a `session_id` generated at `initial_grant` time:

```json
{
  "sub": "alice",
  "aud": "agent-b",
  "act": { "sub": "agent-b", "act": { "sub": "agent-a" } },
  "scope": ["read:orders"],
  "session_id": "4a6388aa..."
}
```

#### Capability Structure

Alongside each token, the STS issues a signed capability:

```json
{
  "cap": {
    "session_id": "4a6388aa...",
    "hop":        1,
    "from":       "agent-a",
    "to":         "agent-b",
    "scope":      ["read:orders"],
    "issued_at":  1748000000,
    "expires_at": 1748003600,
    "nonce":      "0083ab8d..."
  },
  "sig": "<HMAC-SHA256 over cap, keyed with STS secret>"
}
```

Capabilities accumulate into a chain. At each subsequent exchange the requesting agent must present the full chain so far.

#### Validation Steps in `_validate_chain()` (`secure_sts.py:109`)

| Step | Check | Attack Blocked |
|------|-------|----------------|
| 1 | HMAC-SHA256 signature on every capability | Forgery / tampering of any cap |
| 2 | `expires_at > now` | Use of expired capabilities |
| 3 | `session_id` matches the token's `session_id` on every cap | Cross-session splicing |
| 4 | `cap.hop == index` (contiguous 0, 1, 2 …) | Removal of intermediate hops |
| 5 | `chain[i-1].to == chain[i].from` | Insertion of unauthorised nodes |
| 6 | Nonce of the last capability not in `_used_nonces` | Replay of the same request |

#### Scope Enforcement (`secure_sts.py:63`)

```python
if not set(new_scopes).issubset(last_scope):
    raise ValueError("Scope expansion not allowed: ...")
```

Each hop may only request a subset of the scopes granted at the previous hop. Scope can never grow across a delegation step.

#### Why Capabilities Cannot be Forged

The STS returns each capability **only to the agent that performed the exchange**. An attacker who was never part of the delegation flow never receives any capability for that session. Without a valid, STS-signed capability for every hop in the chain, the exchange is rejected. This mirrors the SIFF protocol's defence against IP spoofing: the SYN-ACK is delivered only to the true address holder, so a spoofer cannot complete the handshake.

---

## 4. Secure Demo Output

### Stage 1 — Legitimate Delegation Chain

```
[+] STAGE 1: Legitimate delegation chain
[+]   Alice -> Agent A -> Agent B
[+] STS issues token to agent-a: sub=alice, aud=agent-a, scope=['read:orders', 'write:orders']
[+]   capability hop-0: session_id=4a6388aa..., from=sts, to=agent-a
[+] Agent A delegates to agent-b: sub=alice, aud=agent-b, scope=['read:orders']
[+]   act chain: {'sub': 'agent-b', 'act': {'sub': 'agent-a'}}
[+]   capability chain depth: 2 hops
[+]     hop 0: sts -> agent-a, scope=['read:orders', 'write:orders'], nonce=694c8af3...
[+]     hop 1: agent-a -> agent-b, scope=['read:orders'], nonce=0083ab8d...
```

### Stage 2 — Attack Demonstrations (All Blocked)

```
[+] Attack 2a: Token splicing — no capability chain
[+]   Attacker steals agent_b.token (aud=agent-b) and presents own token as actor
[+]   subject_token.aud='agent-b' != actor_token.act.sub='attacker'
[+] BLOCKED: Path integrity check failed: subject_token.aud='agent-b' != actor_token.act.sub='attacker'

[+] Attack 2b: Replay — reusing agent_b's capability chain
[+]   Attacker replays chain_b (already consumed nonces)
[+] BLOCKED: Replayed nonce detected at hop 1

[+] Attack 2c: Scope escalation — requesting write:orders after only read:orders was granted
[+] BLOCKED: Scope expansion not allowed: requested ['read:orders', 'write:orders'] but last hop only grants ['read:orders']

[+] Attack 2d: Tampered capability — attacker modifies session_id in chain
[+] BLOCKED: Invalid capability signature
```

---

## 5. Test Results

17 unit tests across 6 categories, all passing.

```
tests/test_secure_sts.py::TestLegitimateFlow::test_initial_grant_returns_token_and_one_cap  PASSED
tests/test_secure_sts.py::TestLegitimateFlow::test_session_id_propagates                    PASSED
tests/test_secure_sts.py::TestLegitimateFlow::test_chain_depth_and_hop_numbers              PASSED
tests/test_secure_sts.py::TestLegitimateFlow::test_scope_narrows_correctly                  PASSED
tests/test_secure_sts.py::TestLegitimateFlow::test_act_chain_grows                          PASSED
tests/test_secure_sts.py::TestPathIntegrity::test_token_splicing_blocked                    PASSED
tests/test_secure_sts.py::TestPathIntegrity::test_wrong_session_id_blocked                  PASSED
tests/test_secure_sts.py::TestPathIntegrity::test_missing_session_id_in_token_blocked       PASSED
tests/test_secure_sts.py::TestReplayPrevention::test_replayed_nonce_blocked                 PASSED
tests/test_secure_sts.py::TestChainTampering::test_tampered_signature_blocked               PASSED
tests/test_secure_sts.py::TestChainTampering::test_tampered_session_id_blocked              PASSED
tests/test_secure_sts.py::TestChainTampering::test_non_contiguous_hops_blocked              PASSED
tests/test_secure_sts.py::TestChainTampering::test_path_break_blocked                       PASSED
tests/test_secure_sts.py::TestChainTampering::test_empty_chain_blocked                      PASSED
tests/test_secure_sts.py::TestScopeEnforcement::test_scope_escalation_blocked               PASSED
tests/test_secure_sts.py::TestScopeEnforcement::test_subset_scope_allowed                   PASSED
tests/test_secure_sts.py::TestVulnerableBaseline::test_splicing_succeeds_on_vulnerable_sts  PASSED

17 passed in 1.09s
```

| Category | Tests | Coverage |
|----------|-------|----------|
| Legitimate flow | 5 | Token fields, session propagation, act chain, scope narrowing, chain depth |
| Path integrity | 3 | Token splicing, wrong session, missing session_id |
| Replay prevention | 1 | Nonce reuse |
| Chain tampering | 4 | Forged signature, tampered session_id, non-contiguous hops, path break |
| Scope enforcement | 2 | Escalation blocked, subset allowed |
| Vulnerable baseline | 1 | Confirms the vulnerable STS is still exploitable |

---

## 6. Performance Overhead

Measured over 200 rounds per depth on a local machine (Python 3.13, macOS).

```
depth=1: avg exchange latency=0.057 ms, chain size ~600  chars
depth=2: avg exchange latency=0.127 ms, chain size ~902  chars
depth=3: avg exchange latency=0.201 ms, chain size ~1204 chars
depth=4: avg exchange latency=0.281 ms, chain size ~1506 chars
depth=5: avg exchange latency=0.391 ms, chain size ~1808 chars
```

Both latency and chain size grow linearly with delegation depth (~0.07 ms and ~302 chars per additional hop). Typical OAuth delegation chains are 2–4 hops deep, placing end-to-end validation overhead well under 0.4 ms per exchange. For applications where chain size is a concern, the chain can be compressed into a hash accumulator, reducing it to a fixed-size commitment regardless of depth.

---

## 7. Summary

| Property | Vulnerable STS | Secure STS |
|----------|---------------|------------|
| Caller identity check | Yes | Yes |
| Path integrity (`aud == act.sub`) | **No** | Yes |
| Session binding | **No** | Yes |
| Cryptographic path history | **No** | Yes (capability chain) |
| Replay prevention | **No** | Yes (nonce) |
| Scope enforcement | **No** | Yes (subset-only) |
| Token splicing attack | **Succeeds** | Blocked |
| Scope escalation attack | **Succeeds** | Blocked |
| Capability forgery | N/A | Blocked |
| Replay attack | N/A | Blocked |
