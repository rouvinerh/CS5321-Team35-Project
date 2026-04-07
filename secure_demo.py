import time
from sts.secure_sts import SecureSTS
from agent import SecureAgent
from utils.token_utils import verify_token
from utils.logging import log, SESSION1, SESSION2, ATTACK, SUCCESS, RESET
from colorama import Fore

FAIL = Fore.RED

sts = SecureSTS()

# ------------------------------------------------------------------ #
# Stage 1: Legitimate delegation chain                                #
# ------------------------------------------------------------------ #
log("=" * 60, SESSION1)
log("STAGE 1: Legitimate delegation chain", SESSION1)
log("  Alice -> Agent A -> Agent B", SESSION1)
log("=" * 60, SESSION1)

agent_a = SecureAgent("agent-a")
agent_b = SecureAgent("agent-b")

token_a, chain_a = sts.initial_grant("alice", "agent-a", ["read:orders", "write:orders"])
agent_a.receive_grant(token_a, chain_a)

a = verify_token(agent_a.token)
log(f"STS issues token to agent-a: sub={a['sub']}, aud={a['aud']}, scope={a['scope']}", SESSION1)
log(f"  capability hop-0: session_id={chain_a[0]['cap']['session_id'][:8]}..., "
    f"from={chain_a[0]['cap']['from']}, to={chain_a[0]['cap']['to']}", SESSION1)

token_b, chain_b = agent_a.delegate_to(sts, "agent-b", ["read:orders"])
agent_b.receive_grant(token_b, chain_b)

b = verify_token(agent_b.token)
log(f"Agent A delegates to agent-b: sub={b['sub']}, aud={b['aud']}, scope={b['scope']}", SESSION1)
log(f"  act chain: {b['act']}", SESSION1)
log(f"  capability chain depth: {len(chain_b)} hops", SESSION1)
for i, item in enumerate(chain_b):
    c = item["cap"]
    log(f"    hop {c['hop']}: {c['from']} -> {c['to']}, scope={c['scope']}, "
        f"nonce={c['nonce'][:8]}...", SESSION1)

print()

# ------------------------------------------------------------------ #
# Stage 2: Attack attempts                                            #
# ------------------------------------------------------------------ #
log("=" * 60, ATTACK)
log("STAGE 2: Attack demonstrations", ATTACK)
log("=" * 60, ATTACK)

attacker = SecureAgent("attacker")
att_token, att_chain = sts.initial_grant("attacker", "attacker", ["read:orders", "write:orders"])
attacker.receive_grant(att_token, att_chain)
at = verify_token(attacker.token)

# -- Attack 2a: Token splicing without capability chain ------------ #
print()
log("Attack 2a: Token splicing — no capability chain", ATTACK)
log(f"  Attacker steals agent_b.token (aud={b['aud']}) and presents own token as actor", ATTACK)
log(f"  subject_token.aud='{b['aud']}' != actor_token.act.sub='{at['act']['sub']}'", ATTACK)

try:
    sts.exchange(
        agent_b.token,
        attacker.token,
        "attacker",
        ["read:orders", "write:orders"],
        caller="attacker",
        capability_chain=att_chain,  # attacker's own chain — wrong session
    )
    log("FAIL: STS accepted the forged exchange (should not happen)", FAIL)
except ValueError as e:
    log(f"BLOCKED: {e}", SUCCESS)

# -- Attack 2b: Replay a captured capability chain ----------------- #
print()
log("Attack 2b: Replay — reusing agent_b's capability chain", ATTACK)
log("  Attacker replays chain_b (already consumed nonces)", ATTACK)

# Simulate consuming chain_b nonces by performing a legitimate op first
try:
    # Force nonces in chain_b to be consumed
    sts._used_nonces.update(
        item["cap"]["nonce"] for item in chain_b if item["cap"].get("nonce")
    )
    sts.exchange(
        agent_b.token,
        agent_b.token,
        "agent-c",
        ["read:orders"],
        caller="agent-b",
        capability_chain=chain_b,
    )
    log("FAIL: STS accepted the replayed chain (should not happen)", FAIL)
except ValueError as e:
    log(f"BLOCKED: {e}", SUCCESS)

# -- Attack 2c: Scope escalation ----------------------------------- #
print()
log("Attack 2c: Scope escalation — requesting write:orders after only read:orders was granted", ATTACK)

agent_c = SecureAgent("agent-c")
token_c, chain_c = sts.initial_grant("alice", "agent-c", ["read:orders"])
agent_c.receive_grant(token_c, chain_c)

agent_d = SecureAgent("agent-d")
try:
    token_d, chain_d = sts.exchange(
        agent_c.token,
        agent_c.token,
        "agent-d",
        ["read:orders", "write:orders"],  # escalation attempt
        caller="agent-c",
        capability_chain=chain_c,
    )
    log("FAIL: STS allowed scope escalation (should not happen)", FAIL)
except ValueError as e:
    log(f"BLOCKED: {e}", SUCCESS)

# -- Attack 2d: Tampered capability signature ---------------------- #
print()
log("Attack 2d: Tampered capability — attacker modifies session_id in chain", ATTACK)

import copy
tampered_chain = copy.deepcopy(att_chain)
tampered_chain[0]["cap"]["session_id"] = verify_token(agent_b.token)["session_id"]
# signature no longer matches

try:
    sts.exchange(
        agent_b.token,
        agent_b.token,
        "agent-e",
        ["read:orders"],
        caller="agent-b",
        capability_chain=tampered_chain,
    )
    log("FAIL: STS accepted tampered capability (should not happen)", FAIL)
except ValueError as e:
    log(f"BLOCKED: {e}", SUCCESS)

# ------------------------------------------------------------------ #
# Stage 3: Performance measurement                                    #
# ------------------------------------------------------------------ #
print()
log("=" * 60, SESSION2)
log("STAGE 3: Overhead measurement (delegation depth 1–5)", SESSION2)
log("=" * 60, SESSION2)

AGENTS = [f"agent-{i}" for i in range(6)]
ROUNDS = 200

for depth in range(1, 6):
    total = 0.0
    for _ in range(ROUNDS):
        perf_sts = SecureSTS()
        token, chain = perf_sts.initial_grant("alice", AGENTS[0], ["read:orders"])
        t0 = time.perf_counter()
        for hop in range(1, depth + 1):
            token, chain = perf_sts.exchange(
                token, token, AGENTS[hop], ["read:orders"],
                caller=AGENTS[hop - 1], capability_chain=chain,
            )
        total += time.perf_counter() - t0
    avg_ms = (total / ROUNDS) * 1000
    chain_bytes = sum(len(str(item)) for item in chain)
    log(f"  depth={depth}: avg exchange latency={avg_ms:.3f} ms, "
        f"chain size ~{chain_bytes} chars", SESSION2)
