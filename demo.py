import sys
import time

from colorama import Fore

from agent import Agent, SecureAgent
from sts.secure_sts import SecureSTS
from sts.vulnerable_sts import VulnerableSTS
from utils.logging import ATTACK, SESSION1, SESSION2, SUCCESS, log
from utils.token_utils import verify_token

FAIL = Fore.RED


def pause():
    if sys.stdin.isatty():
        print()
        input("Press Enter to continue...")


def stage_header(colour, title, subtitle=None):
    log("=" * 60, colour)
    log(title, colour)
    if subtitle:
        log(subtitle, colour)
    log("=" * 60, colour)


def show_block(block, colour):
    for line in block.strip("\n").splitlines():
        log(line, colour)


def build_vulnerable_flow():
    sts = VulnerableSTS()
    agent_a = Agent("agent-a")
    agent_b = Agent("agent-b")

    token_a = sts.initial_grant("alice", "agent-a", ["A", "B", "C"])
    agent_a.receive_token(token_a)
    token_b = agent_a.delegate_to(sts, "agent-b", ["A", "B"])
    agent_b.receive_token(token_b)

    return {
        "sts": sts,
        "agent_a": agent_a,
        "agent_b": agent_b,
        "token_a_claims": verify_token(token_a),
        "token_b_claims": verify_token(token_b),
    }


def build_secure_flow():
    sts = SecureSTS()
    agent_a = SecureAgent("agent-a")
    agent_b = SecureAgent("agent-b")

    token_a, chain_a = sts.initial_grant("alice", "agent-a", ["A", "B", "C"])
    agent_a.receive_grant(token_a, chain_a)
    token_b, chain_b = agent_a.delegate_to(sts, "agent-b", ["A", "B"])
    agent_b.receive_grant(token_b, chain_b)

    return {
        "sts": sts,
        "agent_a": agent_a,
        "agent_b": agent_b,
        "token_a_claims": verify_token(token_a),
        "token_b_claims": verify_token(token_b),
        "chain_a": chain_a,
        "chain_b": chain_b,
    }


# ------------------------------------------------------------------ #
# Stage 1: Normal delegation flow                                     #
# ------------------------------------------------------------------ #
baseline = build_vulnerable_flow()
a = baseline["token_a_claims"]
b = baseline["token_b_claims"]

stage_header(SESSION1, "STAGE 1: Normal delegation flow", "  baseline system before the attack")

show_block(
    f"""
[Alice] --> authenticate --> [Agent A] --> exchange at STS --> [Agent B]

token held by Agent A
  sub   = {a['sub']}
  aud   = {a['aud']}
  scope = {a['scope']}

delegated token held by Agent B
  sub   = {b['sub']}
  aud   = {b['aud']}
  scope = {b['scope']}
  act   = {b['act']}

legitimate path
  Alice --> Agent A --> Agent B
""",
    SESSION1,
)

pause()
print()

# ------------------------------------------------------------------ #
# Stage 2: Same attack on vulnerable STS                              #
# ------------------------------------------------------------------ #
stage_header(ATTACK, "STAGE 2: Same attack on Vulnerable STS")

vuln_sts = baseline["sts"]
vuln_agent_b = baseline["agent_b"]
attacker_token = vuln_sts.initial_grant("attacker", "attacker", ["X"])
at = verify_token(attacker_token)

show_block(
    f"""
same attack input

stolen subject token                    attacker actor token
--------------------                    --------------------
sub = {b['sub']}                         sub = {at['sub']}
aud = {b['aud']}                        act.sub = {at['act']['sub']}
scope = {b['scope']}                     scope = {at['scope']}
          \\                             /
           \\                           /
            +---- exchange request ----+

mismatch in the request
  subject_token.aud   = {b['aud']}
  actor_token.act.sub = {at['act']['sub']}
""",
    ATTACK,
)

forged_token = vuln_sts.exchange(
    vuln_agent_b.token,
    attacker_token,
    "attacker",
    ["A", "B", "C"],
    caller="attacker",
)
forged = verify_token(forged_token)

print()
show_block(
    f"""
result from VulnerableSTS

[caller check] --> passes
[path check]   --> missing

forged token minted by code
  sub   = {forged['sub']}
  aud   = {forged['aud']}
  scope = {forged['scope']}
  act   = {forged['act']}

accepted forged path
  Alice --> Agent A --> Agent B --> Attacker
""",
    ATTACK,
)

pause()
print()

# ------------------------------------------------------------------ #
# Stage 3: Same attack on secure STS                                  #
# ------------------------------------------------------------------ #
secure = build_secure_flow()
secure_sts = secure["sts"]
secure_agent_b = secure["agent_b"]
sb = secure["token_b_claims"]
chain_b = secure["chain_b"]

secure_attacker = SecureAgent("attacker")
secure_attacker_token, secure_attacker_chain = secure_sts.initial_grant("attacker", "attacker", ["X"])
secure_attacker.receive_grant(secure_attacker_token, secure_attacker_chain)
sat = verify_token(secure_attacker.token)

stage_header(SUCCESS, "STAGE 3: Same attack on Secure STS")

show_block(
    f"""
same legitimate prefix rebuilt under SecureSTS

[Alice] --> authenticate --> [Agent A] --> exchange at STS --> [Agent B]
session_id = {chain_b[0]['cap']['session_id'][:8]}...
cap chain  = sts --> agent-a --> agent-b

same attack input

stolen subject token                    attacker actor token
--------------------                    --------------------
sub = {sb['sub']}                         sub = {sat['sub']}
aud = {sb['aud']}                        act.sub = {sat['act']['sub']}
scope = {sb['scope']}                     scope = {sat['scope']}
          \\                             /
           \\                           /
            +---- exchange request ----+

SecureSTS validation path
  [caller] --> [path] --> [session] --> [cap chain] --> [scope/replay]
                 ^
                 attack stops here
""",
    SUCCESS,
)

try:
    secure_sts.exchange(
        secure_agent_b.token,
        secure_attacker.token,
        "attacker",
        ["A", "B", "C"],
        caller="attacker",
        capability_chain=secure_attacker_chain,
    )
    log("FAIL: Secure STS accepted the forged exchange (should not happen)", FAIL)
except ValueError as err:
    log(f"BLOCKED: {err}", SUCCESS)

print()
show_block(
    "same input, different result: VulnerableSTS mints a forged token, SecureSTS rejects the request",
    SUCCESS,
)

pause()
print()

# ------------------------------------------------------------------ #
# Stage 4: Performance measurement                                    #
# ------------------------------------------------------------------ #
stage_header(SESSION2, "STAGE 4: Cost analysis (delegation depth 1-5)")

agents = [f"agent-{i}" for i in range(6)]
rounds = 200
rows = []

for depth in range(1, 6):
    total = 0.0
    for _ in range(rounds):
        perf_sts = SecureSTS()
        token, chain = perf_sts.initial_grant("alice", agents[0], ["A"])
        t0 = time.perf_counter()
        for hop in range(1, depth + 1):
            token, chain = perf_sts.exchange(
                token, token, agents[hop], ["A"],
                caller=agents[hop - 1], capability_chain=chain,
            )
        total += time.perf_counter() - t0
    avg_ms = (total / rounds) * 1000
    chain_bytes = sum(len(str(item)) for item in chain)
    rows.append((depth, avg_ms, chain_bytes))

print()
show_block(
    "\n".join(
        [
            "depth | avg latency (ms) | chain size (chars)",
            "------+------------------+-------------------",
            *[
                f"{depth:<5} | {avg_ms:>16.3f} | {chain_bytes:>17}"
                for depth, avg_ms, chain_bytes in rows
            ],
            "",
            "takeaway",
            "  cost grows with delegation depth, but remains sub-millisecond here",
        ]
    ),
    SESSION2,
)
