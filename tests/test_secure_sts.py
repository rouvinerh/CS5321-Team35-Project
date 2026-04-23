import copy
import time
import pytest

from sts.secure_sts import SecureSTS
from sts.vulnerable_sts import VulnerableSTS
from agent import SecureAgent
from utils.token_utils import verify_token, sign_capability


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def build_chain(sts, depth=2):
    """Build a legitimate chain alice -> agent-0 -> ... -> agent-{depth}."""
    agents = [f"agent-{i}" for i in range(depth + 1)]
    token, chain = sts.initial_grant("alice", agents[0], ["read", "write"])
    for i in range(1, depth + 1):
        token, chain = sts.exchange(
            token, token, agents[i], ["read", "write"],
            caller=agents[i - 1], capability_chain=chain,
        )
    return token, chain, agents


# ================================================================== #
# 1. Happy path                                                        #
# ================================================================== #

class TestLegitimateFlow:
    def test_initial_grant_returns_token_and_one_cap(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])
        claims = verify_token(token)
        assert claims["sub"] == "alice"
        assert claims["aud"] == "agent-a"
        assert len(chain) == 1
        cap = chain[0]["cap"]
        assert cap["hop"] == 0
        assert cap["from"] == "sts"
        assert cap["to"] == "agent-a"

    def test_session_id_propagates(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])
        session_id = chain[0]["cap"]["session_id"]
        token2, chain2 = sts.exchange(
            token, token, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain,
        )
        claims2 = verify_token(token2)
        assert claims2["session_id"] == session_id
        assert chain2[1]["cap"]["session_id"] == session_id

    def test_chain_depth_and_hop_numbers(self):
        # Each call to build_chain uses a fresh STS so no nonce state is shared
        token, chain, agents = build_chain(SecureSTS(), depth=3)
        assert len(chain) == 4
        for i, item in enumerate(chain):
            assert item["cap"]["hop"] == i

    def test_scope_narrows_correctly(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read", "write"])
        token2, chain2 = sts.exchange(
            token, token, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain,
        )
        claims2 = verify_token(token2)
        assert set(claims2["scope"]) == {"read"}

    def test_act_chain_grows(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])
        token2, chain2 = sts.exchange(
            token, token, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain,
        )
        claims2 = verify_token(token2)
        assert claims2["act"]["sub"] == "agent-b"
        assert claims2["act"]["act"]["sub"] == "agent-a"


# ================================================================== #
# 2. Path integrity attacks                                            #
# ================================================================== #

class TestPathIntegrity:
    def test_token_splicing_blocked(self):
        """Attacker splices stolen token with their own as actor."""
        sts = SecureSTS()
        # Legitimate chain: alice -> agent-a -> agent-b
        token_a, chain_a = sts.initial_grant("alice", "agent-a", ["read"])
        token_b, chain_b = sts.exchange(
            token_a, token_a, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain_a,
        )
        # Attacker gets their own grant
        att_token, att_chain = sts.initial_grant("attacker", "attacker", ["read"])

        with pytest.raises(ValueError, match="Path integrity"):
            sts.exchange(
                token_b,        # stolen subject_token (aud=agent-b)
                att_token,      # attacker's own token (act.sub=attacker)
                "attacker",
                ["read"],
                caller="attacker",
                capability_chain=att_chain,
            )

    def test_wrong_session_id_blocked(self):
        """Capability chain from a different session is rejected."""
        sts = SecureSTS()
        token1, chain1 = sts.initial_grant("alice", "agent-a", ["read"])
        token2, chain2 = sts.initial_grant("bob", "agent-a", ["read"])

        # Mix session: use token1's session_id context but chain2
        with pytest.raises(ValueError, match="session_id mismatch"):
            sts.exchange(
                token1, token1, "agent-b", ["read"],
                caller="agent-a", capability_chain=chain2,
            )

    def test_missing_session_id_in_token_blocked(self):
        """Token without session_id (e.g. issued by vulnerable STS) is rejected."""
        from utils.token_utils import sign_token
        bad_token = sign_token({
            "sub": "alice", "aud": "agent-a",
            "act": {"sub": "agent-a"}, "scope": ["read"],
        })
        secure_sts = SecureSTS()
        _, chain = secure_sts.initial_grant("alice", "agent-a", ["read"])
        with pytest.raises(ValueError, match="session_id"):
            secure_sts.exchange(
                bad_token, bad_token, "agent-b", ["read"],
                caller="agent-a", capability_chain=chain,
            )


# ================================================================== #
# 3. Replay attacks                                                    #
# ================================================================== #

class TestReplayPrevention:
    def test_replayed_nonce_blocked(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])

        # First exchange - legitimate, consumes nonces
        token2, chain2 = sts.exchange(
            token, token, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain,
        )
        # Force nonce consumption (as the legitimate exchange would do in production)
        sts._used_nonces.update(
            item["cap"]["nonce"] for item in chain if item["cap"].get("nonce")
        )

        # Second exchange replaying the same chain
        with pytest.raises(ValueError, match="Replayed nonce"):
            sts.exchange(
                token, token, "agent-b", ["read"],
                caller="agent-a", capability_chain=chain,
            )


# ================================================================== #
# 4. Capability chain tampering                                        #
# ================================================================== #

class TestChainTampering:
    def test_tampered_signature_blocked(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])
        tampered = copy.deepcopy(chain)
        tampered[0]["sig"] = "00" * 32  # corrupt the signature

        with pytest.raises(ValueError, match="Invalid capability signature"):
            sts.exchange(
                token, token, "agent-b", ["read"],
                caller="agent-a", capability_chain=tampered,
            )

    def test_tampered_session_id_blocked(self):
        sts = SecureSTS()
        token1, chain1 = sts.initial_grant("alice", "agent-a", ["read"])
        _, chain2 = sts.initial_grant("alice", "agent-a", ["read"])

        # Swap session_id in chain1's cap to chain2's session, but keep old sig
        tampered = copy.deepcopy(chain1)
        tampered[0]["cap"]["session_id"] = chain2[0]["cap"]["session_id"]
        # sig is now wrong for the tampered cap

        with pytest.raises(ValueError, match="Invalid capability signature"):
            sts.exchange(
                token1, token1, "agent-b", ["read"],
                caller="agent-a", capability_chain=tampered,
            )

    def test_non_contiguous_hops_blocked(self):
        sts = SecureSTS()
        token, chain, _ = build_chain(sts, depth=2)
        # Remove the middle capability to create a gap: hop 0 then hop 2
        broken = [chain[0], chain[2]]
        with pytest.raises(ValueError, match="Non-contiguous hop"):
            sts._validate_chain(broken, chain[0]["cap"]["session_id"])

    def test_path_break_blocked(self):
        sts = SecureSTS()
        _, chain_x = sts.initial_grant("alice", "agent-x", ["read"])
        session_id = chain_x[0]["cap"]["session_id"]

        # Craft a second capability with the same session_id but wrong 'from'
        # (sts->agent-z instead of agent-x->agent-z), breaking the path
        import time as _time
        now = int(_time.time())
        broken_cap_data = {
            "session_id": session_id,
            "hop": 1,
            "from": "agent-z",   # should be "agent-x"
            "to": "agent-w",
            "scope": ["read"],
            "issued_at": now,
            "expires_at": now + 3600,
            "nonce": "deadbeef1234",
        }
        broken_cap = {"cap": broken_cap_data, "sig": sign_capability(broken_cap_data)}
        mixed = [chain_x[0], broken_cap]
        with pytest.raises(ValueError, match="Delegation path break"):
            sts._validate_chain(mixed, session_id)

    def test_empty_chain_blocked(self):
        sts = SecureSTS()
        token, _ = sts.initial_grant("alice", "agent-a", ["read"])
        with pytest.raises(ValueError, match="Empty capability chain"):
            sts.exchange(
                token, token, "agent-b", ["read"],
                caller="agent-a", capability_chain=[],
            )


# ================================================================== #
# 5. Scope enforcement                                                 #
# ================================================================== #

class TestScopeEnforcement:
    def test_scope_escalation_blocked(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read"])
        with pytest.raises(ValueError, match="Scope expansion"):
            sts.exchange(
                token, token, "agent-b", ["read", "write"],
                caller="agent-a", capability_chain=chain,
            )

    def test_subset_scope_allowed(self):
        sts = SecureSTS()
        token, chain = sts.initial_grant("alice", "agent-a", ["read", "write", "delete"])
        token2, chain2 = sts.exchange(
            token, token, "agent-b", ["read"],
            caller="agent-a", capability_chain=chain,
        )
        claims2 = verify_token(token2)
        assert set(claims2["scope"]) == {"read"}


# ================================================================== #
# 6. Vulnerable STS still exploitable (regression baseline)           #
# ================================================================== #

class TestVulnerableBaseline:
    def test_splicing_succeeds_on_vulnerable_sts(self):
        """Confirms the vulnerable STS remains exploitable for demo purposes."""
        sts = VulnerableSTS()
        from agent import Agent

        agent_a = Agent("agent-a")
        agent_b = Agent("agent-b")
        agent_a.receive_token(sts.initial_grant("alice", "agent-a", ["read", "write"]))
        agent_b.receive_token(agent_a.delegate_to(sts, "agent-b", ["read", "write"]))

        attacker_token = sts.initial_grant("attacker", "attacker", ["read"])
        forged = sts.exchange(
            agent_b.token, attacker_token, "attacker", ["read", "write"],
            caller="attacker",
        )
        claims = verify_token(forged)
        assert claims["sub"] == "alice"
        assert claims["aud"] == "attacker"
        assert "write" in claims["scope"]
