import uuid
import time
from utils.token_utils import sign_token, verify_token, sign_capability, verify_capability_sig


class SecureSTS:
    def __init__(self):
        self._used_nonces = set()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def initial_grant(self, user, agent, scopes):
        """Issue the first token in a delegation chain and return (token, [capability])."""
        session_id = uuid.uuid4().hex
        payload = {
            "sub": user,
            "aud": agent,
            "act": {"sub": agent},
            "scope": scopes,
            "session_id": session_id,
        }
        token = sign_token(payload)
        cap = self._make_capability(session_id, hop=0, from_agent="sts", to_agent=agent, scope=scopes)
        return token, [cap]

    def exchange(self, subject_token, actor_token, requesting_agent,
                 new_scopes, caller, capability_chain):
        """
        Validate tokens + capability chain, then issue a new token and appended chain.

        Raises ValueError on any integrity failure.
        Returns (new_token, new_capability_chain).
        """
        sub_claims = verify_token(subject_token)
        act_claims = verify_token(actor_token)

        # 1. Caller identity check (also present in the vulnerable STS)
        if caller != act_claims["act"]["sub"]:
            raise ValueError(
                f"Caller '{caller}' is not the current actor in actor_token "
                f"(got '{act_claims['act']['sub']}')"
            )

        # 2. Path integrity: the token was issued to the agent presenting it
        if sub_claims["aud"] != act_claims["act"]["sub"]:
            raise ValueError(
                f"Path integrity check failed: "
                f"subject_token.aud='{sub_claims['aud']}' != "
                f"actor_token.act.sub='{act_claims['act']['sub']}'"
            )

        # 3. session_id must match across the chain and the token
        session_id = sub_claims.get("session_id")
        if not session_id:
            raise ValueError("subject_token is missing session_id")

        # 4. Validate the full capability chain
        self._validate_chain(capability_chain, session_id)

        # 5. Scopes must not expand beyond the last hop
        last_scope = set(capability_chain[-1]["cap"]["scope"])
        if not set(new_scopes).issubset(last_scope):
            raise ValueError(
                f"Scope expansion not allowed: requested {new_scopes} "
                f"but last hop only grants {list(last_scope)}"
            )

        # 6. Consume only the last capability's nonce (replay prevention for this request).
        #    Earlier caps in the chain were already validated at prior hops.
        last_nonce = capability_chain[-1]["cap"].get("nonce")
        if last_nonce:
            self._used_nonces.add(last_nonce)

        # 7. Issue new token
        payload = {
            "sub": sub_claims["sub"],
            "aud": requesting_agent,
            "act": {"sub": requesting_agent, "act": act_claims["act"]},
            "scope": new_scopes,
            "session_id": session_id,
        }
        new_token = sign_token(payload)

        # 8. Issue new capability and append to chain
        hop = len(capability_chain)
        new_cap = self._make_capability(session_id, hop, caller, requesting_agent, new_scopes)
        return new_token, capability_chain + [new_cap]

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _make_capability(self, session_id, hop, from_agent, to_agent, scope):
        now = int(time.time())
        cap = {
            "session_id": session_id,
            "hop": hop,
            "from": from_agent,
            "to": to_agent,
            "scope": list(scope),
            "issued_at": now,
            "expires_at": now + 3600,
            "nonce": uuid.uuid4().hex,
        }
        return {"cap": cap, "sig": sign_capability(cap)}

    def _validate_chain(self, chain, expected_session_id):
        if not chain:
            raise ValueError("Empty capability chain")

        for i, item in enumerate(chain):
            # Signature + expiry check
            verify_capability_sig(item)
            cap = item["cap"]

            if time.time() > cap["expires_at"]:
                raise ValueError(f"Capability at hop {i} has expired")

            # Nonce replay check — only applies to the last cap (the current request's cap).
            # Previous caps in the chain were already validated at earlier hops.
            if i == len(chain) - 1:
                nonce = cap.get("nonce")
                if nonce and nonce in self._used_nonces:
                    raise ValueError(f"Replayed nonce detected at hop {i}")

            # session_id continuity
            if cap["session_id"] != expected_session_id:
                raise ValueError(
                    f"session_id mismatch at hop {i}: "
                    f"expected '{expected_session_id}', got '{cap['session_id']}'"
                )

            # Contiguous hop numbers
            if cap["hop"] != i:
                raise ValueError(
                    f"Non-contiguous hop at index {i}: cap.hop={cap['hop']}"
                )

        # from/to path continuity
        for i in range(1, len(chain)):
            prev_to = chain[i - 1]["cap"]["to"]
            curr_from = chain[i]["cap"]["from"]
            if prev_to != curr_from:
                raise ValueError(
                    f"Delegation path break at hop {i}: "
                    f"previous 'to'='{prev_to}' != current 'from'='{curr_from}'"
                )
