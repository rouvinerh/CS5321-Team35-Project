from utils.token_utils import sign_token, verify_token


class VulnerableSTS:
    def __init__(self):
        pass

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def initial_grant(self, user, agent, scopes):
        """Issue the first token in a delegation chain and return the token."""
        payload = {
            "sub": user,
            "aud": agent,
            "act": {"sub": agent},
            "scope": scopes,
        }
        return sign_token(payload)

    def exchange(self, subject_token, actor_token, requesting_agent,
                 new_scopes, caller, capability_chain=None):
        """
        Validate tokens and issue a new token.

        Only checks that the caller matches the current actor in actor_token.
        Does NOT verify that subject_token.aud == actor_token.act.sub,
        so the full delegation path is never confirmed. An attacker can splice
        a stolen token with their own actor token to forge a delegation chain.

        Returns new_token.
        """
        sub_claims = verify_token(subject_token)
        act_claims = verify_token(actor_token)

        # 1. Caller identity check: present in both STS variants
        if caller != act_claims["act"]["sub"]:
            raise ValueError(
                f"Caller '{caller}' is not the current actor in actor_token "
                f"(got '{act_claims['act']['sub']}')"
            )

        # MISSING: path integrity check
        #   subject_token.aud should equal actor_token.act.sub,
        #   but this STS never verifies it, allowing token splicing.

        payload = {
            "sub": sub_claims["sub"],
            "aud": requesting_agent,
            "act": {"sub": requesting_agent, "act": act_claims["act"]},
            "scope": new_scopes,
        }
        return sign_token(payload)