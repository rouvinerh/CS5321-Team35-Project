from utils.token_utils import sign_token, verify_token

class VulnerableSTS:
    def initial_grant(self, user, agent, scopes):
        payload = {
            "sub": user,
            "aud": agent,
            "act": {"sub": agent},
            "scope": scopes,
        }
        return sign_token(payload)

    def exchange(self, subject_token, actor_token, requesting_agent, new_scopes, caller):
        sub_claims = verify_token(subject_token)
        act_claims = verify_token(actor_token)

        if caller != act_claims["act"]["sub"]:
            raise ValueError(f"Caller '{caller}' is not the current actor on actor_token")

        # never checks that sub_claims["aud"] == act_claims["act"]["sub"]
        # so the full delegation path is never verified, any agent can splice themselves
        # into an existing chain by presenting a stolen token as the subject
        payload = {
            "sub": sub_claims["sub"],
            "aud": requesting_agent,
            "act": {"sub": requesting_agent, "act": act_claims["act"]},
            "scope": new_scopes,
        }
        return sign_token(payload)