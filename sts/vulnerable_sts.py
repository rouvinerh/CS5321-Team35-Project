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

    def exchange(self, subject_token, actor_token, requesting_agent, new_scopes):
        sub_claims = verify_token(subject_token)
        act_claims = verify_token(actor_token)

        # never checks that sub_claims["aud"] == act_claims["act"]["sub"]
        # A valid aud/sub match would prove both tokens belong to the same delegation flow

        payload = {
            "sub": sub_claims["sub"],
            "aud": requesting_agent,
            "act": {"sub": requesting_agent, "act": act_claims["act"]},
            "scope": new_scopes,
        }
        return sign_token(payload)