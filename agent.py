class Agent:
    def __init__(self, name):
        self.name = name
        self.token = None

    def receive_token(self, token):
        self.token = token

    def delegate_to(self, sts, target_name, scopes):
        return sts.exchange(self.token, self.token, target_name, scopes, caller=self.name)


class SecureAgent:
    def __init__(self, name):
        self.name = name
        self.token = None
        self.capability_chain = []

    def receive_grant(self, token, capability_chain):
        self.token = token
        self.capability_chain = list(capability_chain)

    def delegate_to(self, sts, target_name, scopes):
        """Returns (token, new_capability_chain) from the STS."""
        return sts.exchange(
            self.token, self.token, target_name, scopes,
            caller=self.name, capability_chain=self.capability_chain,
        )