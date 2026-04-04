class Agent:
    def __init__(self, name):
        self.name = name
        self.token = None

    def receive_token(self, token):
        self.token = token

    def delegate_to(self, sts, target_name, scopes):
        return sts.exchange(self.token, self.token, target_name, scopes, caller=self.name)