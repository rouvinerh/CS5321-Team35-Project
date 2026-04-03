# CS5321 Project

Demonstrates a cross-session token splicing attack against a vulnerable OAuth 2.0 STS (RFC 8693), and a session-bound capability chain defence based on the Stateless Internet Flow Filter protocol.

## Vulnerability

RFC 8693 does not require the STS to cross-validate the `subject_token` and `actor_token` in an exchange request. A vulnerable STS validates each token's signature independently and, seeing two valid tokens, issues a new one without verifying they belong to the same delegation flow.

## Setup and Demo

```bash
pip3 install -r requirements.txt

# Demonstrate vulnerability
python3 vulnerable_demo.py

# Demonstrate solution
python3 secure_demo.py
```

## Implementation

### Agents

Agents hold a name and a token. Each agent calls `delegate_to(sts, target, scopes)` to request a delegated token from the STS for a downstream agent, passing the STS as a parameter to simulate calling a shared token service endpoint.

### STS

2 methods are exposed:

`initial_grant(user, agent, scopes)` is called when a user first authenticates to an agent. Issues the first token in the delegation chain with the user as `sub`, the agent as both `aud` and the initial `act`.

`exchange(subject_token, actor_token, requesting_agent, new_scopes)` is called when an agent delegates to another. Verifies both token signatures and issues a new token combining the `sub` from `subject_token` and the `act` chain from `actor_token`.

The vulnerable implementation does not check that `subject_token.aud` matches `actor_token.act.sub`, which is what makes the splice possible.

### Tokens

Tokens are signed JWTs using HS256, carrying 4 token fields like so:

```json
{
  "sub": "alice",
  "aud": "agent-b",
  "act": {
    "sub": "agent-b",
    "act": {
      "sub": "agent-a"
    }
  },
  "scope": ["A", "B"]
}
```

- `sub`: The original user the token acts on behalf of, in this case `alice`. This never changes across hops.

- `aud`: The intended recipient of this token, set to `agent-b`.

- `act`: Nested chain recording who is currently holding and using the token. The outermost `act.sub` is set to `agent-b`, meaning `agent-b` is the active holder. The nested `act.sub` is set to `agent-a`, meaning `agent-a` held this token before `agent-b` did.

- `scope`: Permissions granted by this token, which narrows at each delegation step.

### Delegation

When an agent delegates, it presents 2 tokens. The `subject_token` is the token it currently holds, identifying who the delegation is on behalf of (`sub`). The `actor_token` identifies the entity requesting the exchange, which in this implementation is the same token since the agent's identity is already recorded in the `act` chain. The STS combines them to issue a new token for the next agent in the chain.

In a legitimate exchange, `aud` must match the outermost `act.sub`, which dictates that the token was issued for the agent now presenting it. In the above case, both are set to `agent-b`, meaning `agent-b` is presenting a token that was intended for it by `agent-a`.

## Attack Demonstration

Each user has a protected resource that can only be accessed by presenting a valid token. The goal of the attacker is to access the protected resource of any user.

The resource server checks 2 things before returning information based on `sub`:

1. Token is validly signed
2. `act.sub` matches the `requester`

The checking of `act.sub` validates that the `requester` is who they say they are. The attacker must obtain a token where they are the named actor, which is only possible through the forged exchange.

The demo runs through 3 stages:

1. **Session 1**: Alice authenticates to Agent A, which delegates to Agent B with reduced scope. Each delegation step passes the `aud` check.

2. **Session 2**: Bob authenticates to Agent C, which delegates to Agent D with reduced scope. Same flow, separate session.

3. **Attack**: The attacker intercepts one token from each session. Direct access with either token fails because `act.sub` does not match `attacker`. They forge an exchange request pairing Alice's `sub` with Agent D's `act` chain. The `aud/sub` mismatch (`agent-b` vs `agent-d`) goes undetected by the vulnerable STS, which issues a token naming the attacker as a legitimate actor on Alice's delegation chain. The attacker authenticates as themselves and accesses Alice's protected resource.

