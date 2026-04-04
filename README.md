# CS5321 Project

Demonstrates a cross-session token splicing attack against a vulnerable OAuth 2.0 STS (RFC 8693), and a session-bound capability chain defence based on the Stateless Internet Flow Filter (SIFF) protocol.

## Vulnerability

RFC 8693 does not require the STS to verify the full delegation path when processing a token exchange. Even with a caller identity check, an attacker who steals a token can splice it with their own token as the actor, inserting themselves into a delegation chain they were never part of. The STS validates tokens individually but does not verify that the delegation chain is continuous.

A valid delegation requires the following:

```
subject_token.aud == actor_token.act.sub
```

This ensures that the entity presenting the token is the same entity the token was issued for. The vulnerable implementation does not enforce this check, allowing an attacker to splice together unrelated tokens and create a forged delegation path.

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

1. `initial_grant(user, agent, scopes)` is called when a user first authenticates to an agent. Issues the first token in the delegation chain with the user as `sub`, the agent as both `aud` and the initial `act`.

2. `exchange(subject_token, actor_token, requesting_agent, new_scopes, caller)` is called when an agent delegates to another. Verifies both token signatures and checks that `caller` matches `actor_token.act.sub`. Issues a new token combining the `sub` from `subject_token` and the `act` chain from `actor_token`.

The vulnerable implementation does not check that `subject_token.aud` matches `actor_token.act.sub`, so the full delegation path is never verified.

### Tokens

Tokens are signed JWTs using HS256, carrying 4 fields:

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

In a legitimate exchange, the following must hold:

```
subject_token.aud == actor_token.act.sub
```

This ensures that the token is being presented by the agent it was issued to, preserving continuity of the delegation chain.

For example, if `subject_token.aud = agent-b`, then `actor_token.act.sub` must also be `agent-b`, meaning `agent-b` is the entity presenting the token it received from the previous step.

## Attack Demonstration

The demo runs through 2 stages:

1. **Legitimate chain**: Alice authenticates to Agent A, which delegates to Agent B with reduced scope. The legitimate `act` chain is printed to show what a valid delegation path looks like.

2. **Attack**: The attacker obtains their own token via `initial_grant` and steals `agent_b.token`. They splice the two together, presenting `agent_b.token` as the subject and their own token as the actor. The caller check passes since they are presenting their own token. The STS issues a token with a forged `act` chain and escalated scope. The path `Alice -> Agent A -> Agent B -> Attacker` never existed.

The attacker authenticates as themselves and cannot impersonate any other agent, as tokens are signed by the STS and cannot be forged. The attack works purely because path integrity is not enforced.