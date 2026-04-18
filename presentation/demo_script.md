# Demo Presentation Script

Run:

```bash
source .venv/bin/activate
python demo.py
```

## Opening

I am going to show the same delegation scenario under two systems: the vulnerable design and our defended design.
The point of this demo is to show that our method does not just describe the attack better.
It actually changes the execution result in code.

## Stage 1: Normal Delegation Flow

In the first stage, I explain the normal case.
Alice authenticates to Agent A, and Agent A delegates to Agent B through the STS.

On the screen, we can see the token fields, including `sub`, `aud`, and `scope`, and we can also see the legitimate path `Alice -> Agent A -> Agent B`.

The important point here is that this is a valid delegation chain.
The token held by Agent B was actually issued to Agent B, so the path is continuous.
This is the baseline behavior we want from the system.

Press Enter.

## Stage 2: Same Attack on Vulnerable STS

Now we keep the same scenario, but we change the input to an attack case.
On the left is the stolen subject token from Agent B.
On the right is the attacker’s own valid actor token.

The key mismatch is shown on the screen:
`subject_token.aud = agent-b`, but `actor_token.act.sub = attacker`.
These two values should match if the delegation path is legitimate, but here they do not.

In the vulnerable STS, the caller identity check still passes, but there is no path continuity check.
Because of that, the code actually mints a forged token for the attacker.

So this is not just a diagram or a hypothetical attack.
The vulnerable system really produces a forged result in code, and accepts the fake path `Alice -> Agent A -> Agent B -> Attacker`.

Press Enter.

## Stage 3: Same Attack on Secure STS

Now we rebuild the same legitimate prefix under the secure design, and replay the same kind of attack input.

This time, the request goes through the Secure STS validation pipeline:
caller check, path check, session binding, capability-chain validation, and scope and replay checks.

The attack stops at the path check.
The stolen token was never issued to the attacker, so the request is rejected before any new token is minted.

This is the main result of our project:
the same attack input leads to two different outcomes.
Under the vulnerable design, the forged token is issued.
Under our design, the request is rejected.

Press Enter.

## Stage 4: Cost Analysis

Finally, we show the cost of the defense.
This table measures exchange latency and chain size as delegation depth increases from 1 to 5.

The overhead grows roughly linearly with the number of hops, which is expected because more capability-chain state must be validated at each additional step.
But in this prototype, the latency remains in the sub-millisecond range, so the defense is practical while still enforcing path integrity.

## Closing

So the demo shows three things.

1. The vulnerability is real and executable in code.
2. Our method changes the actual system behavior, not just the explanation.
3. The defense introduces measurable overhead, but the overhead remains small.
