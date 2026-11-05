# Prove you know a private key

Suppose you've already given me a public key `Y`. You claim to know the
secret exponent `x` that produced it. Schnorr identification lets me test that
claim by asking you a fresh question after you commit to the round.

```sh
python3 schnorr.py --toy
python3 schnorr.py
```

The first command uses small numbers you can check by hand. The second uses
a 2048-bit group. Both run a live exchange and then simulate one using only
the public key. Each run generates a disposable key and prints the public
messages. Python 3.8+ and its standard library are sufficient. This is
teaching code. For deployed authentication, use a vetted implementation.

## One round by hand

Use powers of `g = 2` modulo `p = 23`. Since 2 has order `q = 11`,
exponents wrap around modulo 11. Let's look over the prover's shoulder for
this worked example. Suppose you choose `x = 6`. I already have your public
key `Y = 2**6 % 23 = 18`.

| Step | What happens | What crosses the wire |
| --- | --- | --- |
| 1. You commit | Pick a fresh secret nonce, here `r = 5`. Compute `R = pow(2, r, 23)`. | You → me: `R = 9` |
| 2. I challenge | After receiving 9, I draw a random challenge, here `c = 4`. | Me → you: `c = 4` |
| 3. You respond | Compute `s = (r + c*x) % 11 = (5 + 4*6) % 11`. | You → me: `s = 7` |

I can now check your answer using only the public values:

```python
>>> pow(2, 7, 23)                # g**s
13
>>> 9 * pow(18, 4, 23) % 23      # R * Y**c
13
```

Both sides agree because $g^{r+cx}=g^r (g^x)^c$. You can answer any
challenge I choose after you send $R$. An impersonator can prepare a
commitment for one guessed challenge. In the toy group that guess succeeds
with probability $1/11$, and the public key is small enough to brute-force.

## Why does this count as zero knowledge?

Put yourself in the verifier's seat. You can manufacture the *same* transcript
with just the public key. Pick `c = 4` and `s = 7` first, then work backward:

```python
>>> pow(2, 7, 23) * pow(18, -4, 23) % 23
9
```

That gives `(R, c, s) = (9, 4, 7)`. In a live exchange you would have
insisted on seeing 9 **before** choosing 4. Someone reading your saved
transcript has no such assurance.

The claim is stronger than being able to reproduce this one example.
For each challenge $c$, the mapping $r \mapsto s=r+cx \pmod q$ is a
bijection. Drawing $s$ uniformly and solving for $R$ therefore reproduces
the live distribution exactly, provided we skip $R=1$ just as the live
prover skips $r=0$. This is *honest-verifier zero knowledge*. The transcript
reveals only what the verifier could have sampled from the public key alone.

## Why the nonce is single-use

Suppose you answer a second challenge `c = 5` for that same commitment.
Your second response would be `s = 2`. Subtracting the two response
equations cancels the nonce, and I recover your private key:

```python
>>> (2 - 7) * pow(5 - 4, -1, 11) % 11
6
```

This is also the knowledge argument. A prover who can answer two distinct
challenges for one commitment gives us enough information to extract $x$.
In normal use, generate a fresh secret nonce for every commitment and answer
just one challenge per commitment.

The interactive protocol and its security properties are described in
[RFC 8235, §§2.2 and 6](https://www.rfc-editor.org/rfc/rfc8235.html#section-2.2).
The RFC subtracts the challenge term in the response. This demo adds it and
moves the factor to the other side of the verification equation. The large
group parameters come from [RFC 3526, §3](https://www.rfc-editor.org/rfc/rfc3526.html#section-3).
