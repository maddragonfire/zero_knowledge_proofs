"""An interactive Schnorr proof of knowledge, with both roles in one process."""

import argparse
from dataclasses import dataclass
from secrets import randbelow


# RFC 3526 section 3, MODP group 14. Both this group and the toy group
# use base 2, which has prime order (p - 1) // 2.
MODP_2048 = int.from_bytes(bytes.fromhex("""
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
"""), "big")


@dataclass(frozen=True)
class Transcript:
    commitment: int
    challenge: int
    response: int


def live_round(p, private_key):
    q = (p - 1) // 2

    # Prover sends the commitment and keeps the fresh nonce secret.
    nonce = 1 + randbelow(q - 1)
    commitment = pow(2, nonce, p)

    # Verifier samples the challenge only after receiving the commitment.
    challenge = randbelow(q)

    # Prover answers this challenge once, then discards the nonce.
    response = (nonce + challenge * private_key) % q
    return Transcript(commitment, challenge, response)


def verify(p, public_key, transcript):
    q = (p - 1) // 2
    for element in (public_key, transcript.commitment):
        if not (1 < element < p and pow(element, q, p) == 1):
            return False
    if not (0 <= transcript.challenge < q and 0 <= transcript.response < q):
        return False

    left = pow(2, transcript.response, p)
    right = transcript.commitment * pow(public_key, transcript.challenge, p) % p
    return left == right


def simulate(p, public_key):
    """Reproduce an honest verifier's view using only public information."""
    q = (p - 1) // 2
    challenge = randbelow(q)
    inverse_factor = pow(public_key, -challenge, p)
    while True:
        response = randbelow(q)
        commitment = pow(2, response, p) * inverse_factor % p
        if commitment != 1:  # The live prover sampled a nonzero nonce.
            return Transcript(commitment, challenge, response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--toy", action="store_true", help="use p=23 for hand arithmetic")
    p = 23 if parser.parse_args().toy else MODP_2048
    q = (p - 1) // 2
    private_key = 1 + randbelow(q - 1)
    public_key = pow(2, private_key, p)

    print(f"Group: p={p}, q={q}, g=2")
    print(f"Public key Y = {public_key}")
    for label, transcript in (
        ("Live", live_round(p, private_key)),
        ("Simulated from Y alone", simulate(p, public_key)),
    ):
        print(f"\n{label}")
        print(f"  Commitment R = {transcript.commitment}")
        print(f"  Challenge  c = {transcript.challenge}")
        print(f"  Response   s = {transcript.response}")
        print(f"  Verifier accepts: {verify(p, public_key, transcript)}")


if __name__ == "__main__":
    main()
