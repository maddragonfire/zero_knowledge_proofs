"""Prove knowledge of a graph relabeling, with both parties in one process."""

import argparse
from dataclasses import dataclass
from secrets import SystemRandom, randbits
from typing import FrozenSet, Tuple


Permutation = Tuple[int, ...]  # Entry i is the new label of vertex i.


@dataclass(frozen=True)
class Graph:
    """Vertices are 0 through n-1. Each undirected edge has its smaller end first."""

    n: int
    edges: FrozenSet[Tuple[int, int]]

    def relabel(self, permutation):
        edges = set()
        for u, v in self.edges:
            a, b = permutation[u], permutation[v]
            edges.add((min(a, b), max(a, b)))
        return Graph(self.n, frozenset(edges))


@dataclass(frozen=True)
class Transcript:
    commitment: Graph
    challenge: int
    response: Permutation


def random_permutation(n):
    labels = list(range(n))
    SystemRandom().shuffle(labels)
    return tuple(labels)


def live_round(graphs, witness):
    """The secret witness maps G0 to G1."""
    # Prover commits to H by giving G1 fresh random labels.
    mask = random_permutation(graphs[1].n)
    commitment = graphs[1].relabel(mask)

    # Verifier chooses which public graph the prover must map to H.
    challenge = randbits(1)
    if challenge == 0:
        # Follow G0 -> G1 -> H, applying the witness before the mask.
        response = tuple(mask[v] for v in witness)
    else:
        response = mask
    return Transcript(commitment, challenge, response)


def verify(graphs, transcript):
    """Check the public reply against the commitment and the verifier's challenge."""
    n = graphs[0].n
    bit, mapping = transcript.challenge, transcript.response
    if type(bit) is not int or bit not in (0, 1) or graphs[1].n != n:
        return False
    if not isinstance(mapping, (tuple, list)) or len(mapping) != n:
        return False
    if any(type(v) is not int for v in mapping):
        return False
    if set(mapping) != set(range(n)):
        return False
    return graphs[bit].relabel(mapping) == transcript.commitment


def simulate(graphs):
    """Sample an honest verifier's transcript using just the two public graphs."""
    challenge = randbits(1)
    response = random_permutation(graphs[challenge].n)
    commitment = graphs[challenge].relabel(response)
    return Transcript(commitment, challenge, response)


def show_transcript(label, graphs, transcript):
    print(f"\n{label}")
    print(f"  Commitment H edges: {sorted(transcript.commitment.edges)}")
    print(f"  Challenge: map G{transcript.challenge} to H")
    print(f"  Response (new label of each vertex): {transcript.response}")
    print(f"  Verifier accepts: {verify(graphs, transcript)}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=1, help="number of fresh live rounds")
    rounds = parser.parse_args().rounds
    if rounds < 1:
        parser.error("--rounds must be positive")

    # A triangle with a leaf on one vertex and a two-edge tail on another.
    graph0 = Graph(6, frozenset({(0, 1), (0, 2), (1, 2), (0, 3), (1, 4), (4, 5)}))
    witness = random_permutation(graph0.n)
    graphs = (graph0, graph0.relabel(witness))
    print(f"Public graphs on vertices 0 through {graph0.n - 1}")
    for index, graph in enumerate(graphs):
        print(f"  G{index} edges: {sorted(graph.edges)}")
    for i in range(rounds):
        show_transcript(f"Live round {i + 1}", graphs, live_round(graphs, witness))
    show_transcript("Simulated from the public graphs alone", graphs, simulate(graphs))


if __name__ == "__main__":
    main()
