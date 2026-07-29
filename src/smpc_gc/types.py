"""Backend-agnostic data structures for the threshold sub-protocol.

These types define the *interface boundary* of the protocol-switching step: the
secure-summation layer reduces the 4-node network to two consolidated share
vectors ``A`` and ``B``; this module is how those vectors — and the public
parameters of the circuit — are handed to the 2PC engine, independently of which
SMPC library evaluates it.
"""

from __future__ import annotations

from dataclasses import dataclass

# Public sentinel emitted when a region is *below* the quarantine threshold.
# The circuit reveals this instead of the real region id, leaking nothing about
# the true (sub-threshold) count.  Region ids therefore MUST be non-zero.
CLEAR_TOKEN: int = 0


@dataclass(frozen=True)
class ThresholdProblem:
    """A fully specified threshold-evaluation problem for one 2PC session.

    The combined case count for region ``j`` is ``a_shares[j] + b_shares[j]``.
    The circuit reveals ``region_ids[j]`` iff that sum exceeds ``threshold``,
    otherwise it reveals :data:`CLEAR_TOKEN`.

    Depending on the run mode, a party only fills in the share vector it owns:

    * **Local simulation** (``party is None``): a single process mocks and holds
      *both* ``a_shares`` and ``b_shares`` — the isolated-development mode where
      inputs A and B are mocked locally.
    * **Distributed 2PC** (``party in {0, 1}``): party 0 fills ``a_shares`` only
      and party 1 fills ``b_shares`` only; the other vector stays ``None`` and is
      never learned locally.

    Notes:
        ``modulus`` is how the finite field of the secure-summation layer is
        carried across this boundary.  When it is set, ``a_shares`` and
        ``b_shares`` are additive shares over 𝔽_modulus, so they reconstruct
        the true count only modulo ``modulus``, and the circuit reduces
        ``A + B`` accordingly before comparing.  When it is ``None`` the shares
        are assumed to reconstruct directly over the integers — the simpler
        setting used by the mocked problems in ``problems/``.
    """

    threshold: int
    region_ids: list[int]
    a_shares: list[int] | None = None
    b_shares: list[int] | None = None
    bit_length: int = 32
    clear_token: int = CLEAR_TOKEN
    modulus: int | None = None

    def reconstruct(self, a: int, b: int) -> int:
        """The true count for one region, from the two shares."""
        total = a + b
        return total % self.modulus if self.modulus is not None else total

    @property
    def num_regions(self) -> int:
        return len(self.region_ids)

    def owned_shares(self, party: int | None) -> list[int] | None:
        """Return the share vector this party contributes as a sender.

        ``party is None`` (local simulation) contributes both vectors and is
        handled by the caller directly; this helper returns the A-vector.
        """
        if party is None or party == 0:
            return self.a_shares
        if party == 1:
            return self.b_shares
        raise ValueError(f"party must be 0, 1 or None, got {party!r}")

    def validate(self, *, party: int | None = None) -> None:
        """Sanity-check the problem before handing it to the engine."""
        if self.num_regions == 0:
            raise ValueError("problem has no regions")
        if self.bit_length < 2:
            raise ValueError("bit_length must be >= 2")
        if self.clear_token in self.region_ids:
            raise ValueError(
                f"clear_token {self.clear_token} collides with a region id; "
                "region ids must be distinct from the 'Clear' sentinel"
            )
        if self.modulus is not None and not 2 <= self.modulus <= (1 << self.bit_length):
            raise ValueError(
                f"modulus {self.modulus} must fit in bit_length={self.bit_length} "
                "bits (both shares are reduced mod it, so each must fit its wires)"
            )
        for name, vec in (("a_shares", self.a_shares), ("b_shares", self.b_shares)):
            if vec is not None and len(vec) != self.num_regions:
                raise ValueError(
                    f"{name} has length {len(vec)} but there are "
                    f"{self.num_regions} regions"
                )
            if vec is not None and self.modulus is not None:
                bad = next((v for v in vec if not 0 <= v < self.modulus), None)
                if bad is not None:
                    raise ValueError(
                        f"{name} contains {bad}, which is not reduced mod "
                        f"{self.modulus}"
                    )
        if party is None:
            if self.a_shares is None or self.b_shares is None:
                raise ValueError(
                    "local simulation (party=None) requires both a_shares and "
                    "b_shares to be provided"
                )
        else:
            if self.owned_shares(party) is None:
                raise ValueError(f"party {party} must provide its own shares")

    def expected_plaintext(self) -> list[RegionResult] | None:
        """Compute the result in the clear, if both share vectors are known.

        Used for verifying the secure result; returns ``None`` when a share
        vector is missing (as in a genuine distributed run).
        """
        if self.a_shares is None or self.b_shares is None:
            return None
        results = []
        for j, rid in enumerate(self.region_ids):
            crossed = self.reconstruct(self.a_shares[j], self.b_shares[j]) > self.threshold
            revealed = rid if crossed else self.clear_token
            results.append(RegionResult(j, rid, revealed, crossed))
        return results


@dataclass(frozen=True)
class RegionResult:
    """The revealed outcome of the threshold circuit for a single region."""

    region_index: int
    region_id: int
    revealed: int
    crossed: bool

    @property
    def status(self) -> str:
        return "QUARANTINE" if self.crossed else "clear"

    def as_dict(self) -> dict:
        return {
            "region_index": self.region_index,
            "region_id": self.region_id,
            "revealed": self.revealed,
            "crossed": self.crossed,
            "status": self.status,
        }
