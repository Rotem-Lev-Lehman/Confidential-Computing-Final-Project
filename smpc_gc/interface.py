"""The pluggable backend interface and registry.

A *backend* is an adapter that evaluates a :class:`ThresholdProblem` on a
concrete SMPC engine.  The rest of the system (CLI, tests, integration code)
only ever talks to the abstract :class:`ThresholdBackend`, so swapping the
from-scratch Yao engine for MPyC is a one-line change (``--backend mpyc``).

Backends are registered lazily: importing this module does not import MPyC,
so a missing/optional dependency for one backend never breaks the other.
Call :func:`get_backend` to instantiate one by name.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Callable

from smpc_gc.types import RegionResult, ThresholdProblem


class ThresholdBackend(ABC):
    """Adapter that evaluates the threshold circuit on one SMPC framework."""

    #: Short, stable identifier used as the ``--backend`` value.
    name: str = "abstract"

    #: Human-readable name of the underlying cryptographic technique.
    technique: str = ""

    @abstractmethod
    def evaluate(
        self, problem: ThresholdProblem, *, party: int | None = None
    ) -> list[RegionResult]:
        """Securely evaluate ``problem`` and return the revealed results.

        Args:
            problem: the fully specified problem (see :class:`ThresholdProblem`).
            party: ``None`` for a single-process local simulation that holds both
                share vectors; ``0`` or ``1`` to act as that party in a genuine
                distributed 2PC session.

        Returns:
            One :class:`RegionResult` per region, in region order.  The revealed
            output is identical for both parties (the threshold outcome is a
            public result broadcast to all).
        """

    def availability(self) -> tuple[bool, str]:
        """Report whether this backend can actually run here.

        Returns ``(True, "")`` when ready, or ``(False, reason)`` with a
        human-readable explanation (e.g. a missing dependency or unset path).
        """
        return True, ""

    def describe(self) -> str:
        ok, reason = self.availability()
        state = "available" if ok else f"unavailable: {reason}"
        return f"{self.name} — {self.technique} ({state})"


# --- registry ---------------------------------------------------------------

# Maps backend name -> zero-arg factory.  Factories are used (instead of classes
# directly) so the concrete backend modules are imported only on demand.
_REGISTRY: dict[str, Callable[[], ThresholdBackend]] = {}


def register_backend(name: str, factory: Callable[[], ThresholdBackend]) -> None:
    _REGISTRY[name] = factory


def available_backends() -> list[str]:
    return sorted(_REGISTRY)


def get_backend(name: str) -> ThresholdBackend:
    try:
        factory = _REGISTRY[name]
    except KeyError:
        raise KeyError(
            f"unknown backend {name!r}; available: {', '.join(available_backends())}"
        ) from None
    return factory()


def _register_builtins() -> None:
    def _yao() -> ThresholdBackend:
        from smpc_gc.backends.yao_backend import YaoBackend

        return YaoBackend()

    def _mpyc() -> ThresholdBackend:
        from smpc_gc.backends.mpyc_backend import MPyCBackend

        return MPyCBackend()

    register_backend("yao", _yao)
    register_backend("mpyc", _mpyc)


_register_builtins()
