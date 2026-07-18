"""MPyC backend for the threshold circuit.

`MPyC <https://github.com/lschoe/mpyc>`_ is a pure-Python SMPC framework based
on **honest-majority Shamir secret sharing** (Shamir's threshold scheme, secure
against passive adversaries controlling fewer than half of the parties — which
means threshold ``t = 0``, i.e. no privacy, in the 2-party setting).  It
demonstrates the same computation as the from-scratch ``yao`` backend running
on an established library.

The secure computation itself is tiny and maps directly onto the proposal's
circuit:

    total   = A + B                         # secure fixed-width addition
    crossed = total > threshold             # secure comparison
    output  = crossed ? region_id : Clear   # secure multiplexer

**Unified run modes.**  This backend takes the exact same ``party`` / ``host``
/ ``port`` parameters as the ``yao`` backend, so the CLI flags are identical
for both — switching engines is only ``--backend``:

    * ``party=None`` — local simulation; one process holds both A and B.
    * ``party=0/1``  — genuine 2PC; the two processes rendezvous on
      ``host:port`` (MPyC itself uses ``port`` for party 0 and ``port + 1``
      for party 1, both on ``host``).

MPyC configures its parties from its *own* command-line flags (``-M -I -P``)
parsed from ``sys.argv`` when ``mpyc.runtime`` is first imported.  This
backend does the translation: it builds the equivalent MPyC argv from the
unified parameters and swaps it in around that first import, so callers never
touch MPyC flags (and our CLI flags — e.g. ``--threshold``, ``--bit-length`` —
can no longer be misread by MPyC's overlapping option names).
"""

from __future__ import annotations

import os
import sys

from smpc_gc.channel import DEFAULT_HOST, DEFAULT_PORT
from smpc_gc.interface import ThresholdBackend
from smpc_gc.types import RegionResult, ThresholdProblem

# The party the (import-time-configured, per-process) MPyC runtime was set up
# for: "unset" until first use, then None (local) or 0/1.  One process is one
# MPyC party; a second, different configuration cannot take effect.
_UNSET = "unset"
_runtime_party: object = _UNSET


def _log_flags() -> list[str]:
    """MPyC log-control flags.

    MPyC's logging is suppressed by default so stdout stays identical across
    backends (and ``--json`` stays parseable).  Set ``SMPC_GC_MPYC_LOG=1`` to
    keep MPyC's own log lines — the experiment harness uses them to read the
    runtime's self-reported ``bytes sent`` statistic.
    """
    return [] if os.environ.get("SMPC_GC_MPYC_LOG") == "1" else ["--no-log"]


def _import_with_argv(module: str, mpyc_argv: list[str]) -> None:
    """Import ``module`` with the given flags substituted into ``sys.argv``.

    Both ``mpyc`` (logging setup) and ``mpyc.runtime`` (party configuration)
    parse ``sys.argv`` at first import; this scopes the translated flags to
    exactly that window so our own CLI flags never reach MPyC and vice versa.
    """
    import importlib

    saved_argv = sys.argv
    sys.argv = [saved_argv[0], *mpyc_argv]
    try:
        importlib.import_module(module)
    finally:
        sys.argv = saved_argv


class MPyCBackend(ThresholdBackend):
    name = "mpyc"
    technique = "honest-majority Shamir secret sharing (arithmetic circuit)"

    def __init__(
        self, *, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT
    ) -> None:
        self.host = host
        self.port = port

    def availability(self) -> tuple[bool, str]:
        try:
            _import_with_argv("mpyc", _log_flags())
        except ImportError as exc:
            return False, f"mpyc not importable ({exc}); run `uv add mpyc`"
        return True, ""

    # --- unified-flags -> MPyC-flags translation ----------------------------

    def _mpyc_argv(self, party: int | None) -> list[str]:
        """The MPyC runtime flags equivalent to the unified parameters."""
        if party is None:
            return _log_flags()  # single local party, no networking
        return [
            "-M", "2",
            "-I", str(party),
            "-P", f"{self.host}:{self.port}",       # party 0's address
            "-P", f"{self.host}:{self.port + 1}",   # party 1's address
            *_log_flags(),
        ]

    def _runtime(self, party: int | None):
        """Import (and thereby configure) the MPyC runtime for ``party``.

        MPyC reads ``sys.argv`` once, at first import of ``mpyc.runtime``; we
        substitute the translated flags for exactly that window.
        """
        global _runtime_party
        if "mpyc.runtime" in sys.modules:
            if _runtime_party is not _UNSET and _runtime_party != party:
                raise RuntimeError(
                    "the MPyC runtime is already configured for "
                    f"party={_runtime_party!r} in this process; one process "
                    "can only act as one MPyC party — start a new process "
                    f"to run as party={party!r}"
                )
        else:
            _import_with_argv("mpyc.runtime", self._mpyc_argv(party))
        _runtime_party = party
        from mpyc.runtime import mpc

        return mpc

    # --- evaluation ---------------------------------------------------------

    def evaluate(
        self, problem: ThresholdProblem, *, party: int | None = None
    ) -> list[RegionResult]:
        problem.validate(party=party)
        mpc = self._runtime(party)

        captured: dict[str, list[int]] = {}

        async def _protocol() -> None:
            secint = mpc.SecInt(problem.bit_length)
            await mpc.start()
            try:
                num_parties = len(mpc.parties)
                pid = mpc.pid
                secure_outputs = []
                for j, region_id in enumerate(problem.region_ids):
                    a_val = _local_value(problem.a_shares, j)
                    b_val = _local_value(problem.b_shares, j)

                    if num_parties >= 2:
                        # Genuine 2PC: each value is privately input by its owner.
                        a = mpc.input(
                            secint(a_val if pid == 0 else None), senders=0
                        )
                        b = mpc.input(
                            secint(b_val if pid == 1 else None), senders=1
                        )
                    else:
                        # Single-process simulation: this party supplies both.
                        a = mpc.input(secint(a_val), senders=0)
                        b = mpc.input(secint(b_val), senders=0)

                    total = a + b
                    crossed = total > problem.threshold
                    secure_outputs.append(
                        mpc.if_else(crossed, region_id, problem.clear_token)
                    )

                revealed = await mpc.output(secure_outputs)
                captured["revealed"] = [int(v) for v in revealed]
            finally:
                await mpc.shutdown()

        mpc.run(_protocol())

        revealed = captured["revealed"]
        return [
            RegionResult(
                region_index=j,
                region_id=region_id,
                revealed=revealed[j],
                crossed=revealed[j] != problem.clear_token,
            )
            for j, region_id in enumerate(problem.region_ids)
        ]


def _local_value(shares: list[int] | None, index: int) -> int | None:
    """The value this party holds for ``index`` (``None`` if it owns no shares)."""
    if shares is None:
        return None
    return shares[index]
