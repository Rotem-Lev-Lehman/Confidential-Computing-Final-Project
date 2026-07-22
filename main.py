"""Entry point for the Garbled Circuit / 2PC threshold engine.

Delegates to :mod:`smpc_gc.cli`.  See that module (or ``uv run smpc-gc --help``)
for usage; the backend is chosen with ``--backend {yao,mpyc}``.
"""

from smpc_gc.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
