"""Allow ``python -m crashlab`` to behave like the ``crashlab`` script."""

from __future__ import annotations

from crashlab.cli import main

if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
