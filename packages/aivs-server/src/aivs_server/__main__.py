"""Console entry point for ``aivs-server``.

Exists so that ``[project.scripts]`` and ``python -m aivs_server`` resolve to the
same callable, and so the container's ``CMD`` does not depend on the internal
module layout of ``main.py``.
"""

from __future__ import annotations

from aivs_server.main import main

__all__ = ["main"]

if __name__ == "__main__":  # pragma: no cover - process entry point
    main()
