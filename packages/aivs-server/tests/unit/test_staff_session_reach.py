"""A member's request reaches the staff login through two modules, and nothing else (Phase P).

The member login is refused who filed what, and every table that would say it
(``db.grants.MEMBER_GRANTS``). That refusal is only as good as the member
path's inability to open the other login: a staff session opened anywhere a
member's request runs reads all of it, whatever the grants say. So the names
that open a staff session -- the staff engine, its sessionmaker, the
background session scope -- are imported only where this file says, each with
the reason it is safe. ``services.member_staff_reads``,
``services.member_staff_writes`` and ``services.attribution`` are the ones a
member's request goes through, each function keyed on the caller's
organisation; ``auth.staff_auth`` is where every request is authenticated,
keyed on what it presented.

Parsed, not grepped: a docstring that names ``get_sessionmaker`` is not an
import of it.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path
from typing import Final

SOURCE: Final = Path(__file__).resolve().parents[2] / "src" / "aivs_server"
ENGINE_MODULE: Final = "aivs_server.db.engine"

#: Whatever opens a session on the staff login.
STAFF_ENTRY_POINTS: Final = frozenset(
    {"get_engine", "get_sessionmaker", "get_session", "session_scope", "_engine", "_sessionmaker"}
)

#: The modules that may name one, and why each is safe.
ALLOWED: Final[dict[str, str]] = {
    "main.py": "the lifespan and the background jobs, which serve no request",
    "bootstrap_operator.py": "a command-line tool",
    "rewrap_secrets.py": "a command-line tool",
    "rekey_attribution.py": "a command-line tool",
    "auth/staff_auth.py": (
        "authentication, keyed only on what the request presented: a token, an email with"
        " its certificate's organisation, a signed identity, a certificate the caller manages"
    ),
    "auth/deps.py": (
        "binds each request to the login its caller is entitled to (policy.uses_staff_database)"
    ),
    "api/meta.py": (
        "readiness asks the staff connection its own role, and /metrics counts the "
        "work waiting; neither returns a row"
    ),
    "services/attribution.py": "submissions_filed_by: a member's own filings, keyed on its org",
    "services/member_staff_writes.py": (
        "a member's own organisation's status and settings, keyed on its org"
    ),
    "services/documents.py": (
        "a document's reads and writes, each decided by the caller's own grant on it"
    ),
    "services/member_staff_reads.py": (
        "a member's own rows in tables its login may only write, keyed on its org"
    ),
}


def _names_from_engine(tree: ast.AST) -> Iterator[str]:
    """Every staff entry point the module imports from, or reads off, ``db.engine``."""
    engine_aliases = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == ENGINE_MODULE:
            yield from (alias.name for alias in node.names if alias.name in STAFF_ENTRY_POINTS)
        if isinstance(node, ast.ImportFrom) and node.module == "aivs_server.db":
            engine_aliases |= {alias.asname or alias.name for alias in node.names}
        if isinstance(node, ast.Import):
            engine_aliases |= {
                alias.asname or alias.name for alias in node.names if alias.name == ENGINE_MODULE
            }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in STAFF_ENTRY_POINTS
            and isinstance(node.value, ast.Name)
            and node.value.id in engine_aliases
        ):
            yield node.attr


def _reaching_modules() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted(SOURCE.rglob("*.py")):
        names = set(_names_from_engine(ast.parse(path.read_text(encoding="utf-8"))))
        if names:
            found[path.relative_to(SOURCE).as_posix()] = names
    return found


def test_only_the_named_modules_can_open_the_staff_login():
    unexplained = {
        module: sorted(names)
        for module, names in _reaching_modules().items()
        if module not in ALLOWED
    }
    assert unexplained == {}, (
        "a module that can open a staff session, which a member's request might reach; "
        "read it through services/member_staff_reads.py, keyed on the caller's organisation, "
        "or say here why it is safe"
    )


def test_every_allowed_module_still_opens_one():
    """An entry no longer needed is a hole left open for the next module to use."""
    assert set(_reaching_modules()) == set(ALLOWED)


def test_an_import_from_another_spelling_is_caught():
    """The scan is only as good as the spellings it knows; each is proved to be seen."""
    spellings = (
        "from aivs_server.db.engine import get_sessionmaker",
        "from aivs_server.db import engine\nengine.session_scope()",
        "import aivs_server.db.engine as e\ne._sessionmaker",
    )
    for source in spellings:
        assert set(_names_from_engine(ast.parse(source))), source
