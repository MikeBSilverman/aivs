"""Who filed what is read through one module, and nothing else reads it (Phase P).

The submitter of a submission is ISAC-only and treated as TLP:RED (Mike, Q16
and Q37). ``services/attribution.py`` is the one place that reads or writes
it, so what can reach the mapping is one file a reviewer can read, not thirty
modules that each asked in their own way. A new reader written anywhere else
-- an attribute read, a constructor argument, a hand-written query naming the
schema -- fails here rather than in a review.

Parsed, not grepped: a comment or a docstring that mentions a column is not a
reader, and a reader spelt across two lines is still one.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]
#: Where application code lives. Tests and migrations are left out: a test
#: builds the rows it reads, and a migration moves them.
SCANNED = (REPO / "packages" / "aivs-server" / "src", REPO / "demo", REPO / "scripts")
#: The module that owns the mapping, and the model that declares it.
OWNERS = frozenset(
    {
        REPO / "packages/aivs-server/src/aivs_server/services/attribution.py",
        REPO / "packages/aivs-server/src/aivs_server/db/models.py",
    }
)
#: Who filed a submission, for whom, and on what consent.
FILING_COLUMNS = frozenset(
    {"submitter_org_id", "created_by_operator_id", "filed_by_operator_id", "proxy_consent_sha256"}
)
SCHEMA_PREFIX = "attribution."


def _sources() -> Iterator[Path]:
    for root in SCANNED:
        for path in sorted(root.rglob("*.py")):
            if path not in OWNERS:
                yield path


def _filing_column_reads(tree: ast.AST) -> Iterator[ast.Attribute]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in FILING_COLUMNS:
            yield node


def _submission_constructed_with_filer(tree: ast.AST) -> Iterator[ast.Call]:
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Submission"
            and any(keyword.arg in FILING_COLUMNS for keyword in node.keywords)
        ):
            yield node


def _sql_naming_the_schema(tree: ast.AST) -> Iterator[ast.Constant]:
    """String literals that name the schema, as hand-written SQL would.

    Docstrings are statements of their own, not values used by the code, so
    they are not counted.
    """
    docstrings = {
        id(node.body[0].value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
    }
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and SCHEMA_PREFIX in node.value
            and id(node) not in docstrings
        ):
            yield node


def _offences(check) -> list[str]:
    found = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        found.extend(f"{path.relative_to(REPO)}:{node.lineno}" for node in check(tree))
    return found


@pytest.mark.requirement("SF-88")
def test_nothing_outside_the_attribution_module_reads_who_filed_a_submission():
    assert _offences(_filing_column_reads) == []


@pytest.mark.requirement("SF-88")
def test_nothing_outside_the_attribution_module_records_who_filed_a_submission():
    assert _offences(_submission_constructed_with_filer) == []


@pytest.mark.requirement("SF-88")
def test_no_hand_written_query_names_the_attribution_schema():
    assert _offences(_sql_naming_the_schema) == []


def test_the_checks_find_what_they_are_for():
    """Each check refuses the shape it exists to refuse, so a green run means
    the code is clean rather than that the parser saw nothing."""
    tree = ast.parse(
        "x = submission.submitter_org_id\n"
        "Submission(created_by_operator_id=None)\n"
        'text("SELECT org_id FROM attribution.submitters")\n'
        'def f():\n    """Reads attribution.submitters, in prose."""\n'
    )

    assert len(list(_filing_column_reads(tree))) == 1
    assert len(list(_submission_constructed_with_filer(tree))) == 1
    assert len(list(_sql_naming_the_schema(tree))) == 1
