"""Every table declares a data class (plan, exit criterion 3; NFR-S10).

The class decides protection and what happens on offboarding, and the
inventory is what a member's third-party-risk review reads. A table that lands
without a row here would be stored without anyone having decided either.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from aivs_server.db import models  # noqa: F401 - registers every table on Base.metadata
from aivs_server.db.base import Base

INVENTORY = Path(__file__).resolve().parents[4] / "docs" / "data-inventory.md"
CLASSES = frozenset({"content", "pii", "evidence", "operational"})
#: A table name, schema-qualified where the table is outside ``public``
#: (``attribution.submitters``): a narrower pattern silently skipped those rows,
#: and the test then passed while ignoring them.
_ROW = re.compile(r"^\| `(?P<table>[a-z_]+(?:\.[a-z_]+)?)` \| (?P<cls>[a-z]+) \|", re.MULTILINE)


def _declared() -> dict[str, str]:
    return {m["table"]: m["cls"] for m in _ROW.finditer(INVENTORY.read_text(encoding="utf-8"))}


@pytest.mark.requirement("NFR-S10")
def test_every_mapped_table_is_classified_and_nothing_else_is():
    declared = _declared()
    mapped = set(Base.metadata.tables)

    assert mapped - set(declared) == set(), "tables with no data class"
    assert set(declared) - mapped == set(), "classified tables that no longer exist"


@pytest.mark.requirement("NFR-S10")
def test_every_class_used_is_one_the_inventory_defines():
    used = set(_declared().values())
    assert used <= CLASSES, f"undefined classes: {used - CLASSES}"
    defined = set(re.findall(r"^\| `([a-z]+)` \| ", INVENTORY.read_text(encoding="utf-8"), re.M))
    assert defined >= CLASSES, "a class is used in the code's list but not defined in the doc"
