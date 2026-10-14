"""Every requirement row is pinned by a test, and every pin names a row (NFR-M3).

``docs/security-requirements.md`` and ``docs/non-functional-requirements.md``
list properties the system holds today. A row is only worth reading if a test
would fail when the property stopped holding, so each row's id is applied as a
``requirement`` marker on the tests that prove it, and this module checks both
directions: a row nobody pins reads as enforced and is not; a pin naming no
row is a test whose purpose nobody can look up.

The census is a real collection of the whole suite, in a subprocess, rather
than a grep for the marker text. A grep counts a marker on a test that is
skipped, or in a file pytest never collects; what matters is what the suite
actually runs. Skipped and expected-to-fail tests do not count as pins.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[3]
DOCS = (
    REPO / "docs" / "security-requirements.md",
    REPO / "docs" / "non-functional-requirements.md",
)
ROW_ID = re.compile(r"^\| (SF-\d+|NFR-[A-Z]+\d+) \|", re.MULTILINE)

#: A collection that found fewer tests than this did not see the suite, and
#: an empty census must not read as "nothing to check".
COLLECTION_FLOOR = 500

_CENSUS_PLUGIN = textwrap.dedent(
    """
    import json
    import os


    def _counts(item):
        if any(True for _ in item.iter_markers("skip")):
            return False
        if any(True for _ in item.iter_markers("xfail")):
            return False
        for marker in item.iter_markers("skipif"):
            if not marker.args or marker.args[0]:
                return False
        return True


    def pytest_collection_finish(session):
        pins = {}
        for item in session.items:
            if not _counts(item):
                continue
            for marker in item.iter_markers("requirement"):
                for requirement_id in marker.args:
                    pins.setdefault(requirement_id, []).append(item.nodeid)
        census = {"collected": len(session.items), "pins": pins}
        with open(os.environ["REQUIREMENT_CENSUS"], "w", encoding="utf-8") as out:
            json.dump(census, out)
    """
)


@pytest.fixture(scope="module")
def census(tmp_path_factory) -> dict[str, Any]:
    """Collect the whole suite once and return what each requirement id is pinned by."""
    workdir = tmp_path_factory.mktemp("census")
    (workdir / "requirement_census.py").write_text(_CENSUS_PLUGIN, encoding="utf-8")
    result_path = workdir / "census.json"
    env = {
        **os.environ,
        "PYTHONPATH": os.pathsep.join(filter(None, [str(workdir), os.environ.get("PYTHONPATH")])),
        "REQUIREMENT_CENSUS": str(result_path),
    }
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "requirement_census"],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout[-2000:] + completed.stderr[-2000:]
    census: dict[str, Any] = json.loads(result_path.read_text(encoding="utf-8"))
    return census


def documented_ids() -> list[str]:
    return [match for doc in DOCS for match in ROW_ID.findall(doc.read_text(encoding="utf-8"))]


@pytest.mark.requirement("NFR-M3")
def test_the_census_saw_the_whole_suite(census):
    assert census["collected"] >= COLLECTION_FLOOR, census["collected"]


@pytest.mark.requirement("NFR-M3")
def test_every_documented_requirement_is_pinned_by_a_collected_test(census):
    unpinned = sorted(set(documented_ids()) - set(census["pins"]))
    assert not unpinned, f"rows with no collected, unskipped test: {unpinned}"


@pytest.mark.requirement("NFR-M3")
def test_every_pin_names_a_documented_requirement(census):
    undocumented = {
        requirement_id: nodes
        for requirement_id, nodes in census["pins"].items()
        if requirement_id not in set(documented_ids())
    }
    assert not undocumented, f"markers naming no row: {undocumented}"


@pytest.mark.requirement("NFR-M3")
def test_each_requirement_is_one_row_in_one_document():
    ids = documented_ids()
    duplicated = sorted({requirement_id for requirement_id in ids if ids.count(requirement_id) > 1})
    assert not duplicated, duplicated
