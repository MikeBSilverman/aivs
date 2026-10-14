"""The index-column migration backfills rows stored before it, by the ingest rules.

A column a reader filters on has to equal ``raw`` for every row, not only those
written after the column existed, or the reader silently misses old content.
This migrates a scratch database to the revision before the index columns,
stores rows the way the previous release could have, runs the migration, and
reads the columns back.
"""

from __future__ import annotations

import datetime as dt
import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

from tests.conftest import TEST_DATABASE_URL, TEST_SECRET_KEY_FILE

pytestmark = [pytest.mark.db, pytest.mark.slow]

ALEMBIC_INI = Path(__file__).resolve().parents[2] / "alembic.ini"
INDEX_REVISION = "1e2fc8ecb375"

INDICATOR = {
    "type": "indicator",
    "pattern_type": "sigma",
    "valid_until": "2027-02-01T12:30:45.123456Z",
}
UNPARSEABLE_INDICATOR = {"type": "indicator", "pattern_type": "stix", "valid_until": "soon"}
VULNERABILITY = {
    "type": "vulnerability",
    "external_references": [
        {"source_name": "cwe", "external_id": "CWE-306"},
        {"source_name": "cve", "external_id": "CVE-2026-1"},
        {"source_name": "cwe", "external_id": "CWE-287"},
        {"source_name": "cwe", "external_id": "CWE-306"},
    ],
}
PLAIN_VULNERABILITY = {"type": "vulnerability"}


@pytest.fixture(scope="module")
def config() -> Iterator[Config]:
    test_url = make_url(TEST_DATABASE_URL)
    scratch = f"{test_url.database}_index_backfill"
    admin = create_engine(test_url.set(database="postgres"), isolation_level="AUTOCOMMIT")
    with admin.connect() as connection:
        connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        connection.execute(text(f'CREATE DATABASE "{scratch}"'))
    url = test_url.set(database=scratch).render_as_string(hide_password=False)
    names = (
        "AIVS_DATABASE_URL",
        "AIVS_MIGRATION_DATABASE_URL",
        "AIVS_SECRET_ENCRYPTION_KEY",
        "AIVS_SECRET_ENCRYPTION_KEY_FILE",
    )
    saved = {name: os.environ.get(name) for name in names}
    os.environ["AIVS_DATABASE_URL"] = url
    os.environ["AIVS_MIGRATION_DATABASE_URL"] = url
    os.environ.pop("AIVS_SECRET_ENCRYPTION_KEY", None)
    os.environ["AIVS_SECRET_ENCRYPTION_KEY_FILE"] = str(TEST_SECRET_KEY_FILE)
    try:
        yield Config(str(ALEMBIC_INI))
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        with admin.connect() as connection:
            connection.execute(text(f'DROP DATABASE IF EXISTS "{scratch}" WITH (FORCE)'))
        admin.dispose()


def _store(url: str, raws: dict[str, dict[str, Any]]) -> None:
    """Rows as the previous release stored them: raw only, no index columns."""
    engine = create_engine(url)
    with engine.begin() as connection:
        org = connection.execute(
            text(
                "INSERT INTO organizations (name, slug, org_type, status, stix_identity_id) "
                "VALUES ('Old', 'old-member', 'gsib', 'active', "
                "'identity--0f9c0000-0000-4000-8000-0000000000aa') RETURNING id"
            )
        ).scalar_one()
        submission = connection.execute(
            text(
                "INSERT INTO submissions (submitter_org_id, state, tlp, discovery_scope, "
                "distribute_anonymously, title) VALUES (:org, 'draft', 'amber', 'own_product', "
                "false, 'Old filing') RETURNING id"
            ),
            {"org": org},
        ).scalar_one()
        stamp = dt.datetime(2026, 8, 1, tzinfo=dt.UTC)
        for stix_id, raw in raws.items():
            connection.execute(
                text(
                    "INSERT INTO stix_objects (stix_id, modified, created, type, spec_version, "
                    "submission_id, raw) VALUES (:stix_id, :stamp, :stamp, :type, '2.1', "
                    ":submission, CAST(:raw AS jsonb))"
                ),
                {
                    "stix_id": stix_id,
                    "stamp": stamp,
                    "type": raw["type"],
                    "submission": submission,
                    "raw": json.dumps(raw),
                },
            )
    engine.dispose()


def _columns(url: str) -> dict[str, dict[str, Any]]:
    engine = create_engine(url)
    with engine.connect() as connection:
        rows = connection.execute(
            text("SELECT stix_id, pattern_type, valid_until, cwe_ids FROM stix_objects")
        ).mappings()
        found = {row["stix_id"]: dict(row) for row in rows}
    engine.dispose()
    return found


@pytest.mark.requirement("NFR-M2")
def test_existing_rows_get_the_values_ingest_would_have_given_them(config: Config):
    previous = ScriptDirectory.from_config(config).get_revision(INDEX_REVISION).down_revision
    assert isinstance(previous, str), "the index revision must have a single parent"
    command.upgrade(config, previous)
    url = os.environ["AIVS_MIGRATION_DATABASE_URL"]
    _store(
        url,
        {
            "indicator--old": INDICATOR,
            "indicator--unparseable": UNPARSEABLE_INDICATOR,
            "vulnerability--old": VULNERABILITY,
            "vulnerability--plain": PLAIN_VULNERABILITY,
        },
    )

    command.upgrade(config, INDEX_REVISION)
    columns = _columns(url)

    assert columns["indicator--old"]["pattern_type"] == "sigma"
    assert columns["indicator--old"]["valid_until"] == dt.datetime(
        2027, 2, 1, 12, 30, 45, 123000, tzinfo=dt.UTC
    )
    assert columns["indicator--unparseable"]["pattern_type"] == "stix"
    assert columns["indicator--unparseable"]["valid_until"] is None
    assert columns["vulnerability--old"]["cwe_ids"] == ["CWE-306", "CWE-287"]
    assert columns["vulnerability--plain"]["cwe_ids"] is None
    assert columns["vulnerability--old"]["pattern_type"] is None
