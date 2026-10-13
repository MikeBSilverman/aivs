"""The test harness's own assumptions, checked (Appendix F.9).

A hand-kept list of tables to truncate that misses a new one leaks rows from one
test into the next -- an order-dependent flake under pytest-randomly, or worse,
a test that passes only because an earlier one left state behind.
"""

from __future__ import annotations

from aivs_server.db.base import Base
from tests.conftest import _ALL_TABLES


def test_every_table_is_truncated_between_tests():
    assert set(_ALL_TABLES) == set(Base.metadata.tables)
