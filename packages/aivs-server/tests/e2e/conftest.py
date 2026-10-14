"""Fixtures for the end-to-end tests.

These tests reach the stack only through its published port and ``docker``.
They never touch the suite's own database, so the parent conftest's autouse
``clean_database`` -- which truncates ``aivs_test`` after every test -- is
replaced here by a fixture that does nothing. Without the override an e2e run
would need the unit-test database and would empty it.
"""

from __future__ import annotations

import pytest

from tests.e2e.stack import Stack, load_stack


@pytest.fixture(autouse=True)
def clean_database() -> None:
    return None


@pytest.fixture(scope="session")
def stack() -> Stack:
    return load_stack()


@pytest.fixture(scope="session")
def isac_bearer(stack: Stack) -> dict[str, str]:
    return stack.isac_bearer()
