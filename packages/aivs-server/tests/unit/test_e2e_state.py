"""The e2e opt-in: unset skips, a state file runs, anything else is an error.

Pointed at the state directory, the e2e run once skipped all 42 tests and
exited 0, which reads exactly like a green run.
"""

from __future__ import annotations

import pytest

from tests.e2e.stack import state_path


def test_unset_means_no_stack():
    assert state_path("") is None


def test_a_state_file_is_the_stack(tmp_path):
    state = tmp_path / "state.json"
    state.write_text("{}", encoding="utf-8")
    assert state_path(str(state)) == state


@pytest.mark.parametrize("name", [".", "missing.json"])
def test_set_to_anything_but_a_file_is_refused(tmp_path, name):
    with pytest.raises(pytest.UsageError, match="is not a file"):
        state_path(str(tmp_path / name))
