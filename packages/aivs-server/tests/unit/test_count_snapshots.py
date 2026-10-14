"""When published counts may change: only once K organisations differ (R2-C1).

The rule is a pure function of two bases, so it is tested as a table. The
database half (one snapshot per subject, replaced in place, and an offboarded
organisation removed from every basis) is tested against Postgres.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aivs_server.db.models import CountSnapshot, CountSubject
from aivs_server.services.count_snapshots import (
    K_ANONYMITY,
    changed_organisations,
    forget_organisation,
    publish_if_changed,
    published,
    should_publish,
)

FIRMS = [f"org-{index}" for index in range(3 * K_ANONYMITY)]
NOW = dt.datetime(2026, 10, 14, 12, tzinfo=dt.UTC)


def _basis(statuses: list[str]) -> dict[str, str]:
    return dict(zip(FIRMS, statuses, strict=False))


SPLIT = _basis(["affected"] * K_ANONYMITY + ["fixed"] * K_ANONYMITY)


@pytest.mark.parametrize(
    ("old", "new", "publish"),
    [
        pytest.param(None, _basis(["affected"] * (K_ANONYMITY - 1)), False, id="first, below K"),
        pytest.param(None, _basis(["affected"] * K_ANONYMITY), True, id="first, at K"),
        pytest.param(SPLIT, SPLIT, False, id="nothing changed"),
        pytest.param(
            SPLIT,
            _basis(["fixed"] * (K_ANONYMITY - 1) + ["affected"] + ["fixed"] * K_ANONYMITY),
            False,
            id="K-1 firms changed",
        ),
        pytest.param(SPLIT, _basis(["fixed"] * (2 * K_ANONYMITY)), True, id="K firms changed"),
        pytest.param(
            SPLIT,
            {key: value for key, value in SPLIT.items() if key != FIRMS[0]},
            False,
            id="one firm left (suspended, offboarded)",
        ),
        pytest.param(
            SPLIT,
            SPLIT | {f"joined-{index}": "fixed" for index in range(K_ANONYMITY)},
            True,
            id="K firms joined",
        ),
    ],
)
@pytest.mark.requirement("SF-80")
def test_a_snapshot_is_replaced_only_once_k_firms_differ(old, new, publish):
    assert should_publish(old, new) is publish


@pytest.mark.requirement("SF-80")
def test_firms_that_swap_statuses_are_changes_though_no_total_moves():
    """Comparing totals would see nothing here; it is 2K changes, and enough."""
    swapped = {
        key: ("fixed" if value == "affected" else "affected") for key, value in SPLIT.items()
    }

    assert changed_organisations(SPLIT, swapped) == 2 * K_ANONYMITY
    assert should_publish(SPLIT, swapped)


@pytest.mark.db
@pytest.mark.requirement("SF-80")
async def test_a_published_snapshot_is_kept_until_k_firms_differ(session):
    subject = "vulnerability--00000000-0000-4000-8000-000000000001"
    assert await publish_if_changed(session, CountSubject.POSTURE, subject, SPLIT, now=NOW)
    one_changed = SPLIT | {FIRMS[0]: "fixed"}
    later = NOW + dt.timedelta(days=1)

    republished = await publish_if_changed(
        session, CountSubject.POSTURE, subject, one_changed, now=later
    )
    await session.commit()

    assert republished is False
    kept = await published(session, CountSubject.POSTURE, subject)
    assert kept is not None
    assert (dict(kept.basis), kept.taken_at) == (SPLIT, NOW)


@pytest.mark.db
@pytest.mark.requirement("SF-80")
async def test_offboarding_removes_an_organisation_from_every_basis(session):
    for kind, subject in (
        (CountSubject.POSTURE, "vulnerability--a"),
        (CountSubject.TELEMETRY, "s"),
    ):
        session.add(
            CountSnapshot(subject_kind=kind.value, subject_id=subject, taken_at=NOW, basis=SPLIT)
        )
    await session.commit()

    await forget_organisation(session, FIRMS[0])
    await session.commit()

    for kind, subject in (
        (CountSubject.POSTURE, "vulnerability--a"),
        (CountSubject.TELEMETRY, "s"),
    ):
        kept = await published(session, kind, subject)
        assert kept is not None
        assert FIRMS[0] not in kept.basis
        assert len(kept.basis) == len(SPLIT) - 1
