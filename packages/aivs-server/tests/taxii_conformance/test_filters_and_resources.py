"""Filter parsing and TAXII resource shapes, tested directly.

These are pure functions, so they are tested without a database or an HTTP
round trip. That matters for the version selectors in particular: ``first``,
explicit timestamps, and combinations of the two are documented TAXII surface
that no end-to-end test reached, so a member relying on them would have been the
one to discover they were broken.
"""

from __future__ import annotations

import datetime as dt

import pytest

from aivs_server.taxii import resources
from aivs_server.taxii.filters import (
    MAX_MATCH_VALUES,
    FilterError,
    VersionSelector,
    parse_filters,
)

pytestmark = pytest.mark.requirement("NFR-I1")

LIMITS = {"default_limit": 100, "max_limit": 500}


def parse(**params: list[str]):
    return parse_filters(params, **LIMITS)


# ---------------------------------------------------------------------------
# Version selectors
# ---------------------------------------------------------------------------
def test_version_defaults_to_last():
    """Absent means `last`, not `all`.

    A server defaulting to every version floods members with superseded content.
    """
    assert parse().version_selectors == frozenset({VersionSelector.LAST})


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("all", {VersionSelector.ALL}),
        ("first", {VersionSelector.FIRST}),
        ("last", {VersionSelector.LAST}),
        ("first,last", {VersionSelector.FIRST, VersionSelector.LAST}),
    ],
)
def test_version_keywords(value, expected):
    filters = parse(**{"match[version]": [value]})
    assert filters.version_selectors == frozenset(expected)


def test_explicit_version_timestamps_are_parsed():
    filters = parse(**{"match[version]": ["2026-08-01T00:00:00.000Z"]})
    assert filters.version_timestamps == (dt.datetime(2026, 8, 1, tzinfo=dt.UTC),)
    assert filters.version_selectors == frozenset()


def test_keywords_and_timestamps_combine():
    """The spec's own example: `first,<timestamp>,last`."""
    filters = parse(**{"match[version]": ["first,2026-08-01T00:00:00.000Z,last"]})
    assert filters.version_selectors == frozenset({VersionSelector.FIRST, VersionSelector.LAST})
    assert len(filters.version_timestamps) == 1


def test_all_must_not_be_combined():
    with pytest.raises(FilterError, match="must not be combined"):
        parse(**{"match[version]": ["all,last"]})


def test_a_repeated_version_value_is_refused():
    with pytest.raises(FilterError, match="repeat"):
        parse(**{"match[version]": ["last,last"]})


def test_an_unparseable_version_timestamp_is_refused():
    with pytest.raises(FilterError, match="timestamp"):
        parse(**{"match[version]": ["yesterday"]})


# ---------------------------------------------------------------------------
# Other match fields
# ---------------------------------------------------------------------------
def test_comma_separated_values_or_together():
    filters = parse(**{"match[type]": ["vulnerability,course-of-action"]})
    assert filters.types == ("vulnerability", "course-of-action")


def test_an_unknown_match_field_is_ignored():
    """Permitted by the spec, and better for interoperability than refusing."""
    filters = parse(**{"match[vendor_extension]": ["anything"]})
    assert filters.types == ()


def test_too_many_match_values_are_refused():
    """Bounded so a filter cannot push an unbounded list into a SQL IN clause."""
    values = ",".join(f"vulnerability--{i:08d}-0000-4000-8000-000000000000" for i in range(200))
    with pytest.raises(FilterError, match=str(MAX_MATCH_VALUES)):
        parse(**{"match[id]": [values]})


def test_an_empty_match_value_is_refused():
    with pytest.raises(FilterError, match="no values"):
        parse(**{"match[type]": [","]})


def test_spec_version_is_carried_through():
    filters = parse(**{"match[spec_version]": ["2.1"]})
    assert filters.spec_versions == ("2.1",)


# ---------------------------------------------------------------------------
# limit, added_after, next
# ---------------------------------------------------------------------------
def test_limit_is_capped_not_refused():
    """The spec allows returning fewer than requested; `more` tells the client."""
    assert parse(limit=["100000"]).limit == 500


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5"])
def test_a_bad_limit_is_refused(value):
    with pytest.raises(FilterError, match="limit"):
        parse(limit=[value])


def test_a_repeated_parameter_is_refused():
    """Malformed, not a union: two clients sending the same query must agree."""
    with pytest.raises(FilterError, match="exactly once"):
        parse(limit=["10", "20"])


def test_added_after_is_parsed():
    filters = parse(added_after=["2026-08-01T00:00:00.000Z"])
    assert filters.added_after == dt.datetime(2026, 8, 1, tzinfo=dt.UTC)


def test_a_date_only_added_after_is_refused():
    """TAXII timestamps carry a time and a literal Z."""
    with pytest.raises(FilterError):
        parse(added_after=["2026-08-01"])


def test_next_is_carried_through_opaquely():
    assert parse(next=["some-cursor"]).next_cursor == "some-cursor"


# ---------------------------------------------------------------------------
# Resource shapes
# ---------------------------------------------------------------------------
def test_an_empty_collections_resource_omits_the_key():
    assert resources.collections_resource([]) == {}


def test_an_empty_manifest_omits_the_key():
    assert resources.manifest_resource([]) == {}


def test_an_empty_versions_resource_omits_the_key():
    assert resources.versions_resource([]) == {}


def test_an_empty_envelope_is_empty():
    assert resources.envelope_resource([]) == {}


def test_more_without_a_cursor_is_still_valid():
    """`next` is optional even when `more` is true."""
    envelope = resources.envelope_resource([{"id": "x"}], more=True)
    assert envelope["more"] is True
    assert "next" not in envelope


def test_a_paged_envelope_carries_both():
    envelope = resources.envelope_resource([{"id": "x"}], more=True, next_cursor="abc")
    assert envelope["next"] == "abc"


def test_discovery_omits_absent_optional_properties():
    resource = resources.discovery_resource(title="AIVS", api_roots=[])
    assert resource == {"title": "AIVS"}, "only title is required"


def test_discovery_carries_its_optional_properties():
    resource = resources.discovery_resource(
        title="AIVS",
        api_roots=["https://x/taxii2/aivs/"],
        description="d",
        contact="c",
        default="https://x/taxii2/aivs/",
    )
    assert resource["default"] in resource["api_roots"]
    assert resource["contact"] == "c"


def test_api_root_requires_max_content_length():
    resource = resources.api_root_resource(title="feed", max_content_length=5_242_880)
    assert set(resource) >= {"title", "versions", "max_content_length"}
    assert resources.TAXII_MEDIA_TYPE in resource["versions"]


def test_collection_omits_absent_optional_properties():
    resource = resources.collection_resource(
        collection_id="c", title="t", can_read=True, can_write=False
    )
    assert set(resource) == {"id", "title", "can_read", "can_write"}


def test_status_carries_all_four_counts_even_when_zero():
    resource = resources.status_resource(
        status_id="s",
        status="complete",
        total_count=0,
        success_count=0,
        failure_count=0,
        pending_count=0,
    )
    assert resource["total_count"] == 0
    assert set(resource) >= {
        "id",
        "status",
        "total_count",
        "success_count",
        "failure_count",
        "pending_count",
    }


def test_status_includes_detail_lists_when_present():
    resource = resources.status_resource(
        status_id="s",
        status="complete",
        total_count=1,
        success_count=1,
        failure_count=0,
        pending_count=0,
        request_timestamp=dt.datetime(2026, 8, 1, tzinfo=dt.UTC),
        successes=[{"id": "x", "version": "v"}],
    )
    assert resource["successes"][0]["id"] == "x"
    assert resource["request_timestamp"].endswith("Z")


def test_error_resource_requires_only_a_title():
    assert resources.error_resource(title="Forbidden") == {"title": "Forbidden"}


def test_error_resource_carries_its_optional_properties():
    resource = resources.error_resource(
        title="Bad Request",
        http_status=400,
        description="d",
        error_id="e",
        error_code="c",
    )
    assert resource["http_status"] == "400"
    assert resource["error_code"] == "c"


def test_manifest_record_shape():
    record = resources.manifest_record(
        stix_id="vulnerability--x",
        date_added=dt.datetime(2026, 8, 1, tzinfo=dt.UTC),
        version="2026-08-01T00:00:00.000Z",
        media_type=resources.STIX_MEDIA_TYPE,
    )
    assert set(record) == {"id", "date_added", "version", "media_type"}


# ---------------------------------------------------------------------------
# Timestamps
# ---------------------------------------------------------------------------
def test_taxii_timestamps_carry_milliseconds_and_a_literal_z():
    rendered = resources.to_taxii_timestamp(
        dt.datetime(2026, 8, 1, 12, 30, 45, 123456, tzinfo=dt.UTC)
    )
    assert rendered == "2026-08-01T12:30:45.123Z"


def test_a_naive_timestamp_is_refused():
    """A silent timezone assumption on a member's polling cursor loses content."""
    with pytest.raises(ValueError, match="naive"):
        resources.to_taxii_timestamp(dt.datetime(2026, 8, 1))  # noqa: DTZ001 - the point


def test_truncation_matches_what_taxii_can_express():
    """Storage is microseconds; the wire is milliseconds. They must agree."""
    value = dt.datetime(2026, 8, 1, 0, 0, 0, 123999, tzinfo=dt.UTC)
    truncated = resources.truncate_to_taxii_precision(value)
    assert truncated.microsecond == 123000
    assert resources.to_taxii_timestamp(truncated) == resources.to_taxii_timestamp(value)


def test_a_non_utc_timestamp_is_normalised():
    rendered = resources.to_taxii_timestamp(
        dt.datetime(2026, 8, 1, 5, 0, 0, tzinfo=dt.timezone(dt.timedelta(hours=5)))
    )
    assert rendered == "2026-08-01T00:00:00.000Z"
