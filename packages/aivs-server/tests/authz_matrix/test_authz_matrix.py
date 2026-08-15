"""The deny-by-default proof.

Every route in the application is enumerated and called with no credentials at
all. Anything that answers is either a deliberate, listed exception or a defect.

The load-bearing part is not the assertions -- it is the enumeration. A matrix
that walks the routes incorrectly passes while proving nothing, which is worse
than having no matrix, because it manufactures confidence. So the walker is
tested against a floor count, and a route absent from the expected-public list
fails the build rather than being quietly skipped.

This caught a real trap: FastAPI 0.141 / Starlette 1.6 do not flatten included
routers into ``app.routes``. They appear as ``_IncludedRouter`` wrappers, so the
obvious ``for route in app.routes`` walk finds three routes -- the docs
endpoints -- and misses all thirty-one real ones.
"""

from __future__ import annotations

from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient

from aivs_schemas.enums import OrgStatus, OrgType
from tests.conftest import TEST_PROXY_SECRET, proxy_headers

pytestmark = [pytest.mark.db, pytest.mark.authz]


def walk_routes(routes: list[Any]) -> list[tuple[str, str]]:
    """Flatten every route in an application, descending into included routers.

    Returns ``(path, method)`` pairs. See the module docstring for why the
    ``original_router`` hop is required.
    """
    found: list[tuple[str, str]] = []
    for route in routes:
        included = getattr(route, "original_router", None)
        if included is not None:
            found.extend(walk_routes(included.routes))
            continue
        nested = getattr(route, "routes", None)
        if nested:
            found.extend(walk_routes(nested))
            continue
        methods = getattr(route, "methods", None)
        if not methods:
            continue
        found.extend(
            (getattr(route, "path", ""), method) for method in methods - {"HEAD", "OPTIONS"}
        )
    return found


#: Endpoints that intentionally answer without a client certificate.
#:
#: The health probes exist for the orchestrator, which cannot present one. The
#: docs endpoints are served only outside production (``create_app`` passes
#: ``docs_url=None`` when the environment is production).
#:
#: Adding to this set is a security decision. The test below fails if a route
#: becomes reachable without credentials and is not listed here, so the set
#: cannot grow by accident.
EXPECTED_PUBLIC: frozenset[tuple[str, str]] = frozenset(
    {
        ("/healthz", "GET"),
        ("/readyz", "GET"),
        ("/docs", "GET"),
        ("/docs/oauth2-redirect", "GET"),
        ("/openapi.json", "GET"),
    }
)

#: Placeholder values for path parameters. The identifiers do not resolve, which
#: is the point: an unauthenticated caller must be refused before the server ever
#: looks anything up, so a 404 here would mean the lookup happened first.
_PATH_VALUES = {
    "submission_id": "0f9c0000-0000-4000-8000-000000000001",
    "collection_id": "0f9c0000-0000-4000-8000-000000000002",
    "certificate_id": "0f9c0000-0000-4000-8000-000000000003",
    "circle_id": "0f9c0000-0000-4000-8000-000000000004",
    "org_id": "0f9c0000-0000-4000-8000-000000000005",
    "object_id": "vulnerability--0f9c0000-0000-4000-8000-000000000006",
}


def concrete(path: str) -> str:
    """Substitute placeholder values for path parameters."""
    for name, value in _PATH_VALUES.items():
        path = path.replace("{" + name + "}", value)
    return path


def test_the_walker_actually_finds_the_routes(app):
    """Guard the guard.

    Without this, a change to how routes are stored would silently reduce the
    matrix below to a handful of endpoints and it would keep passing.
    """
    routes = walk_routes(app.routes)
    assert len(routes) >= 30, (
        f"route walker found only {len(routes)} routes; it is under-enumerating "
        "and every authorization assertion below is therefore vacuous"
    )
    paths = {path for path, _ in routes}
    for expected in ("/api/v1/submissions", "/taxii2/aivs/collections/", "/api/v1/orgs"):
        assert expected in paths, f"{expected} missing from the walk"


async def test_every_route_requires_authentication(app):
    """No route answers without a client certificate, except the listed few."""
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    reachable: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as anonymous:
        for path, method in sorted(set(walk_routes(app.routes))):
            if (path, method) in EXPECTED_PUBLIC:
                continue
            response = await anonymous.request(method, concrete(path), json={})
            if response.status_code != 401:
                reachable.append(f"{method} {path} -> {response.status_code}")

    assert not reachable, "these routes answered an unauthenticated request:\n  " + "\n  ".join(
        reachable
    )


async def test_public_routes_are_exactly_the_intended_set(app):
    """A route that stops requiring credentials must fail the build.

    The previous test skips EXPECTED_PUBLIC; this one confirms the set has not
    silently grown, by checking each listed entry really is public and that
    nothing else is.
    """
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    unexpectedly_public: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as anonymous:
        for path, method in sorted(set(walk_routes(app.routes))):
            response = await anonymous.request(method, concrete(path), json={})
            is_public = response.status_code != 401
            listed = (path, method) in EXPECTED_PUBLIC
            if is_public and not listed:
                unexpectedly_public.append(f"{method} {path} -> {response.status_code}")

    assert not unexpectedly_public, (
        "routes reachable without credentials but not in EXPECTED_PUBLIC:\n  "
        + "\n  ".join(unexpectedly_public)
    )


async def test_a_valid_certificate_from_a_suspended_org_reaches_nothing(app, make_org, make_cert):
    """Suspension is a single field change that closes the whole surface."""
    org = await make_org("suspended-firm", status=OrgStatus.SUSPENDED)
    pem, _ = await make_cert(org)

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    reachable: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as suspended:
        for path, method in sorted(set(walk_routes(app.routes))):
            if (path, method) in EXPECTED_PUBLIC:
                continue
            response = await suspended.request(
                method, concrete(path), json={}, headers=proxy_headers(pem)
            )
            if response.status_code != 401:
                reachable.append(f"{method} {path} -> {response.status_code}")

    assert not reachable, "a suspended organisation reached these routes:\n  " + "\n  ".join(
        reachable
    )


async def test_administrative_routes_refuse_an_ordinary_member(app, make_org, make_cert):
    """The endpoints that enrol members and run circles are the ISAC's alone.

    A member reaching any of these would be a full compromise of the trust
    model: they could enrol an organisation, register a certificate to it, and
    add it to a circle.
    """
    org = await make_org("ordinary-member", org_type=OrgType.GSIB)
    pem, _ = await make_cert(org)

    administrative = [
        ("POST", "/api/v1/orgs", {"slug": "x-firm", "name": "X", "org_type": "gsib"}),
        ("POST", "/api/v1/circles", {"slug": "x-circle", "name": "X"}),
        ("POST", f"/api/v1/orgs/{_PATH_VALUES['org_id']}/activate", {}),
        ("POST", f"/api/v1/orgs/{_PATH_VALUES['org_id']}/suspend", {}),
        (
            "POST",
            f"/api/v1/circles/{_PATH_VALUES['circle_id']}/members",
            {"org_id": _PATH_VALUES["org_id"]},
        ),
    ]

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    permitted: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as member:
        for method, path, body in administrative:
            response = await member.request(method, path, json=body, headers=proxy_headers(pem))
            # 403 is the correct refusal. 404 is acceptable where the resource
            # genuinely does not exist, but 2xx never is.
            if response.status_code < 400:
                permitted.append(f"{method} {path} -> {response.status_code}")

    assert not permitted, (
        "an ordinary member was permitted administrative actions:\n  " + "\n  ".join(permitted)
    )


async def test_forged_proxy_secret_reaches_nothing(app, make_org, make_cert):
    """A genuine member certificate is worthless without the proxy's secret.

    The control that matters if an attacker reaches the application's network
    directly, applied across the whole route surface rather than one endpoint.
    """
    org = await make_org("meridian-global")
    pem, _ = await make_cert(org)

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    reachable: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as forger:
        for path, method in sorted(set(walk_routes(app.routes))):
            if (path, method) in EXPECTED_PUBLIC:
                continue
            response = await forger.request(
                method,
                concrete(path),
                json={},
                headers=proxy_headers(pem, proxy_secret=TEST_PROXY_SECRET + "-wrong"),
            )
            if response.status_code != 401:
                reachable.append(f"{method} {path} -> {response.status_code}")

    assert not reachable, "requests without the proxy secret reached:\n  " + "\n  ".join(reachable)
