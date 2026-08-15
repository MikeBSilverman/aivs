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
from sqlalchemy import func, select

from aivs_schemas.enums import OrgStatus, OrgType
from aivs_server.db.models import SubmissionTransition
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

#: The portal is a browser surface and refuses differently from the machine
#: surface: an unauthenticated GET redirects to the sign-in page rather than
#: returning 401, because a 401 in a browser is a dead end rather than a
#: recovery. That difference is asserted explicitly further down rather than
#: exempted here, so "the portal is allowed to behave differently" cannot
#: quietly become "the portal is not checked".
PORTAL_PREFIX = "/portal"


def machine_routes(app: Any) -> list[tuple[str, str]]:
    """Every route on the machine-facing surface: API and TAXII."""
    return sorted(
        {
            (path, method)
            for path, method in walk_routes(app.routes)
            if not path.startswith(PORTAL_PREFIX) and (path, method) not in EXPECTED_PUBLIC
        }
    )


def portal_routes(app: Any) -> list[tuple[str, str]]:
    return sorted(
        {
            (path, method)
            for path, method in walk_routes(app.routes)
            if path.startswith(PORTAL_PREFIX)
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
    # Deduplicated, because every consuming test iterates `set(walk_routes(...))`.
    # Counting the raw list would let a walker that descends both
    # `original_router` and `routes` return the same handful of routes many
    # times, satisfy this guard, and leave the matrix testing almost nothing.
    routes = set(walk_routes(app.routes))
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
        for path, method in machine_routes(app):
            response = await anonymous.request(method, concrete(path), json={})
            if response.status_code != 401:
                reachable.append(f"{method} {path} -> {response.status_code}")

    assert not reachable, "these routes answered an unauthenticated request:\n  " + "\n  ".join(
        reachable
    )


async def test_public_routes_are_exactly_the_intended_set(app):
    """The public set is EXACTLY `EXPECTED_PUBLIC` -- both directions.

    The previous version of this test collected only routes that were public but
    unlisted, which is logically identical to the test above it. It therefore
    could not detect the other failure: a listed route that stops being public,
    is deleted, or lingers in the list after removal. `/healthz` and `/readyz`
    are the orchestrator's liveness contract, and nothing else in the suite
    calls them.
    """
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    actually_public: set[tuple[str, str]] = set()

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as anonymous:
        for path, method in sorted(set(walk_routes(app.routes))):
            if path.startswith(PORTAL_PREFIX):
                continue
            response = await anonymous.request(method, concrete(path), json={})
            if response.status_code != 401:
                actually_public.add((path, method))

    assert actually_public == set(EXPECTED_PUBLIC), (
        "the set of routes reachable without credentials has changed.\n"
        f"  newly public : {sorted(actually_public - set(EXPECTED_PUBLIC))}\n"
        f"  no longer public: {sorted(set(EXPECTED_PUBLIC) - actually_public)}"
    )


async def test_the_health_probes_actually_answer(client):
    """The orchestrator contract, which nothing else exercises.

    A liveness probe that started returning 401 would take the instance out of
    rotation on every deployment, and until now no test would have noticed.
    """
    liveness = await client.get("/healthz")
    assert liveness.status_code == 200
    assert liveness.json()["status"] == "ok"

    readiness = await client.get("/readyz")
    assert readiness.status_code == 200
    assert readiness.json()["database"] == "ok"


async def test_a_valid_certificate_from_a_suspended_org_reaches_nothing(app, make_org, make_cert):
    """Suspension is a single field change that closes the whole surface."""
    org = await make_org("suspended-firm", status=OrgStatus.SUSPENDED)
    pem, _ = await make_cert(org)

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    reachable: list[str] = []

    async with AsyncClient(transport=transport, base_url="https://aivs.test") as suspended:
        for path, method in machine_routes(app):
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
            # 403 is the correct refusal; 404 is acceptable only where the
            # resource genuinely does not exist. Anything else -- a 2xx, but also
            # a 422 from body drift or a 500 -- means this test is not proving
            # what it claims, so it is reported too.
            if response.status_code not in (403, 404):
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
        for path, method in machine_routes(app):
            response = await forger.request(
                method,
                concrete(path),
                json={},
                headers=proxy_headers(pem, proxy_secret=TEST_PROXY_SECRET + "-wrong"),
            )
            if response.status_code != 401:
                reachable.append(f"{method} {path} -> {response.status_code}")

    assert not reachable, "requests without the proxy secret reached:\n  " + "\n  ".join(reachable)


# ---------------------------------------------------------------------------
# The portal surface
# ---------------------------------------------------------------------------
async def test_no_portal_route_serves_content_without_a_session(app):
    """The portal refuses differently, but it does refuse.

    A browser gets a redirect to the sign-in page rather than a 401, because a
    401 leaves a person with nowhere to go. What must hold either way is that
    nothing renders authenticated content and nothing performs an action. The
    only page that may return 200 is the sign-in form itself.
    """
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    served: list[str] = []

    async with AsyncClient(
        transport=transport, base_url="https://aivs.test", follow_redirects=False
    ) as anonymous:
        for path, method in portal_routes(app):
            response = await anonymous.request(method, concrete(path), data={})

            if path == "/portal/login":
                # GET renders the form; POST is refused for want of credentials.
                if method == "GET" and response.status_code != 200:
                    served.append(f"{method} {path} -> {response.status_code}")
                if method == "POST" and response.status_code < 400:
                    served.append(f"{method} {path} -> {response.status_code}")
                continue

            # Everything else: a redirect to sign in, or a refusal. Never 2xx.
            if response.status_code < 300:
                served.append(f"{method} {path} -> {response.status_code}")
            if 300 <= response.status_code < 400:
                target = response.headers.get("location", "")
                if not target.startswith("/portal/login"):
                    served.append(f"{method} {path} redirected to {target!r}")

    assert not served, (
        "these portal routes served content or acted without a session:\n  " + "\n  ".join(served)
    )


async def test_the_sign_in_page_leaks_nothing_about_members(app):
    """The one anonymous-reachable portal page must be inert.

    It names the instance, which the caller already reached, and nothing else.
    """
    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    async with AsyncClient(transport=transport, base_url="https://aivs.test") as anonymous:
        response = await anonymous.get("/portal/login")

    assert response.status_code == 200
    body = response.text.lower()
    for leaked in ("meridian", "section9", "submission--", "vulnerability--", "circle"):
        assert leaked not in body, f"the sign-in page mentions {leaked!r}"


async def test_a_portal_action_without_a_session_changes_nothing(app, session):
    """A POST to a workflow verb with no session must not act.

    The redirect is the visible behaviour; the property that matters is the
    absence of a write.
    """
    before = await session.scalar(select(func.count()).select_from(SubmissionTransition))

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    async with AsyncClient(
        transport=transport, base_url="https://aivs.test", follow_redirects=False
    ) as anonymous:
        await anonymous.post(
            f"/portal/submissions/{_PATH_VALUES['submission_id']}/validate",
            data={"csrf_token": "forged"},
        )

    after = await session.scalar(select(func.count()).select_from(SubmissionTransition))
    assert after == before
