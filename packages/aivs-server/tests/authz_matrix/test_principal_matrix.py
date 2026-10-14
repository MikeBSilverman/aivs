"""The authorization matrix: every kind of caller against every class of route.

``test_authz_matrix.py`` proves the deny side at the door -- no credentials, a
forged proxy secret, a suspended organisation -- with placeholder identifiers,
so it also shows refusal comes before any lookup. It cannot say what each kind
of caller *may* do. This module can: each principal is sent to every route
against a seeded instance whose targets exist, and every answer is compared
with one expected outcome per (principal, class, surface). It fails if a role
gains a power, and equally if a role loses one it should have.

Not claims of this matrix, and never described as such: what a listing
contains (it proves a listing answers, and filtering is a clause test);
visibility within content a caller may read; audit content; and anything
behind a route that does not exist yet.
"""

from __future__ import annotations

import enum
from collections.abc import Mapping
from typing import Any

import pytest
from httpx import ASGITransport, AsyncClient, Response

from tests.authz_matrix.principals import PLANNED_PRINCIPALS, Principal
from tests.authz_matrix.routes import ROUTES, SURFACE_FLOORS, RouteCase, RouteClass
from tests.authz_matrix.test_authz_matrix import walk_routes
from tests.authz_matrix.world import Factories, build_world

pytestmark = [pytest.mark.db, pytest.mark.authz]


class Outcome(enum.StrEnum):
    ALLOWED = "allowed"
    UNAUTHENTICATED = "401"
    FORBIDDEN = "403"
    NOT_FOUND = "404"
    SIGN_IN_REDIRECT = "redirect to sign-in"


A, U, F, N, S = (
    Outcome.ALLOWED,
    Outcome.UNAUTHENTICATED,
    Outcome.FORBIDDEN,
    Outcome.NOT_FOUND,
    Outcome.SIGN_IN_REDIRECT,
)
P = Principal

#: Refused before anything else is looked at: no usable identity, or an
#: organisation that is not active. 401 on the machine surface, a redirect to
#: sign in on the portal -- the difference is asserted, not exempted.
REFUSED_AT_THE_DOOR: frozenset[Principal] = frozenset(
    {P.ANONYMOUS, P.FORGED_PROXY_SECRET, P.PENDING_ORG, P.SUSPENDED_ORG, P.QUARANTINED_ORG}
)

#: A certificate with no signed-in human. The portal needs a person, so every
#: portal route redirects these to sign in.
CERTIFICATE_ONLY: frozenset[Principal] = frozenset(
    {P.MEMBER_MACHINE, P.PEER_MACHINE, P.ADMIN_CERTIFICATE}
)

_MEMBER = (P.MEMBER_MACHINE, P.MEMBER_ANALYST, P.MEMBER_ORG_ADMIN)
_ISAC = (P.ISAC_ANALYST, P.ISAC_EDITOR, P.ISAC_MEMBERSHIP, P.SYSTEM_ADMIN)
_PAST_THE_DOOR = (*_MEMBER, P.PEER_MACHINE, P.ADMIN_CERTIFICATE, *_ISAC)


def _row(default: Outcome, **overrides: Outcome) -> dict[Principal, Outcome]:
    """One class's answers for every principal past the door."""
    by_name = {principal.name: principal for principal in _PAST_THE_DOOR}
    row = dict.fromkeys(_PAST_THE_DOOR, default)
    for name, outcome in overrides.items():
        row[by_name[name]] = outcome
    return row


def _allow(*principals: Principal, otherwise: Outcome) -> dict[Principal, Outcome]:
    row = dict.fromkeys(_PAST_THE_DOOR, otherwise)
    row.update(dict.fromkeys(principals, A))
    return row


#: What each principal past the door gets from each class. The member
#: organisation ("member") filed every submission the routes address; "peer" is
#: another member of the same circle. ISAC staff are not members of that circle.
EXPECTED: Mapping[RouteClass, Mapping[Principal, Outcome]] = {
    RouteClass.LISTING: _row(A),
    RouteClass.FILING: _row(A),
    RouteClass.OWN_SETTINGS: _row(A),
    RouteClass.HEALTH: _row(A),
    RouteClass.CIRCLE_CONTENT: _allow(*_MEMBER, P.PEER_MACHINE, otherwise=N),
    RouteClass.SUBMISSION_RECORD: _allow(*_MEMBER, P.ISAC_ANALYST, P.ISAC_EDITOR, otherwise=N),
    RouteClass.DRAFT_EDIT: {
        **_allow(*_MEMBER, otherwise=N),
        P.ISAC_ANALYST: F,
        P.ISAC_EDITOR: F,
    },
    RouteClass.WITHDRAW: {
        **_allow(*_MEMBER, P.ISAC_EDITOR, otherwise=N),
        P.ISAC_ANALYST: F,
    },
    RouteClass.RECEIPT: _allow(*_MEMBER, P.PEER_MACHINE, otherwise=N),
    RouteClass.EDITORIAL: {
        **_allow(P.ISAC_EDITOR, otherwise=N),
        **dict.fromkeys(_MEMBER, F),
        P.ISAC_ANALYST: F,
    },
    RouteClass.REVIEW_QUEUE: {
        **_allow(P.ISAC_ANALYST, P.ISAC_EDITOR, otherwise=N),
        **dict.fromkeys(CERTIFICATE_ONLY, S),
    },
    RouteClass.MEMBERSHIP: _allow(P.ISAC_MEMBERSHIP, otherwise=F),
    RouteClass.QUARANTINE: _allow(P.ISAC_MEMBERSHIP, P.ISAC_EDITOR, P.SYSTEM_ADMIN, otherwise=F),
    RouteClass.RECONNECT: _allow(P.ISAC_MEMBERSHIP, P.ISAC_EDITOR, otherwise=F),
    RouteClass.CERTIFICATE_REVOKE: _allow(P.ISAC_MEMBERSHIP, otherwise=N),
    RouteClass.CIRCLE_CREATE: _allow(P.ISAC_EDITOR, otherwise=F),
    RouteClass.CIRCLE_SCREENS: {
        **_allow(P.ISAC_EDITOR, P.ISAC_MEMBERSHIP, otherwise=F),
        **dict.fromkeys(CERTIFICATE_ONLY, S),
    },
    RouteClass.PAUSE: _allow(P.ISAC_EDITOR, P.SYSTEM_ADMIN, otherwise=F),
    RouteClass.RESUME: _allow(P.ISAC_EDITOR, otherwise=F),
    RouteClass.STATUS_PAGE: {
        **_allow(P.SYSTEM_ADMIN, P.ISAC_MEMBERSHIP, otherwise=F),
        **dict.fromkeys(CERTIFICATE_ONLY, S),
    },
    RouteClass.WEBHOOK_REGISTER: _allow(
        P.MEMBER_MACHINE, P.MEMBER_ORG_ADMIN, P.PEER_MACHINE, P.SYSTEM_ADMIN, otherwise=F
    ),
    RouteClass.WEBHOOK_DELETE: {
        **_allow(P.MEMBER_MACHINE, P.MEMBER_ORG_ADMIN, otherwise=F),
        P.PEER_MACHINE: N,
        P.SYSTEM_ADMIN: N,
    },
}

#: Signing in and out answers every caller alike: the form renders, a wrong
#: password is refused, and signing out lands on the sign-in page.
SIGN_IN_ROUTES: Mapping[tuple[str, str], Outcome] = {
    ("/portal/login", "GET"): A,
    ("/portal/login", "POST"): F,
    ("/portal/logout", "POST"): S,
}


def expected(principal: Principal, route: RouteCase) -> Outcome:
    """The answer ``principal`` must get from ``route``."""
    if route.route_class is RouteClass.SIGN_IN:
        return SIGN_IN_ROUTES[route.key]
    if route.route_class is RouteClass.HEALTH:
        return A
    if principal in REFUSED_AT_THE_DOOR:
        return S if route.is_portal else U
    if route.is_portal and principal in CERTIFICATE_ONLY:
        return S
    return EXPECTED[route.route_class][principal]


def observed(response: Response) -> Outcome | str:
    """Classify a response. Anything unclassifiable is returned as text and fails.

    A 400 or 422 is *not* counted as allowed: request validation runs before a
    handler's policy check, so a malformed body would let a refused caller pass
    as permitted. Every request the matrix sends is valid for an allowed caller.
    """
    status = response.status_code
    location = response.headers.get("location", "")
    refusals = {401: U, 403: F, 404: N}
    if status in refusals:
        return refusals[status]
    if 300 <= status < 400:
        return S if location.startswith("/portal/login") else A
    if status < 300:
        return A
    return f"HTTP {status}: {response.text[:120]}"


# ---------------------------------------------------------------------------
# Guards: the table covers the application, and nothing in it is vacuous
# ---------------------------------------------------------------------------
def test_every_walked_route_is_in_exactly_one_class(app):
    walked = set(walk_routes(app.routes))
    declared = [route.key for route in ROUTES]
    duplicated = sorted({key for key in declared if declared.count(key) > 1})
    assert not duplicated, f"routes classified twice: {duplicated}"
    assert walked - set(declared) == set(), (
        f"routes with no class -- classify them: {sorted(walked - set(declared))}"
    )
    assert set(declared) - walked == set(), (
        f"classified routes that do not exist: {sorted(set(declared) - walked)}"
    )


def test_no_class_is_empty():
    used = {route.route_class for route in ROUTES}
    assert set(RouteClass) - used == set()


def test_each_surface_keeps_its_floor(app):
    """A floor per surface, so one surface vanishing cannot hide behind another."""
    walked = set(walk_routes(app.routes))
    for prefix, minimum in SURFACE_FLOORS.items():
        found = sum(1 for route in ROUTES if route.template.startswith(prefix))
        assert found >= minimum, f"{prefix}: {found} classified routes, floor {minimum}"
        assert sum(1 for path, _method in walked if path.startswith(prefix)) >= minimum


def test_every_cell_is_declared():
    for route_class in RouteClass:
        if route_class in (RouteClass.SIGN_IN, RouteClass.HEALTH):
            continue
        assert set(EXPECTED[route_class]) == set(_PAST_THE_DOOR), route_class


def test_no_cell_claims_what_the_surface_rule_overrides():
    """A portal-only class's cell for a certificate-only caller says "sign in".

    The portal needs a person, so those callers are redirected whatever the
    class; any other value in the table would be a claim nothing asserts.
    """
    for route_class, row in EXPECTED.items():
        if all(route.is_portal for route in ROUTES if route.route_class is route_class):
            for principal in CERTIFICATE_ONLY:
                assert row[principal] is S, (route_class, principal)


def test_planned_principals_are_not_faked():
    """Each planned principal arrives with its phase; none is a member of the table yet."""
    names = {principal.value for principal in Principal}
    assert not names & set(PLANNED_PRINCIPALS)


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------
@pytest.fixture
def factories(
    client,
    session,
    settings,
    secret_box,
    ca,
    make_org,
    make_cert,
    make_circle,
    join_circle,
    make_collection,
    make_operator,
    monkeypatch,
) -> Factories:
    # Webhook registration resolves the hostname; the matrix is about who may
    # register one, not about DNS. The resolver itself is tested in test_webhooks.
    monkeypatch.setattr("aivs_server.api.admin.resolve_delivery_target", lambda *_a, **_k: None)
    return Factories(
        client,
        session,
        settings,
        secret_box,
        ca,
        make_org,
        make_cert,
        make_circle,
        join_circle,
        make_collection,
        make_operator,
    )


def _in_safe_order(routes: tuple[RouteCase, ...]) -> list[RouteCase]:
    """Declaration order, except signing out last: it ends the session.

    Declaration order matters once: an acknowledgment needs a server-written
    retrieval receipt, so the circle-content reads come before ``receipt``.
    A recipient that never retrieved is refused, which is the gate working.
    """
    return sorted(routes, key=lambda route: route.key == ("/portal/logout", "POST"))


async def _call(http: AsyncClient, route: RouteCase, world: Any, credentials: Any) -> Response:
    path, body = route.build(world)
    if not route.is_portal:
        return await http.request(route.method, path, json=body, headers=credentials.api_headers)
    if route.method == "GET":
        return await http.get(path, headers=credentials.portal_headers)
    form = {**(body or {}), "csrf_token": credentials.csrf_token}
    return await http.request(route.method, path, data=form, headers=credentials.portal_headers)


@pytest.mark.requirement("NFR-S1", "NFR-S2")
@pytest.mark.parametrize("principal", list(Principal), ids=lambda p: p.name.lower())
async def test_each_principal_gets_exactly_its_row(principal, app, factories):
    world, credentials = await build_world(factories)
    mine = credentials[principal]

    transport = ASGITransport(app=app, client=("127.0.0.1", 0))
    wrong: list[str] = []
    async with AsyncClient(
        transport=transport,
        base_url="https://aivs.test",
        follow_redirects=False,
        cookies=mine.cookies,
    ) as http:
        for route in _in_safe_order(ROUTES):
            response = await _call(http, route, world, mine)
            want, got = expected(principal, route), observed(response)
            if got != want:
                wrong.append(
                    f"{route.route_class} / {route.method} {route.template}: "
                    f"expected {want}, got {got}"
                )

    assert not wrong, f"{principal} does not get its row:\n  " + "\n  ".join(wrong)
