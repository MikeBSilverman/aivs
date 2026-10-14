"""Every route, in exactly one class, with the request that exercises it.

A class groups routes that should answer every kind of caller the same way, so
the matrix can state one expected outcome per (principal, class) and a reader
can check it against the policy in a page. A route whose answers do not fit its
class is the signal that either the class or the route is wrong.

Requests are built against a seeded :class:`~tests.authz_matrix.world.World`
whose targets *exist*, so an allowed caller succeeds and a refused one is
refused -- with placeholder identifiers every caller would get the same 404 and
the allow side would prove nothing.
"""

from __future__ import annotations

import datetime as dt
import enum
import json
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from tests.authz_matrix.world import inbox_note

if TYPE_CHECKING:
    from tests.authz_matrix.world import World


class RouteClass(enum.StrEnum):
    """A set of routes that every kind of caller should be answered the same on.

    Each class is one policy, stated in its docstring line, and the matrix's
    expected row for a principal is that policy applied to it. Where two routes
    under one heading answer differently (``withdraw`` admits an editor,
    ``submit`` does not) they are different classes: forcing them together
    would mean either a looser assertion or a table full of exceptions.
    """

    #: A listing or self-description, filtered to the caller: every active caller.
    LISTING = "listing"
    #: TAXII content in one collection: members of that circle; others 404.
    CIRCLE_CONTENT = "circle content"
    #: One submission's record: its submitter and the ISAC's reviewers; others 404.
    SUBMISSION_RECORD = "submission record"
    #: Telemetry on a submission: its submitter only; everyone else 404, the
    #: ISAC included (it has the receipts; a count to the wrong reader is a
    #: disclosure of who engaged).
    TELEMETRY = "telemetry"
    #: Firm-by-firm receipts on a submission: the ISAC's reviewers; everyone
    #: else 404, the submitter included (each row is the receiving member's
    #: record; the submitter gets telemetry).
    RECEIPT_RECORD = "receipt record"
    #: Filing a new submission: every active caller.
    FILING = "filing"
    #: Amending or sending a draft: its submitter; a reviewer who can see it 403.
    DRAFT_EDIT = "draft edit"
    #: Withdrawing: its submitter or an editor.
    WITHDRAW = "withdraw"
    #: Acknowledging receipt: organisations the submission was distributed to.
    RECEIPT = "receipt"
    #: Validate, distribute, embargo, reveal: an ISAC editor.
    EDITORIAL = "editorial verb"
    #: The review queue: the ISAC's analysts and editors.
    REVIEW_QUEUE = "review queue"
    #: Enrolment, status, certificates, rosters: ISAC membership staff.
    MEMBERSHIP = "membership verb"
    #: Quarantining an organisation: membership, editors, system admins.
    QUARANTINE = "quarantine"
    #: Reconnecting a quarantined organisation: membership and editors.
    RECONNECT = "reconnect"
    #: Revoking a certificate, addressed by id: membership; others 404.
    CERTIFICATE_REVOKE = "certificate revoke"
    #: Creating a circle: an editor.
    CIRCLE_CREATE = "circle create"
    #: The circle administration screens: editors and membership staff.
    CIRCLE_SCREENS = "circle screens"
    #: Pressing the stop button: editors and system admins.
    PAUSE = "pause"
    #: Releasing it: an editor.
    RESUME = "resume"
    #: The instance status page: system admins and membership staff.
    STATUS_PAGE = "status page"
    #: The caller's own identity and notification endpoints.
    OWN_SETTINGS = "own settings"
    #: Registering a webhook: a member's certificate or org admin; at the ISAC,
    #: a system admin only (its webhooks carry the detection alerts).
    WEBHOOK_REGISTER = "webhook register"
    #: Deleting a webhook, addressed by id: whoever may register one, for their
    #: own organisation's; others 404, those who may not 403 (before any lookup).
    WEBHOOK_DELETE = "webhook delete"
    #: Responding to content (a one-click contribution, a posture): whoever can
    #: read the object; others 404. The ISAC files through review instead
    #: (``services.contributions.filer_problem``).
    CONTENT_RESPONSE = "content response"
    #: A record of one organisation's own (its posture, its TAXII status): that
    #: organisation only; everyone else 404, the ISAC included.
    OWN_RECORD = "own record"
    #: Posture counts, each withheld below k: the ISAC's reviewers; others 404.
    POSTURE_SUMMARY = "posture summary"
    #: The ISAC's own records, outside any circle: its automation's
    #: certificate alone; everyone else 404, ISAC staff included.
    ISAC_RECORDS = "isac records"
    #: Contributing over TAXII: the circle's contributors; its readers 403
    #: (TAXII's answer for readable but not writable); others 404.
    TAXII_INBOX = "taxii inbox"
    #: Turning a circle's post-moderation on or off: an editor.
    POST_MODERATION = "post moderation"
    #: Filing for a member on its consent: an editor.
    PROXY_FILING = "proxy filing"
    #: Confirming a filing made in one's name: a person at that member; its
    #: machine certificate, and a reviewer who can see it, 403.
    PROXY_CONFIRM = "proxy confirm"
    #: Signing in through the ISAC's IdP: absent (404) unless member SSO is on.
    SSO_SIGN_IN = "sso sign in"
    #: Signing in and out: the same for every caller.
    SIGN_IN = "sign in"
    #: Liveness, readiness and metrics, for the orchestrator: everyone.
    HEALTH = "health"


@dataclass(frozen=True)
class RouteCase:
    method: str
    template: str
    route_class: RouteClass
    #: Builds ``(path, body)`` for this route against a seeded world.
    build: Callable[[World], tuple[str, dict[str, Any] | None]]
    #: The portal takes forms, the machine surface JSON.
    is_portal: bool = False
    #: Sent as the body's media type where a route requires its own (TAXII's).
    content_type: str | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.template, self.method)


API = "/api/v1"
TAXII = "/taxii2/aivs"
FUTURE = (dt.datetime.now(dt.UTC) + dt.timedelta(days=30)).isoformat()


def _fixed(path: str, body: dict[str, Any] | None = None) -> Callable[[World], Any]:
    return lambda _world: (path, body)


def _bundle(name: str) -> dict[str, Any]:
    stamp = "2026-08-01T00:00:00.000Z"
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            {
                "type": "vulnerability",
                "spec_version": "2.1",
                "id": f"vulnerability--{uuid.uuid4()}",
                "created": stamp,
                "modified": stamp,
                "name": name,
            }
        ],
    }


def _new_submission(_world: World) -> tuple[str, dict[str, Any]]:
    return f"{API}/submissions", {
        "title": "Matrix finding",
        "discovery_scope": "ai_system",
        "tlp": "amber",
        "bundle": _bundle("Matrix finding"),
    }


def _sub(name: str, suffix: str = "", body: dict[str, Any] | None = None) -> Callable[[World], Any]:
    def build(world: World) -> tuple[str, dict[str, Any] | None]:
        return f"{API}/submissions/{world.submissions[name]}{suffix}", body

    return build


def _org(name: str, suffix: str, body: dict[str, Any] | None = None) -> Callable[[World], Any]:
    def build(world: World) -> tuple[str, dict[str, Any] | None]:
        return f"{API}/orgs/{world.orgs[name]}{suffix}", body

    return build


def _taxii(suffix: str) -> Callable[[World], Any]:
    def build(world: World) -> tuple[str, dict[str, Any] | None]:
        path = suffix.format(collection=world.collection_id, object=world.object_stix_id)
        return f"{TAXII}{path}", None

    return build


def _inbox_envelope(world: World) -> tuple[str, dict[str, Any]]:
    path = f"{TAXII}/collections/{world.collection_id}/objects/"
    return path, {"objects": [inbox_note(world.public_stix_id)]}


def _on_behalf(world: World) -> tuple[str, dict[str, Any]]:
    path, body = _new_submission(world)
    consent = {"on_behalf_of": str(world.orgs["member"]), "consent_sha256": "c0" * 32}
    return f"{path}/on-behalf", {**body, **consent}


def _portal_sub(
    name: str, suffix: str = "", form: dict[str, Any] | None = None
) -> Callable[[World], Any]:
    def build(world: World) -> tuple[str, dict[str, Any] | None]:
        return f"/portal/submissions/{world.submissions[name]}{suffix}", form

    return build


ROUTES: tuple[RouteCase, ...] = (
    # ----- reading: listings, circle content, submission records ----------
    RouteCase("GET", "/taxii2/", RouteClass.LISTING, _fixed("/taxii2/")),
    RouteCase("GET", "/taxii2/aivs/", RouteClass.LISTING, _taxii("/")),
    RouteCase("GET", "/taxii2/aivs/collections/", RouteClass.LISTING, _taxii("/collections/")),
    RouteCase(
        "GET",
        "/taxii2/aivs/collections/{collection_id}/",
        RouteClass.CIRCLE_CONTENT,
        _taxii("/collections/{collection}/"),
    ),
    RouteCase(
        "GET",
        "/taxii2/aivs/collections/{collection_id}/manifest/",
        RouteClass.CIRCLE_CONTENT,
        _taxii("/collections/{collection}/manifest/"),
    ),
    RouteCase(
        "GET",
        "/taxii2/aivs/collections/{collection_id}/objects/",
        RouteClass.CIRCLE_CONTENT,
        _taxii("/collections/{collection}/objects/"),
    ),
    RouteCase(
        "GET",
        "/taxii2/aivs/collections/{collection_id}/objects/{object_id}/",
        RouteClass.CIRCLE_CONTENT,
        _taxii("/collections/{collection}/objects/{object}/"),
    ),
    RouteCase(
        "GET",
        "/taxii2/aivs/collections/{collection_id}/objects/{object_id}/versions/",
        RouteClass.CIRCLE_CONTENT,
        _taxii("/collections/{collection}/objects/{object}/versions/"),
    ),
    RouteCase("GET", "/api/v1/submissions", RouteClass.LISTING, _fixed(f"{API}/submissions")),
    RouteCase(
        "GET", "/api/v1/submissions/{submission_id}", RouteClass.SUBMISSION_RECORD, _sub("read")
    ),
    RouteCase(
        "GET",
        "/api/v1/submissions/{submission_id}/telemetry",
        RouteClass.TELEMETRY,
        _sub("read", "/telemetry"),
    ),
    RouteCase(
        "GET",
        "/api/v1/submissions/{submission_id}/receipts",
        RouteClass.RECEIPT_RECORD,
        _sub("read", "/receipts"),
    ),
    RouteCase("GET", "/portal/", RouteClass.LISTING, _fixed("/portal/"), is_portal=True),
    RouteCase(
        "GET",
        "/portal/submissions",
        RouteClass.LISTING,
        _fixed("/portal/submissions"),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/portal/submissions/{submission_id}",
        RouteClass.SUBMISSION_RECORD,
        _portal_sub("read"),
        is_portal=True,
    ),
    # ----- a member's own submissions and receipts ------------------------
    RouteCase("POST", "/api/v1/submissions", RouteClass.FILING, _new_submission),
    # The sanitisation assist: filing's policy, since it is used before filing.
    RouteCase(
        "POST",
        "/api/v1/submissions/lint",
        RouteClass.FILING,
        _fixed(f"{API}/submissions/lint", {"summary": "seen from 10.0.0.1"}),
    ),
    RouteCase(
        "PATCH",
        "/api/v1/submissions/{submission_id}",
        RouteClass.DRAFT_EDIT,
        _sub("patch", "", {"title": "Amended matrix finding"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/submit",
        RouteClass.DRAFT_EDIT,
        _sub("submit", "/submit", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/withdraw",
        RouteClass.WITHDRAW,
        _sub("withdraw", "/withdraw", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/acknowledgments",
        RouteClass.RECEIPT,
        lambda world: (
            f"{API}/acknowledgments",
            {"submission_id": str(world.submissions["read"]), "ack_type": "acknowledged"},
        ),
    ),
    RouteCase("GET", "/portal/submit", RouteClass.FILING, _fixed("/portal/submit"), is_portal=True),
    RouteCase(
        "POST",
        "/portal/submit",
        RouteClass.FILING,
        lambda _world: (
            "/portal/submit",
            {
                "title": "Matrix portal finding",
                "discovery_scope": "ai_system",
                "tlp": "amber",
                "bundle": json.dumps(_bundle("Matrix portal finding")),
            },
        ),
        is_portal=True,
    ),
    # ----- the ISAC's editorial verbs and review queue --------------------
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/validate",
        RouteClass.EDITORIAL,
        _sub("validate", "/validate", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/distribute",
        RouteClass.EDITORIAL,
        lambda world: (
            f"{API}/submissions/{world.submissions['distribute']}/distribute",
            {"circle_ids": [str(world.circle_id)]},
        ),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/embargo/extend",
        RouteClass.EDITORIAL,
        lambda world: (
            f"{API}/submissions/{world.submissions['extend']}/embargo/extend",
            {"circle_ids": [str(world.circle_id)], "release_at": FUTURE},
        ),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/embargo/release",
        RouteClass.EDITORIAL,
        _sub("release", "/embargo/release", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/reveal",
        RouteClass.EDITORIAL,
        _sub("reveal", "/reveal", {"reason": "matrix: legal process"}),
    ),
    RouteCase(
        "GET", "/portal/review", RouteClass.REVIEW_QUEUE, _fixed("/portal/review"), is_portal=True
    ),
    RouteCase(
        "POST",
        "/portal/submissions/{submission_id}/{verb}",
        RouteClass.EDITORIAL,
        _portal_sub("validate_portal", "/validate", {}),
        is_portal=True,
    ),
    # ----- making members share -------------------------------------------
    RouteCase(
        "POST",
        "/api/v1/contributions",
        RouteClass.CONTENT_RESPONSE,
        lambda world: (
            f"{API}/contributions",
            {"target": world.object_stix_id, "kind": "seen"},
        ),
    ),
    RouteCase(
        "PUT",
        "/api/v1/postures",
        RouteClass.CONTENT_RESPONSE,
        lambda world: (f"{API}/postures", {"vulnerability": world.object_stix_id}),
    ),
    RouteCase(
        "GET",
        "/api/v1/postures",
        RouteClass.LISTING,
        lambda _world: (f"{API}/postures", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/postures/openvex",
        RouteClass.LISTING,
        lambda _world: (f"{API}/postures/openvex", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/postures/{posture_id}",
        RouteClass.OWN_RECORD,
        lambda world: (f"{API}/postures/{world.posture_id}", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/vulnerabilities/{stix_id}/posture-summary",
        RouteClass.POSTURE_SUMMARY,
        lambda world: (f"{API}/vulnerabilities/{world.object_stix_id}/posture-summary", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/isac-records/vulnerabilities",
        RouteClass.ISAC_RECORDS,
        lambda _world: (f"{API}/isac-records/vulnerabilities", None),
    ),
    RouteCase(
        "PUT",
        "/api/v1/circles/{circle_id}/post-moderation",
        RouteClass.POST_MODERATION,
        lambda world: (f"{API}/circles/{world.circle_id}/post-moderation", {"enabled": False}),
    ),
    RouteCase("POST", "/api/v1/submissions/on-behalf", RouteClass.PROXY_FILING, _on_behalf),
    RouteCase(
        "POST",
        "/api/v1/submissions/{submission_id}/confirm",
        RouteClass.PROXY_CONFIRM,
        _sub("proxy", "/confirm", {}),
    ),
    RouteCase(
        "POST",
        "/taxii2/aivs/collections/{collection_id}/objects/",
        RouteClass.TAXII_INBOX,
        _inbox_envelope,
        content_type="application/taxii+json;version=2.1",
    ),
    RouteCase(
        "GET",
        "/taxii2/aivs/status/{status_id}/",
        RouteClass.OWN_RECORD,
        lambda world: (f"{TAXII}/status/{world.taxii_status_id}/", None),
    ),
    # ----- organisations, certificates, rosters ---------------------------
    RouteCase("GET", "/api/v1/orgs", RouteClass.LISTING, _fixed(f"{API}/orgs")),
    RouteCase(
        "POST",
        "/api/v1/orgs",
        RouteClass.MEMBERSHIP,
        _fixed(
            f"{API}/orgs",
            {"slug": "matrix-enrolled", "name": "Matrix Enrolled", "org_type": "gsib"},
        ),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/activate",
        RouteClass.MEMBERSHIP,
        _org("activate", "/activate", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/suspend",
        RouteClass.MEMBERSHIP,
        _org("suspend", "/suspend", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/quarantine",
        RouteClass.QUARANTINE,
        _org("quarantine", "/quarantine", {"reason": "matrix: suspected compromise"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/offboard",
        RouteClass.MEMBERSHIP,
        _org(
            "offboard",
            "/offboard",
            {"reason": "matrix: membership ended", "confirm_slug": "matrix-offboard"},
        ),
    ),
    RouteCase(
        "PUT",
        "/api/v1/orgs/{org_id}/legal-hold",
        RouteClass.MEMBERSHIP,
        _org("hold", "/legal-hold", {"reason": "matrix: litigation hold"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/legal-hold/lift",
        RouteClass.MEMBERSHIP,
        _org("lift", "/legal-hold/lift", {"reason": "matrix: litigation settled"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/reconnect",
        RouteClass.RECONNECT,
        _org("reconnect", "/reconnect", {"reason": "matrix: cleared"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/certificates",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"{API}/orgs/{world.orgs['register']}/certificates",
            {"certificate_pem": world.unregistered_pem},
        ),
    ),
    RouteCase(
        "POST",
        "/api/v1/certificates/{certificate_id}/revoke",
        RouteClass.CERTIFICATE_REVOKE,
        lambda world: (f"{API}/certificates/{world.revocable_certificate_id}/revoke", {}),
    ),
    RouteCase(
        "POST",
        "/api/v1/circles/{circle_id}/members",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"{API}/circles/{world.circle_id}/members",
            {"org_ids": [str(world.orgs["add"])]},
        ),
    ),
    RouteCase(
        "DELETE",
        "/api/v1/circles/{circle_id}/members/{org_id}",
        RouteClass.MEMBERSHIP,
        lambda world: (f"{API}/circles/{world.circle_id}/members/{world.orgs['remove']}", None),
    ),
    RouteCase(
        "GET",
        "/portal/admin/orgs",
        RouteClass.MEMBERSHIP,
        _fixed("/portal/admin/orgs"),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/orgs",
        RouteClass.MEMBERSHIP,
        _fixed(
            "/portal/admin/orgs",
            {"slug": "matrix-portal-enrolled", "name": "Matrix P", "org_type": "gsib"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/orgs/{org_id}/quarantine",
        RouteClass.QUARANTINE,
        lambda world: (
            f"/portal/admin/orgs/{world.orgs['quarantine_portal']}/quarantine",
            {"reason": "matrix: suspected compromise"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/orgs/{org_id}/{action}",
        RouteClass.MEMBERSHIP,
        lambda world: (f"/portal/admin/orgs/{world.orgs['suspend_portal']}/suspend", {}),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/circles/{circle_id}/members",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"/portal/admin/circles/{world.circle_id}/members",
            {"roster": "matrix-add-portal"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/circles/{circle_id}/members/{org_id}/remove",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"/portal/admin/circles/{world.circle_id}/members/{world.orgs['remove_portal']}/remove",
            {},
        ),
        is_portal=True,
    ),
    # ----- circles, the pause, the status page ----------------------------
    RouteCase("GET", "/api/v1/circles", RouteClass.LISTING, _fixed(f"{API}/circles")),
    RouteCase(
        "POST",
        "/api/v1/circles",
        RouteClass.CIRCLE_CREATE,
        _fixed(f"{API}/circles", {"slug": "matrix-new-circle", "name": "Matrix New Circle"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/instance/distribution/pause",
        RouteClass.PAUSE,
        _fixed(f"{API}/instance/distribution/pause", {"reason": "matrix: incident drill"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/instance/distribution/resume",
        RouteClass.RESUME,
        _fixed(f"{API}/instance/distribution/resume", {"reason": "matrix: incident drill"}),
    ),
    RouteCase(
        "GET",
        "/portal/admin/circles",
        RouteClass.CIRCLE_SCREENS,
        _fixed("/portal/admin/circles"),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/circles",
        RouteClass.CIRCLE_CREATE,
        _fixed(
            "/portal/admin/circles",
            {"slug": "matrix-portal-circle", "name": "Matrix Portal Circle"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/portal/admin/circles/{circle_id}",
        RouteClass.CIRCLE_SCREENS,
        lambda world: (f"/portal/admin/circles/{world.circle_id}", None),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/portal/admin/status",
        RouteClass.STATUS_PAGE,
        _fixed("/portal/admin/status"),
        is_portal=True,
    ),
    # ----- the caller's own settings --------------------------------------
    RouteCase("GET", "/api/v1/whoami", RouteClass.OWN_SETTINGS, _fixed(f"{API}/whoami")),
    RouteCase("GET", "/api/v1/webhooks", RouteClass.OWN_SETTINGS, _fixed(f"{API}/webhooks")),
    RouteCase(
        "POST",
        "/api/v1/webhooks",
        RouteClass.WEBHOOK_REGISTER,
        _fixed(f"{API}/webhooks", {"url": "https://hooks.matrix.example/aivs"}),
    ),
    RouteCase(
        "DELETE",
        "/api/v1/webhooks/{webhook_id}",
        RouteClass.WEBHOOK_DELETE,
        lambda world: (f"{API}/webhooks/{world.webhook_id}", None),
    ),
    # ----- sign in -----------------------------------------------------------
    RouteCase("GET", "/portal/login", RouteClass.SIGN_IN, _fixed("/portal/login"), is_portal=True),
    RouteCase(
        "POST",
        "/portal/login",
        RouteClass.SIGN_IN,
        _fixed(
            "/portal/login",
            {"email": "nobody@matrix.test", "password": "wrong", "totp_code": "000000"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST", "/portal/logout", RouteClass.SIGN_IN, _fixed("/portal/logout", {}), is_portal=True
    ),
    RouteCase(
        "GET",
        "/portal/sso/login",
        RouteClass.SSO_SIGN_IN,
        _fixed("/portal/sso/login"),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/portal/sso/callback",
        RouteClass.SSO_SIGN_IN,
        _fixed("/portal/sso/callback"),
        is_portal=True,
    ),
    # ----- health ---------------------------------------------------------
    RouteCase("GET", "/healthz", RouteClass.HEALTH, _fixed("/healthz")),
    RouteCase("GET", "/readyz", RouteClass.HEALTH, _fixed("/readyz")),
    RouteCase("GET", "/metrics", RouteClass.HEALTH, _fixed("/metrics")),
)

#: The fewest routes each surface may have: today's count. A floor per surface,
#: not a total, so one surface vanishing from the walk cannot hide behind another
#: growing. Raise a floor when a surface grows; lowering one is a decision.
SURFACE_FLOORS: dict[str, int] = {
    "/api/v1": 38,
    "/taxii2": 10,
    "/portal/admin": 10,
    "/portal": 22,
    "/healthz": 1,
    "/readyz": 1,
    "/metrics": 1,
}
