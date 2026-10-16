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
    #: An export of a vulnerability (the IoC pack): whoever can see the
    #: vulnerability, which is its circle's members and the ISAC's reviewers;
    #: others 404.
    VULNERABILITY_EXPORT = "vulnerability export"
    #: One submission's record: its submitter and the ISAC's reviewers; others 404.
    SUBMISSION_RECORD = "submission record"
    #: What's available for a vulnerability: whoever can see the vulnerability,
    #: which is its circle's members and the ISAC's reviewers; others 404.
    READINESS = "readiness"
    #: The vulnerability page: whoever can see the vulnerability; others 404.
    VULNERABILITY_PAGE = "vulnerability page"
    #: A member's evidence pack, and its "we've acted" assertion: an
    #: organisation that reads by membership and can see the vulnerability;
    #: everyone else 404, the ISAC included.
    EVIDENCE_PACK = "evidence pack"
    #: The audit trail and receipts streams: an auditor only; everyone else
    #: 403, before the request is examined.
    AUDIT_READ = "audit read"
    #: Telemetry on a submission: its submitter only; everyone else 404, the
    #: ISAC included (it has the receipts; a count to the wrong reader is a
    #: disclosure of who engaged).
    TELEMETRY = "telemetry"
    #: Firm-by-firm receipts on a submission: the ISAC's reviewers; everyone
    #: else 404, the submitter included (each row is the receiving member's
    #: record; the submitter gets telemetry).
    RECEIPT_RECORD = "receipt record"
    #: The first pass over a submission (Phase O): the ISAC's reviewers; else
    #: 404, the submitter included, which is not told anything until the
    #: checks are tuned.
    FIRST_PASS = "first pass"
    #: Setting a submission's priority: an editor; others who can see it 403.
    PRIORITY = "priority"
    #: Taking or handing over a submission: the ISAC's reviewers.
    ASSIGN = "assign"
    #: Validating a review group in one action: an editor; everyone else 403,
    #: before any submission is looked up.
    BULK_VALIDATE = "bulk validate"
    #: Filing a new submission: every active caller.
    FILING = "filing"
    #: Amending or sending a draft: its submitter; a reviewer who can see it 403.
    DRAFT_EDIT = "draft edit"
    #: Withdrawing: its submitter or an editor.
    WITHDRAW = "withdraw"
    #: Acknowledging receipt: organisations the submission was distributed to.
    RECEIPT = "receipt"
    #: Validate, distribute, embargo, reveal, revoke: an ISAC editor.
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
    #: Opening, closing and filing call notes on a sector event: an editor;
    #: everyone else 403, before any lookup.
    SECTOR_EVENT = "sector event"
    #: Creating a circle: an editor.
    CIRCLE_CREATE = "circle create"
    #: The circle administration screens: editors and membership staff.
    CIRCLE_SCREENS = "circle screens"
    #: Pressing the stop button: editors and system admins.
    PAUSE = "pause"
    #: Releasing it: an editor.
    RESUME = "resume"
    #: Choosing what the audit stream serves of its own reading: the system
    #: admin, who runs the instance; nobody else, auditors included.
    AUDIT_STREAM_MODE = "audit stream mode"
    #: The instance status page: system admins and membership staff.
    STATUS_PAGE = "status page"
    #: The caller's own identity and notification endpoints.
    OWN_SETTINGS = "own settings"
    #: Registering a webhook, or changing how often and where the organisation
    #: is notified: a member's certificate or org admin; at the ISAC, a system
    #: admin only (its webhooks carry the detection alerts).
    WEBHOOK_REGISTER = "webhook register"
    #: Deleting a webhook, addressed by id: whoever may register one, for their
    #: own organisation's; others 404, those who may not 403 (before any lookup).
    WEBHOOK_DELETE = "webhook delete"
    #: Responding to content (a one-click contribution, a posture): whoever can
    #: read the object; others 404. The ISAC files through review instead
    #: (``services.contributions.filer_problem``).
    CONTENT_RESPONSE = "content response"
    #: A record of one organisation's own (its posture, its TAXII status, its
    #: lead-time statement): that organisation only; everyone else 404, the
    #: ISAC included.
    OWN_RECORD = "own record"
    #: Sector figures, each withheld below k (posture counts, the lead-time
    #: median): the ISAC's reviewers; others 404.
    POSTURE_SUMMARY = "posture summary"
    #: The ISAC's own records, outside any circle: its automation's
    #: certificate alone; everyone else 404, ISAC staff included.
    ISAC_RECORDS = "isac records"
    #: Contributing over TAXII: the circle's contributors; its readers 403
    #: (TAXII's answer for readable but not writable); others 404.
    TAXII_INBOX = "taxii inbox"
    #: Turning a circle's post-moderation on or off: an editor.
    POST_MODERATION = "post moderation"
    #: Opening or closing a circle's TAXII inbox: an editor, on either door.
    INBOX_SWITCH = "inbox switch"
    #: Filing for a member on its consent: an editor.
    PROXY_FILING = "proxy filing"
    #: Confirming a filing made in one's name: a person at that member; its
    #: machine certificate, and a reviewer who can see it, 403.
    PROXY_CONFIRM = "proxy confirm"
    #: Writing a new text document (Phase I): a signed-in person; a certificate
    #: alone 403, before anything is written.
    DOCUMENT_CREATE = "document create"
    #: Reading one document: its author and its grantees (here the member firm
    #: and the peer); everyone else 404, the ISAC included.
    DOCUMENT_READ = "document read"
    #: Commenting on one: a signed-in person among its grantees; a certificate
    #: alone 403; everyone else 404.
    DOCUMENT_COMMENT = "document comment"
    #: Saving a version or moving its state: a person holding edit (the member
    #: firm); a certificate alone 403; everyone else 404.
    DOCUMENT_EDIT = "document edit"
    #: Seeing and changing who it is shared with: the owner firm's editors; a
    #: certificate alone 403; everyone else 404.
    DOCUMENT_SHARE = "document share"
    #: A firm's document sharing code: its own org admins; everyone else 403.
    SHARING_CODE = "sharing code"
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
        "/api/v1/vulnerabilities/ioc-pack.csv",
        RouteClass.VULNERABILITY_EXPORT,
        lambda world: (f"{API}/vulnerabilities/ioc-pack.csv?id={world.object_stix_id}", None),
    ),
    RouteCase(
        "GET",
        "/portal/vulnerabilities/ioc-pack.csv",
        RouteClass.VULNERABILITY_EXPORT,
        lambda world: (f"/portal/vulnerabilities/ioc-pack.csv?id={world.object_stix_id}", None),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/organizations/{org_id}/lead-time",
        RouteClass.OWN_RECORD,
        lambda world: (
            f"{API}/organizations/{world.orgs['member']}/lead-time?quarter=2026Q4",
            None,
        ),
    ),
    RouteCase(
        "GET",
        "/api/v1/lead-time/sector",
        RouteClass.POSTURE_SUMMARY,
        _fixed(f"{API}/lead-time/sector?quarter=2026Q4"),
    ),
    RouteCase(
        "GET",
        "/api/v1/submissions/{submission_id}/telemetry",
        RouteClass.TELEMETRY,
        _sub("read", "/telemetry"),
    ),
    RouteCase(
        "GET",
        "/api/v1/submissions/{submission_id}/duplicates",
        RouteClass.SUBMISSION_RECORD,
        _sub("read", "/duplicates"),
    ),
    RouteCase(
        "PUT",
        "/api/v1/submissions/{submission_id}/priority",
        RouteClass.PRIORITY,
        _sub("read", "/priority", {"priority": "act"}),
    ),
    RouteCase(
        "PUT",
        "/api/v1/submissions/{submission_id}/assignee",
        RouteClass.ASSIGN,
        _sub("read", "/assignee", {"operator_id": None}),
    ),
    RouteCase(
        "POST",
        "/api/v1/review/validate",
        RouteClass.BULK_VALIDATE,
        lambda world: (
            f"{API}/review/validate",
            {"submission_ids": [str(world.submissions["bulk"])]},
        ),
    ),
    RouteCase(
        "POST",
        "/portal/review/validate",
        RouteClass.BULK_VALIDATE,
        lambda world: (
            "/portal/review/validate",
            {"submission_ids": [str(world.submissions["bulk_portal"])]},
        ),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/vulnerabilities/exploitability",
        RouteClass.VULNERABILITY_EXPORT,
        lambda world: (f"{API}/vulnerabilities/exploitability?id={world.object_stix_id}", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/vulnerabilities/osv",
        RouteClass.VULNERABILITY_EXPORT,
        lambda world: (f"{API}/vulnerabilities/osv?id={world.osv_stix_id}", None),
    ),
    RouteCase(
        "GET",
        "/api/v1/vulnerabilities/readiness",
        RouteClass.READINESS,
        lambda world: (f"{API}/vulnerabilities/readiness?id={world.object_stix_id}", None),
    ),
    RouteCase(
        "GET",
        "/portal/vulnerabilities",
        RouteClass.VULNERABILITY_PAGE,
        lambda world: (f"/portal/vulnerabilities?id={world.object_stix_id}", None),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/evidence-pack",
        RouteClass.EVIDENCE_PACK,
        lambda world: (f"{API}/evidence-pack?vulnerability={world.object_stix_id}", None),
    ),
    RouteCase(
        "GET",
        "/portal/vulnerabilities/evidence-pack",
        RouteClass.EVIDENCE_PACK,
        lambda world: (f"/portal/vulnerabilities/evidence-pack?id={world.object_stix_id}", None),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/vulnerabilities/actioned",
        RouteClass.EVIDENCE_PACK,
        lambda world: ("/portal/vulnerabilities/actioned", {"vulnerability": world.object_stix_id}),
        is_portal=True,
    ),
    RouteCase("GET", "/api/v1/audit/events", RouteClass.AUDIT_READ, _fixed(f"{API}/audit/events")),
    RouteCase(
        "GET", "/api/v1/audit/receipts", RouteClass.AUDIT_READ, _fixed(f"{API}/audit/receipts")
    ),
    RouteCase(
        "POST",
        "/portal/vulnerabilities/contributions",
        RouteClass.CONTENT_RESPONSE,
        lambda world: (
            "/portal/vulnerabilities/contributions",
            {
                "vulnerability": world.object_stix_id,
                "kind": "seen",
                "target_id": world.object_stix_id,
            },
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/vulnerabilities/posture",
        RouteClass.CONTENT_RESPONSE,
        lambda world: (
            "/portal/vulnerabilities/posture",
            {"vulnerability": world.object_stix_id, "status": "not_affected"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/submissions/{submission_id}/first-pass",
        RouteClass.FIRST_PASS,
        _sub("read", "/first-pass"),
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
        "POST",
        "/api/v1/submissions/{submission_id}/revoke",
        RouteClass.EDITORIAL,
        _sub("revoke", "/revoke", {"reason": "matrix: revoked after post-moderation"}),
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
        "GET",
        "/api/v1/isac-records/condition-notes",
        RouteClass.ISAC_RECORDS,
        lambda _world: (f"{API}/isac-records/condition-notes", None),
    ),
    RouteCase(
        "PUT",
        "/api/v1/circles/{circle_id}/post-moderation",
        RouteClass.POST_MODERATION,
        lambda world: (f"{API}/circles/{world.circle_id}/post-moderation", {"enabled": False}),
    ),
    # Opened, not closed: the inbox cases depend on the world's collection
    # taking posts, whichever order the cases run in.
    RouteCase(
        "PUT",
        "/api/v1/circles/{circle_id}/taxii-inbox",
        RouteClass.INBOX_SWITCH,
        lambda world: (f"{API}/circles/{world.circle_id}/taxii-inbox", {"enabled": True}),
    ),
    RouteCase(
        "POST",
        "/portal/admin/circles/{circle_id}/taxii-inbox",
        RouteClass.INBOX_SWITCH,
        lambda world: (f"/portal/admin/circles/{world.circle_id}/taxii-inbox", {"enabled": "on"}),
        is_portal=True,
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
        "GET",
        "/api/v1/orgs/{org_id}/mail-domains",
        RouteClass.MEMBERSHIP,
        _org("member", "/mail-domains"),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/mail-domains",
        RouteClass.MEMBERSHIP,
        _org("member", "/mail-domains", {"domain": "matrix-added.example"}),
    ),
    RouteCase(
        "POST",
        "/api/v1/orgs/{org_id}/mail-domains/remove",
        RouteClass.MEMBERSHIP,
        _org("member", "/mail-domains/remove", {"domain": "matrix-remove.example"}),
    ),
    RouteCase(
        "PUT",
        "/api/v1/orgs/{org_id}/directory-group",
        RouteClass.MEMBERSHIP,
        _org("peer", "/directory-group", {"directory_object_id": "matrix-peer-group"}),
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
        "/portal/admin/orgs/{org_id}/mail-domains",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"/portal/admin/orgs/{world.orgs['member']}/mail-domains",
            {"domain": "matrix-added-portal.example"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/orgs/{org_id}/directory-group",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"/portal/admin/orgs/{world.orgs['peer']}/directory-group",
            {"directory_object_id": "matrix-peer-portal-group"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/portal/admin/orgs/{org_id}/mail-domains/remove",
        RouteClass.MEMBERSHIP,
        lambda world: (
            f"/portal/admin/orgs/{world.orgs['member']}/mail-domains/remove",
            {"domain": "matrix-remove-portal.example"},
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
        "PUT",
        "/api/v1/instance/audit-stream",
        RouteClass.AUDIT_STREAM_MODE,
        _fixed(
            f"{API}/instance/audit-stream",
            {"mode": "full", "reason": "matrix: choosing the stream"},
        ),
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
    RouteCase("GET", "/api/v1/sector-events", RouteClass.LISTING, _fixed(f"{API}/sector-events")),
    RouteCase(
        "POST",
        "/api/v1/sector-events",
        RouteClass.SECTOR_EVENT,
        lambda world: (f"{API}/sector-events", {"vulnerability_stix_id": world.pinnable_stix_id}),
    ),
    RouteCase(
        "POST",
        "/api/v1/sector-events/{event_id}/call-notes",
        RouteClass.SECTOR_EVENT,
        lambda world: (
            f"{API}/sector-events/{world.sector_event_id}/call-notes",
            {
                "summary": "matrix: call summary",
                "action_items": ["patch the gateway"],
                "discovery_scope": "own_estate",
            },
        ),
    ),
    RouteCase(
        "POST",
        "/api/v1/sector-events/{event_id}/close",
        RouteClass.SECTOR_EVENT,
        lambda world: (f"{API}/sector-events/{world.sector_event_id}/close", {}),
    ),
    RouteCase(
        "GET",
        "/api/v1/connection-health",
        RouteClass.OWN_SETTINGS,
        _fixed(f"{API}/connection-health"),
    ),
    RouteCase(
        "GET",
        "/api/v1/tip-config/{tool}",
        RouteClass.OWN_SETTINGS,
        _fixed(f"{API}/tip-config/opencti"),
    ),
    RouteCase(
        "GET",
        "/portal/connection",
        RouteClass.OWN_SETTINGS,
        _fixed("/portal/connection"),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/notification-settings",
        RouteClass.OWN_SETTINGS,
        _fixed(f"{API}/notification-settings"),
    ),
    RouteCase(
        "PUT",
        "/api/v1/notification-settings",
        RouteClass.WEBHOOK_REGISTER,
        _fixed(f"{API}/notification-settings", {"cadence": "hourly"}),
    ),
    RouteCase(
        "POST",
        "/portal/preferences/depth",
        RouteClass.OWN_SETTINGS,
        _fixed("/portal/preferences/depth", {"depth": "guided"}),
        is_portal=True,
    ),
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
    # ----- text documents (Phase I) ----------------------------------------
    RouteCase("GET", "/api/v1/documents", RouteClass.LISTING, _fixed(f"{API}/documents")),
    RouteCase(
        "GET", "/portal/documents", RouteClass.LISTING, _fixed("/portal/documents"), is_portal=True
    ),
    RouteCase(
        "POST",
        "/api/v1/documents",
        RouteClass.DOCUMENT_CREATE,
        _fixed(f"{API}/documents", {"title": "Matrix", "tlp": "amber", "body": "Text."}),
    ),
    RouteCase(
        "POST",
        "/portal/documents",
        RouteClass.DOCUMENT_CREATE,
        _fixed("/portal/documents", {"title": "Matrix", "tlp": "amber", "body": "Text."}),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/documents/{document_id}",
        RouteClass.DOCUMENT_READ,
        lambda world: (f"{API}/documents/{world.document_id}", None),
    ),
    RouteCase(
        "GET",
        "/portal/documents/{document_id}",
        RouteClass.DOCUMENT_READ,
        lambda world: (f"/portal/documents/{world.document_id}", None),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/api/v1/documents/{document_id}/comments",
        RouteClass.DOCUMENT_COMMENT,
        lambda world: (
            f"{API}/documents/{world.document_id}/comments",
            {"version_number": 1, "body": "A comment."},
        ),
    ),
    RouteCase(
        "POST",
        "/portal/documents/{document_id}/comments",
        RouteClass.DOCUMENT_COMMENT,
        lambda world: (
            f"/portal/documents/{world.document_id}/comments",
            {"version_number": "1", "body": "A comment."},
        ),
        is_portal=True,
    ),
    # Saves before moves: a save names the version it read.
    RouteCase(
        "PUT",
        "/api/v1/documents/{document_id}/body",
        RouteClass.DOCUMENT_EDIT,
        lambda world: (
            f"{API}/documents/{world.document_id}/body",
            {"body": "Version two.", "expected_version": 1},
        ),
    ),
    RouteCase(
        "POST",
        "/portal/documents/{document_id}/body",
        RouteClass.DOCUMENT_EDIT,
        lambda world: (
            f"/portal/documents/{world.document_id}/body",
            {"body": "Version three.", "expected_version": "2"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "POST",
        "/api/v1/documents/{document_id}/transition",
        RouteClass.DOCUMENT_EDIT,
        lambda world: (f"{API}/documents/{world.document_id}/transition", {"to": "in_review"}),
    ),
    RouteCase(
        "POST",
        "/portal/documents/{document_id}/transition",
        RouteClass.DOCUMENT_EDIT,
        lambda world: (f"/portal/documents/{world.document_id}/transition", {"to": "draft"}),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/documents/{document_id}/grants",
        RouteClass.DOCUMENT_SHARE,
        lambda world: (f"{API}/documents/{world.document_id}/grants", None),
    ),
    RouteCase(
        "POST",
        "/api/v1/documents/{document_id}/grants",
        RouteClass.DOCUMENT_SHARE,
        lambda world: (
            f"{API}/documents/{world.document_id}/grants",
            {
                "principal_type": "organization",
                "sharing_code": world.peer_sharing_code,
                "permission": "view",
            },
        ),
    ),
    RouteCase(
        "POST",
        "/portal/documents/{document_id}/grants",
        RouteClass.DOCUMENT_SHARE,
        lambda world: (
            f"/portal/documents/{world.document_id}/grants",
            {"sharing_code": world.peer_sharing_code, "permission": "view"},
        ),
        is_portal=True,
    ),
    RouteCase(
        "DELETE",
        "/api/v1/documents/{document_id}/grants/{grant_id}",
        RouteClass.DOCUMENT_SHARE,
        lambda world: (
            f"{API}/documents/{world.document_id}/grants/{world.document_grant_ids[0]}",
            None,
        ),
    ),
    RouteCase(
        "POST",
        "/portal/documents/{document_id}/grants/{grant_id}/revoke",
        RouteClass.DOCUMENT_SHARE,
        lambda world: (
            f"/portal/documents/{world.document_id}/grants/{world.document_grant_ids[1]}/revoke",
            {},
        ),
        is_portal=True,
    ),
    RouteCase(
        "GET",
        "/api/v1/documents/sharing-code",
        RouteClass.SHARING_CODE,
        _fixed(f"{API}/documents/sharing-code"),
    ),
    RouteCase(
        "POST",
        "/api/v1/documents/sharing-code",
        RouteClass.SHARING_CODE,
        _fixed(f"{API}/documents/sharing-code"),
    ),
    RouteCase(
        "POST",
        "/portal/documents/sharing-code",
        RouteClass.SHARING_CODE,
        _fixed("/portal/documents/sharing-code", {}),
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
    "/api/v1": 83,
    "/taxii2": 10,
    "/portal/admin": 10,
    "/portal": 41,
    "/healthz": 1,
    "/readyz": 1,
    "/metrics": 1,
}
