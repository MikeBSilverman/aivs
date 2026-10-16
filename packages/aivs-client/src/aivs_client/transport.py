"""HTTP transport, TAXII polling, and the native API.

One httpx client, configured once with the member's certificate and the hosting
ISAC's CA bundle. Two thin wrappers over it: :class:`TaxiiClient` for collecting
intelligence and :class:`NativeClient` for the submission workflow.

Verification is pinned to the ISAC's CA rather than the system trust store.
That matters: with the system store, any publicly-trusted certificate for the
instance's hostname would satisfy the check, and the whole point of a private CA
is that only the ISAC can issue an identity within it.
"""

from __future__ import annotations

import datetime as dt
import json
import ssl
from collections.abc import Iterator
from typing import Any

import httpx

from aivs_client.config import ClientConfig

__all__ = ["AivsError", "NativeClient", "TaxiiClient", "build_http_client", "build_ssl_context"]

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"

#: The single API root an AIVS instance exposes.
API_ROOT = "taxii2/aivs"

#: Status codes at or above this are failures worth raising on.
_HTTP_ERROR_FLOOR = 400


class AivsError(RuntimeError):
    """The server refused a request.

    Carries the status code so a caller can distinguish "your certificate is not
    accepted" (401) from "you may not do that" (403) from "there is nothing
    there" (404) without parsing prose.
    """

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.message = message


def build_ssl_context(config: ClientConfig) -> ssl.SSLContext:
    """Build the TLS context: pinned CA to verify them, our certificate to prove us.

    Constructed explicitly rather than through httpx's ``verify=``/``cert=``
    convenience arguments, both of which are deprecated in httpx 0.28 and one of
    which is actively wrong for this combination: ``create_ssl_context`` returns
    early from the ``isinstance(verify, str)`` branch, *before* the block that
    calls ``load_cert_chain``. Passing a CA bundle path therefore silently
    discarded the client certificate, so every request went out unauthenticated
    and came back 401 -- and the only configuration that worked was the one that
    dropped the CA pin and fell back to the system trust store. Building the
    context here means the two settings cannot cancel each other out.
    """
    context = ssl.create_default_context(cafile=str(config.ca_bundle))
    context.load_cert_chain(str(config.certificate), str(config.private_key))
    return context


def build_http_client(config: ClientConfig) -> httpx.Client:
    """Construct the mutually-authenticated HTTP client."""
    config.require_files()
    return httpx.Client(
        base_url=config.base_url,
        verify=build_ssl_context(config),
        timeout=config.timeout_seconds,
        follow_redirects=False,
        headers={"user-agent": "aivs-client/0.1"},
    )


def _raise_for_status(response: httpx.Response) -> None:
    """Turn an error response into :class:`AivsError` with a usable message."""
    if response.status_code < _HTTP_ERROR_FLOOR:
        return
    message = response.reason_phrase
    try:
        body = response.json()
        if isinstance(body, dict):
            message = str(body.get("title") or body.get("detail") or message)
    except (ValueError, json.JSONDecodeError):
        pass
    raise AivsError(response.status_code, message)


class TaxiiClient:
    """Collect intelligence over TAXII 2.1."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http
        #: Cursor from the most recent :meth:`objects` call, or ``None`` when
        #: that call returned nothing new. Declared here rather than springing
        #: into existence on first use, so a caller can read it unconditionally.
        self.last_date_added: str | None = None

    def _get(self, path: str, params: dict[str, Any] | None = None) -> httpx.Response:
        response = self._http.get(path, params=params, headers={"accept": TAXII_MEDIA_TYPE})
        _raise_for_status(response)
        return response

    def discovery(self) -> dict[str, Any]:
        return dict(self._get("/taxii2/").json())

    def collections(self) -> list[dict[str, Any]]:
        """Return the collections this member may read.

        An instance with nothing shared to us returns ``{}`` rather than an
        empty list -- that is the specification's rule, not an oddity, so the
        key is fetched defensively.
        """
        body = self._get(f"/{API_ROOT}/collections/").json()
        return list(body.get("collections", []))

    def objects(
        self,
        collection_id: str,
        *,
        added_after: str | None = None,
        limit: int = 100,
        match_type: str | None = None,
    ) -> Iterator[dict[str, Any]]:
        """Yield every visible object in a collection, following pagination.

        Pages until the server stops setting ``more``. Because AIVS keysets on a
        stable sort key, resuming with the returned cursor neither skips nor
        repeats an object.
        """
        # Cleared on entry. This attribute is read after the call to learn the
        # cursor to persist, and a collection that returns nothing new emits no
        # date-added header -- so a caller looping over collections would
        # otherwise persist the *previous* collection's cursor against this one
        # and permanently skip everything in between.
        self.last_date_added = None

        params: dict[str, Any] = {"limit": limit}
        if added_after:
            params["added_after"] = added_after
        if match_type:
            params["match[type]"] = match_type

        path = f"/{API_ROOT}/collections/{collection_id}/objects/"
        while True:
            response = self._get(path, params)
            body = response.json()
            yield from body.get("objects", [])

            if not body.get("more"):
                # The last page's date-added header is the cursor a caller
                # should persist for the next incremental poll.
                self.last_date_added = response.headers.get("X-TAXII-Date-Added-Last")
                return

            next_cursor = body.get("next")
            if not next_cursor:
                # `more` without `next` is legal in TAXII but leaves a client
                # unable to continue; stop rather than loop forever.
                return

            # Filters carry forward. The server's cursor encodes only the sort
            # position and the collection -- it re-parses match[] from the query
            # string on every request -- so rebuilding params from scratch made
            # page two onwards unfiltered, and the caller received objects it had
            # explicitly filtered out. added_after is dropped deliberately: the
            # keyset condition is already strictly ahead of it.
            params = {"limit": limit, "next": next_cursor}
            if match_type:
                params["match[type]"] = match_type

    def manifest(self, collection_id: str) -> list[dict[str, Any]]:
        """Metadata for a collection's objects, without collecting them.

        Deliberately does not create a retrieval receipt on the server: use this
        to survey what exists, and ``objects`` when you actually want it.
        """
        body = self._get(f"/{API_ROOT}/collections/{collection_id}/manifest/").json()
        return list(body.get("objects", []))


class NativeClient:
    """Drive the submission workflow and the evidentiary endpoints."""

    def __init__(self, http: httpx.Client) -> None:
        self._http = http

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        response = self._http.request(method, f"/api/v1{path}", **kwargs)
        _raise_for_status(response)
        if response.status_code == httpx.codes.NO_CONTENT or not response.content:
            return None
        return response.json()

    def whoami(self) -> dict[str, Any]:
        """What the server believes about us.

        The first call worth making after enrolment: it answers "is my
        certificate accepted, and what can I see" in one round trip.
        """
        return dict(self._request("GET", "/whoami"))

    def create_submission(
        self,
        *,
        title: str,
        discovery_scope: str,
        bundle: dict[str, Any],
        summary: str | None = None,
        tlp: str = "amber",
        credit: bool,
    ) -> dict[str, Any]:
        """File a draft. ``credit`` names the filing firm to other members.

        Without it the field is left out and the server applies the owner's
        default: anonymous for a member, the ISAC's own for the ISAC. Required,
        with no default, so every caller states the choice where it is read.
        """
        payload: dict[str, Any] = {
            "title": title,
            "discovery_scope": discovery_scope,
            "tlp": tlp,
            "bundle": bundle,
        }
        if credit:
            payload["distribute_anonymously"] = False
        if summary:
            payload["summary"] = summary
        return dict(self._request("POST", "/submissions", json=payload))

    def submit(self, submission_id: str, reason: str | None = None) -> dict[str, Any]:
        return dict(
            self._request("POST", f"/submissions/{submission_id}/submit", json={"reason": reason})
        )

    def isac_vulnerabilities(self) -> dict[str, Any]:
        """The ISAC's own vulnerability records, newest version each, and how many
        are held back by a draft of the automation's own: its automation only."""
        return dict(self._request("GET", "/isac-records/vulnerabilities"))

    def isac_condition_notes(self) -> dict[str, Any]:
        """The condition import's own notes: those it may version, and the ids of
        those it must not file again (held back). Its automation only."""
        return dict(self._request("GET", "/isac-records/condition-notes"))

    def list_submissions(self, state: str | None = None) -> list[dict[str, Any]]:
        params = {"state": state} if state else None
        return list(self._request("GET", "/submissions", params=params))

    def get_submission(self, submission_id: str) -> dict[str, Any]:
        return dict(self._request("GET", f"/submissions/{submission_id}"))

    def receipts(self, submission_id: str) -> list[dict[str, Any]]:
        return list(self._request("GET", f"/submissions/{submission_id}/receipts"))

    def acknowledge(
        self, submission_id: str, ack_type: str, note: str | None = None
    ) -> dict[str, Any]:
        """Assert that we acknowledged or actioned a submission.

        ``retrieved`` is not accepted here and never will be -- the server writes
        that itself when content is actually delivered, which is what makes the
        record worth anything.
        """
        payload = {"submission_id": submission_id, "ack_type": ack_type}
        if note:
            payload["note"] = note
        return dict(self._request("POST", "/acknowledgments", json=payload))


def utc_now_stamp() -> str:
    """A TAXII-format timestamp for 'now', useful as an initial cursor."""
    now = dt.datetime.now(dt.UTC)
    return f"{now.strftime('%Y-%m-%dT%H:%M:%S')}.{now.microsecond // 1000:03d}Z"
