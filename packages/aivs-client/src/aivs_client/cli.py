"""The ``aivs`` command line.

Designed for two audiences that want different things. A SOC engineer wants
``aivs poll`` to emit newline-delimited STIX on stdout so it pipes straight into
a SIEM or TIP, keep its own cursor, and be safe to run from cron. An analyst
wants to file a finding and check who collected it.

Output discipline: machine-readable content goes to **stdout**, everything
human-facing goes to **stderr**. That is what makes ``aivs poll | ingest`` work
without a flag, and it means a progress message can never corrupt a member's
ingest pipeline.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Annotated, Any, Final, NoReturn

import typer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aivs_client.config import ConfigError, load_config
from aivs_client.state import CursorStore
from aivs_client.transport import AivsError, NativeClient, TaxiiClient, build_http_client

app = typer.Typer(
    name="aivs",
    help="Reference client for an AIVS pre-CVE vulnerability sharing instance.",
    no_args_is_help=True,
    add_completion=False,
)

BaseUrl = Annotated[str | None, typer.Option("--url", help="Instance base URL.")]
CertOpt = Annotated[str | None, typer.Option("--cert", help="Client certificate (PEM).")]
KeyOpt = Annotated[str | None, typer.Option("--key", help="Private key (PEM).")]
CaOpt = Annotated[str | None, typer.Option("--ca", help="CA bundle verifying the server.")]

#: Organisation slugs, matching ``aivs_schemas.models.Slug``. Kept in step with
#: the server's definition so a name the CLI accepts is one the instance will.
#: Also what keeps a slug safe to interpolate into a filename.
_SLUG_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")

#: Characters that must never reach a terminal from server-supplied text.
_CONTROL_CHARACTERS: Final[re.Pattern[str]] = re.compile(r"[\x00-\x1f\x7f]")


def _safe(value: object) -> str:
    """Render a server-supplied string for a line-oriented terminal listing.

    Titles and names come from other member organisations. Printed raw into a
    one-record-per-line listing, an embedded newline forges a row for a
    submission that does not exist, a carriage return overwrites a real one, and
    an escape sequence reaches the terminal directly whenever stdout is a tty.
    """
    return _CONTROL_CHARACTERS.sub("?", str(value))


def _err(message: str) -> None:
    """Human-facing output. Never stdout -- stdout is the data channel."""
    typer.echo(message, err=True)


def _connect(url: str | None, cert: str | None, key: str | None, ca: str | None) -> tuple[Any, Any]:
    """Build the clients, turning configuration problems into clean exits."""
    try:
        config = load_config(base_url=url, certificate=cert, private_key=key, ca_bundle=ca)
        http = build_http_client(config)
    except ConfigError as exc:
        _err(f"configuration error: {exc}")
        raise typer.Exit(code=2) from exc
    return config, http


def _fail(exc: AivsError) -> NoReturn:
    """Report a server refusal in terms the operator can act on.

    Typed ``NoReturn`` because it always raises. Without that the type checker
    believes control can fall through an ``except`` block into code that uses a
    variable the ``try`` never managed to bind.
    """
    hints = {
        401: (
            "the instance did not accept this certificate — check it is registered and not revoked"
        ),
        403: "authenticated, but not permitted to do that",
        404: "not found, or not visible to this organisation",
        406: "the server could not satisfy the requested content type",
        409: "refused because of the resource's current state",
    }
    _err(f"error: {exc.message}")
    hint = hints.get(exc.status_code)
    if hint:
        _err(f"  {hint}")
    raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# Enrolment
# ---------------------------------------------------------------------------
@app.command()
def enroll(
    common_name: Annotated[str, typer.Argument(help="Your organisation's slug.")],
    out_dir: Annotated[Path, typer.Option("--out", help="Where to write key and CSR.")] = Path(),
    organization: Annotated[str | None, typer.Option("--org")] = None,
) -> None:
    """Generate a private key and certificate signing request.

    The private key is written here and **never leaves this machine** — only the
    CSR is sent to the hosting ISAC. Send them the .csr file; they return a
    signed certificate to use with the other commands.

    The key is written with owner-only permissions. If that matters to your
    environment, generate it on the host that will use it rather than copying it
    around afterwards.
    """
    # Validated before it is used to build a path. The argument is documented as
    # a slug, but nothing enforced that, so `../../shared/foo` wrote the private
    # key outside --out and `a/b` failed with an unhandled FileNotFoundError from
    # a directory mkdir never created.
    if not _SLUG_PATTERN.match(common_name):
        _err(
            f"{common_name!r} is not a valid organisation slug. Use lowercase "
            "letters, digits and hyphens, starting and ending with a letter or "
            "digit (3-64 characters)."
        )
        raise typer.Exit(code=2)

    out_dir.mkdir(parents=True, exist_ok=True)
    key_path = out_dir / f"{common_name}.key"
    csr_path = out_dir / f"{common_name}.csr"

    for path in (key_path, csr_path):
        if path.exists():
            _err(f"refusing to overwrite existing {path}")
            raise typer.Exit(code=2)

    # P-384 to match the hosting ISAC's issuing CA.
    key = ec.generate_private_key(ec.SECP384R1())

    attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    if organization:
        attributes.insert(0, x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization))

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name(attributes))
        .sign(key, hashes.SHA384())
    )

    # Written before the key material so the file exists with the right mode
    # before it has anything worth protecting in it.
    key_path.touch(mode=0o600)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    csr_path.write_bytes(csr.public_bytes(serialization.Encoding.PEM))

    _err(f"private key : {key_path}  (keep this; it never leaves this machine)")
    _err(f"CSR          : {csr_path}  (send this to the hosting ISAC)")


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------
@app.command()
def whoami(url: BaseUrl = None, cert: CertOpt = None, key: KeyOpt = None, ca: CaOpt = None) -> None:
    """Show what the instance believes about this certificate.

    The fastest way to diagnose an enrolment or circle-membership problem.
    """
    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            identity = NativeClient(http).whoami()
    except AivsError as exc:
        _fail(exc)
    typer.echo(json.dumps(identity, indent=2))


@app.command()
def collections(
    url: BaseUrl = None, cert: CertOpt = None, key: KeyOpt = None, ca: CaOpt = None
) -> None:
    """List the collections this organisation may read."""
    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            found = TaxiiClient(http).collections()
    except AivsError as exc:
        _fail(exc)

    if not found:
        _err("no collections — this organisation is not yet in any sharing circle")
        return
    for entry in found:
        writable = " (contributor)" if entry.get("can_write") else ""
        typer.echo(f"{entry['id']}  {_safe(entry['title'])}{writable}")


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------
def _poll_collection(
    taxii: TaxiiClient,
    cursors: CursorStore,
    collection_id: str,
    *,
    since: str | None,
    full: bool,
) -> int:
    """Emit one collection's new objects on stdout, then advance its cursor.

    Returns the number of objects emitted.
    """
    start = since if since else (None if full else cursors.get(collection_id))
    taxii.last_date_added = None
    count = 0
    for obj in taxii.objects(collection_id, added_after=start):
        typer.echo(json.dumps(obj, separators=(",", ":")))
        count += 1

    # Advance only after the objects are out; if the pipe broke, the
    # next run should collect them again rather than skip them.
    latest = getattr(taxii, "last_date_added", None)
    if latest and not full:
        cursors.set(collection_id, latest)
    return count


@app.command()
def poll(
    collection: Annotated[str, typer.Argument(help="Collection id, or 'all'.")] = "all",
    since: Annotated[
        str | None,
        typer.Option("--since", help="Timestamp to collect from. Default: resume from cursor."),
    ] = None,
    full: Annotated[
        bool, typer.Option("--full", help="Ignore the cursor and collect all.")
    ] = False,
    url: BaseUrl = None,
    cert: CertOpt = None,
    key: KeyOpt = None,
    ca: CaOpt = None,
) -> None:
    """Collect new intelligence, emitting one STIX object per line on stdout.

    Newline-delimited JSON so it pipes directly into an ingest pipeline:

        aivs poll | your-siem-ingest

    Cursors are kept per collection, so running this from cron collects only
    what arrived since the last run. Nothing is written to the cursor until the
    objects have been emitted, so a failure part-way through re-collects rather
    than silently skipping.
    """
    config, http = _connect(url, cert, key, ca)
    cursors = CursorStore(config.state_dir, config.base_url)

    try:
        with http:
            taxii = TaxiiClient(http)
            targets = (
                [entry["id"] for entry in taxii.collections()]
                if collection == "all"
                else [collection]
            )
            if not targets:
                _err("no collections available to this organisation")
                return

            total = 0
            for collection_id in targets:
                count = _poll_collection(taxii, cursors, collection_id, since=since, full=full)
                total += count
                _err(f"{collection_id}: {count} object(s)")
            _err(f"collected {total} object(s)")
    except AivsError as exc:
        _fail(exc)


# ---------------------------------------------------------------------------
# Submission
# ---------------------------------------------------------------------------
@app.command()
def submit(
    bundle_path: Annotated[Path, typer.Argument(help="Path to a STIX 2.1 bundle.")],
    title: Annotated[str, typer.Option("--title", help="Short title for the finding.")],
    scope: Annotated[
        str,
        typer.Option(
            "--scope",
            help="own_product, own_estate, or ai_system.",
        ),
    ],
    tlp: Annotated[str, typer.Option("--tlp")] = "amber",
    summary: Annotated[str | None, typer.Option("--summary")] = None,
    anonymous: Annotated[
        bool,
        typer.Option("--anonymous", help="Withhold our identity from other members."),
    ] = False,
    send: Annotated[
        bool, typer.Option("--send", help="Hand to the ISAC for review immediately.")
    ] = False,
    url: BaseUrl = None,
    cert: CertOpt = None,
    key: KeyOpt = None,
    ca: CaOpt = None,
) -> None:
    """File a finding.

    Creates a draft. Add ``--send`` to hand it to the hosting ISAC for review in
    the same command; without it the submission stays editable.
    """
    if not bundle_path.is_file():
        _err(f"no such file: {bundle_path}")
        raise typer.Exit(code=2)
    try:
        bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err(f"{bundle_path} is not valid JSON: {exc}")
        raise typer.Exit(code=2) from exc

    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            native = NativeClient(http)
            created = native.create_submission(
                title=title,
                discovery_scope=scope,
                bundle=bundle,
                summary=summary,
                tlp=tlp,
                anonymous=anonymous,
            )
            _err(f"created draft {created['id']}")
            if send:
                sent = native.submit(created["id"])
                _err(f"submitted for review (state: {sent['state']})")
            typer.echo(json.dumps(created, indent=2))
    except AivsError as exc:
        _fail(exc)


@app.command()
def ack(
    submission_id: Annotated[str, typer.Argument()],
    ack_type: Annotated[
        str, typer.Option("--type", help="acknowledged or actioned.")
    ] = "acknowledged",
    note: Annotated[str | None, typer.Option("--note")] = None,
    url: BaseUrl = None,
    cert: CertOpt = None,
    key: KeyOpt = None,
    ca: CaOpt = None,
) -> None:
    """Record that we acknowledged or acted on a warning.

    Retrieval is recorded automatically by the instance when content is
    delivered; this is for asserting what your firm did about it afterwards.
    """
    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            result = NativeClient(http).acknowledge(submission_id, ack_type, note)
    except AivsError as exc:
        _fail(exc)
    _err(f"recorded {result['ack_type']}")


@app.command()
def receipts(
    submission_id: Annotated[str, typer.Argument()],
    url: BaseUrl = None,
    cert: CertOpt = None,
    key: KeyOpt = None,
    ca: CaOpt = None,
) -> None:
    """Show who received and acted on one of our submissions."""
    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            rows = NativeClient(http).receipts(submission_id)
    except AivsError as exc:
        _fail(exc)

    if not rows:
        _err("no receipts recorded yet")
        return
    for row in rows:
        typer.echo(
            f"{row['org_slug']:24} {row['ack_type']:14} "
            f"first={row['first_at']}  n={row['occurrences']}"
        )


@app.command(name="submissions")
def list_submissions(
    state: Annotated[str | None, typer.Option("--state")] = None,
    url: BaseUrl = None,
    cert: CertOpt = None,
    key: KeyOpt = None,
    ca: CaOpt = None,
) -> None:
    """List our submissions."""
    _config, http = _connect(url, cert, key, ca)
    try:
        with http:
            rows = NativeClient(http).list_submissions(state)
    except AivsError as exc:
        _fail(exc)

    if not rows:
        _err("no submissions")
        return
    for row in rows:
        typer.echo(f"{row['id']}  {row['state']:12} {row['tlp']:12} {_safe(row['title'])}")


def main() -> None:  # pragma: no cover - console entry point
    try:
        app()
    except KeyboardInterrupt:  # pragma: no cover
        sys.exit(130)


if __name__ == "__main__":  # pragma: no cover
    main()
