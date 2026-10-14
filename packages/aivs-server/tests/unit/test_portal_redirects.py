"""The portal redirects only to its own pages (CodeQL py/url-redirection).

Every redirect target is built from constants and typed path parameters, so
none could be steered off-site; CodeQL cannot see the typing and flagged two.
The helper makes it a checked property, and the guard keeps it the only way
a portal module redirects.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aivs_server.portal.shared import redirect_within_portal

PORTAL = Path(__file__).resolve().parents[2] / "src" / "aivs_server" / "portal"


@pytest.mark.parametrize("path", ["/portal/", "/portal/submissions/0f6e", "/portal/admin/orgs"])
def test_a_portal_page_is_a_redirect(path):
    assert redirect_within_portal(path).headers["location"] == path


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.example/",
        "//evil.example/portal/",
        "/portal//evil.example",
        "/portal/\\\\evil.example",
        "/api/v1/whoami",
        "portal/relative",
    ],
)
def test_anything_else_is_refused(path):
    with pytest.raises(ValueError, match="outside the portal"):
        redirect_within_portal(path)


def test_no_portal_module_builds_its_own_redirect():
    builders = [
        module.name
        for module in PORTAL.glob("*.py")
        if module.name != "shared.py" and "RedirectResponse(" in module.read_text("utf-8")
    ]
    assert builders == []
