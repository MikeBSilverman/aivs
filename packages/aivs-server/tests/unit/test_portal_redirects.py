"""The portal redirects only to its own pages (CodeQL py/url-redirection).

Every redirect target is built from constants and typed path parameters, so
none could be steered off-site; CodeQL cannot see the typing and flagged two.
The helper makes it a checked property, and the guard keeps it the only way
a portal module redirects.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aivs_server.portal.shared import redirect_to_identity_provider, redirect_within_portal

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


_ISSUER = "https://idp.member-tenant.test/oauth2/default"


@pytest.mark.requirement("SF-65")
def test_the_identity_providers_own_authorization_endpoint_is_a_redirect():
    url = "https://idp.member-tenant.test/oauth2/default/v1/authorize?state=s"
    response = redirect_to_identity_provider(url, _ISSUER)
    assert response.status_code == 303
    assert response.headers["location"] == url


@pytest.mark.requirement("SF-65")
@pytest.mark.parametrize(
    "url",
    [
        "http://idp.member-tenant.test/oauth2/default/v1/authorize",
        "https://elsewhere.test/authorize",
        "https://idp.member-tenant.test@elsewhere.test/authorize",
        "https://idp.member-tenant.test.elsewhere.test/authorize",
        "//elsewhere.test/authorize",
    ],
)
def test_an_authorization_endpoint_off_the_issuers_origin_is_refused(url):
    with pytest.raises(ValueError, match="identity provider's origin"):
        redirect_to_identity_provider(url, _ISSUER)
