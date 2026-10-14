"""A TOTP code signs the ISAC operator in once, through the real portal.

The unit tests prove the rule against the suite's own schema; this proves it
against the production image and its migrated database, where a missing
migration would show up as a sign-in that fails outright, or a replay that works.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from tests.e2e.stack import Stack, requires_stack

pytestmark = [pytest.mark.e2e, requires_stack]


def sign_in(stack: Stack, code: str) -> int:
    password = Path(stack.raw["isac"]["password_file"]).read_text(encoding="utf-8")
    with stack.client(stack.isac) as browser:
        form = browser.get("/portal/login")
        token = re.search(r'name="csrf_token" value="([^"]+)"', form.text)
        assert token, "the sign-in form carried no CSRF token"
        response = browser.post(
            "/portal/login",
            data={
                "email": stack.raw["isac"]["email"],
                "password": password,
                "totp_code": code,
                "csrf_token": token.group(1),
            },
        )
    return response.status_code


def test_a_code_signs_in_once_and_is_refused_the_second_time(stack):
    uri = Path(stack.raw["isac"]["totp_uri_file"]).read_text(encoding="utf-8")
    code = stack._unspent_totp_code(parse_qs(urlparse(uri).query)["secret"][0])

    assert sign_in(stack, code) == 303
    assert sign_in(stack, code) != 303
