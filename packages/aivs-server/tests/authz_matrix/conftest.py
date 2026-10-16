"""Fixtures shared by the matrix and the sweeps that walk its routes."""

from __future__ import annotations

import pytest

from tests.authz_matrix.world import Factories


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
