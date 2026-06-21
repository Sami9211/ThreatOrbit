"""SSE stream tickets (audit B3): the live stream is opened with a short-lived,
single-use ticket minted from the session — the long-lived JWT is never put in
the stream URL, and a ticket can't be replayed as a session token.
"""
import pytest
from fastapi import HTTPException

from dashboard_api.routers import stream as stream_mod


def test_ticket_endpoint_requires_auth(client):
    assert client.post("/stream/ticket").status_code in (401, 403)


def test_ticket_minted_and_single_use(client, auth):
    r = client.post("/stream/ticket", headers=auth)
    assert r.status_code == 200
    body = r.json()
    ticket = body["ticket"]
    assert ticket and body["expires_in"] == 60

    # First use resolves a principal…
    principal = stream_mod._validate(ticket, "")
    assert principal["id"]
    # …a second use of the SAME ticket is rejected (single-use).
    with pytest.raises(HTTPException):
        stream_mod._validate(ticket, "")


def test_stream_ticket_not_usable_as_session_token(client, auth):
    ticket = client.post("/stream/ticket", headers=auth).json()["ticket"]
    # The 60s SSE ticket must NOT authenticate a normal API call.
    r = client.get("/auth/sessions", headers={"Authorization": f"Bearer {ticket}"})
    assert r.status_code == 401


def test_stream_requires_a_credential(client):
    # No ticket and no token → rejected (not an open stream).
    with pytest.raises(HTTPException):
        stream_mod._validate("", "")
