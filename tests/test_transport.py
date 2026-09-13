from __future__ import annotations

import json

import pytest
import requests

from client70mai.client import CHANNEL_ID, DEFAULT_BASE_URL, MaiClient
from client70mai.exceptions import (
    MaiConnectionError,
    MaiHTTPError,
    MaiNotAuthenticatedError,
    MaiResponseFormatError,
    MaiTimeoutError,
)

from .helpers import FakeResponse, FakeSession, envelope, last_sent_body

TEST_UUID = "3FA85F64-5717-4562-B3FC-2C963F66AFA6"


# ------------------------------------------------------------------ #
# construction
# ------------------------------------------------------------------ #
def test_constructor_defaults() -> None:
    client = MaiClient(uuid=TEST_UUID)
    assert client.uuid == TEST_UUID
    assert client.base_url == DEFAULT_BASE_URL
    assert client.token is None
    assert client.device_token is None
    assert client.timeout == 15.0
    assert isinstance(client.session, requests.Session)
    # DEFAULT_HEADERS must be merged into the session, not replace it.
    assert client.session.headers["Content-Type"] == "application/json;application/x-www-form-urlencoded"


def test_constructor_strips_trailing_slash_from_base_url() -> None:
    client = MaiClient(uuid=TEST_UUID, base_url="https://example.com/")
    assert client.base_url == "https://example.com"


def test_constructor_accepts_custom_session_and_device_token(fake_session: FakeSession) -> None:
    client = MaiClient(uuid=TEST_UUID, session=fake_session, device_token="fcm-token", timeout=5.0)
    assert client.session is fake_session
    assert client.device_token == "fcm-token"
    assert client.timeout == 5.0


# ------------------------------------------------------------------ #
# _post
# ------------------------------------------------------------------ #
def test_post_returns_parsed_json(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"ok": True})))
    result = client._post("/some/path", {"a": 1})
    assert result == envelope({"ok": True})


def test_post_sends_json_encoded_body_and_timeout(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope()))
    client._post("/some/path", {"a": 1, "b": "two"})
    call = fake_session.post_calls[-1]
    assert call.url == f"{DEFAULT_BASE_URL}/some/path"
    assert json.loads(call.data) == {"a": 1, "b": "two"}
    assert call.timeout == client.timeout


def test_post_with_none_body_sends_no_data(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope()))
    client._post("/baseServiceApi/V2/getTs", None)
    assert fake_session.post_calls[-1].data is None


def test_post_raises_mai_http_error_on_non_ok_response(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(status_code=500, ok=False, text="server exploded"))
    with pytest.raises(MaiHTTPError) as exc_info:
        client._post("/some/path", {})
    err = exc_info.value
    assert err.status_code == 500
    assert err.url == f"{DEFAULT_BASE_URL}/some/path"
    assert err.body == "server exploded"
    assert "500" in str(err)


def test_post_raises_mai_timeout_error(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(requests.Timeout("timed out"))
    with pytest.raises(MaiTimeoutError):
        client._post("/some/path", {})


def test_post_raises_mai_connection_error(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(requests.ConnectionError("dns failure"))
    with pytest.raises(MaiConnectionError):
        client._post("/some/path", {})


def test_post_raises_mai_response_format_error_on_invalid_json(
    client: MaiClient, fake_session: FakeSession
) -> None:
    fake_session.queue_post(FakeResponse(json_error=True, text="<html>not json</html>"))
    with pytest.raises(MaiResponseFormatError):
        client._post("/some/path", {})


# ------------------------------------------------------------------ #
# _signed_body
# ------------------------------------------------------------------ #
def test_signed_body_requires_token_by_default(client: MaiClient) -> None:
    assert client.token is None
    with pytest.raises(MaiNotAuthenticatedError):
        client._signed_body()


def test_signed_body_envelope_when_authenticated(authed_client: MaiClient, provider) -> None:
    body = authed_client._signed_body({"deviceId": "dev-1"})
    assert body["uuid"] == TEST_UUID
    assert body["channel"] == CHANNEL_ID
    assert isinstance(body["ts"], int)
    assert body["token"] == "existing-session-token"
    assert body["deviceId"] == "dev-1"
    assert body["sig"] == provider.SIGNATURE
    # sig must be computed over the body *including* the extra fields.
    assert provider.sign_calls[-1]["deviceId"] == "dev-1"
    assert "sig" not in provider.sign_calls[-1]


def test_signed_body_without_require_token_omits_token_field(client: MaiClient) -> None:
    body = client._signed_body(require_token=False)
    assert "token" not in body
    assert body["uuid"] == TEST_UUID
    assert body["channel"] == CHANNEL_ID


def test_signed_body_with_no_extra_fields(authed_client: MaiClient) -> None:
    body = authed_client._signed_body()
    assert set(body.keys()) == {"uuid", "channel", "ts", "token", "sig"}


# ------------------------------------------------------------------ #
# download_media
# ------------------------------------------------------------------ #
def test_download_media_writes_streamed_chunks(client: MaiClient, fake_session: FakeSession, tmp_path) -> None:
    fake_session.queue_get(FakeResponse(chunks=[b"hello ", b"world"]))
    dest = tmp_path / "video.mp4"

    client.download_media("https://cos.example.com/signed-url", str(dest))

    assert dest.read_bytes() == b"hello world"
    call = fake_session.get_calls[-1]
    assert call.url == "https://cos.example.com/signed-url"
    assert call.stream is True
    assert call.timeout == client.timeout


def test_download_media_raises_http_error_and_does_not_write_file(
    client: MaiClient, fake_session: FakeSession, tmp_path
) -> None:
    fake_session.queue_get(FakeResponse(status_code=403, ok=False, text="Forbidden"))
    dest = tmp_path / "video.mp4"

    with pytest.raises(MaiHTTPError):
        client.download_media("https://cos.example.com/signed-url", str(dest))

    assert not dest.exists()


def test_download_media_raises_mai_timeout_error(client: MaiClient, fake_session: FakeSession, tmp_path) -> None:
    fake_session.queue_get(requests.Timeout("timed out"))
    with pytest.raises(MaiTimeoutError):
        client.download_media("https://cos.example.com/signed-url", str(tmp_path / "video.mp4"))


def test_download_media_raises_mai_connection_error(
    client: MaiClient, fake_session: FakeSession, tmp_path
) -> None:
    fake_session.queue_get(requests.ConnectionError("dns failure"))
    with pytest.raises(MaiConnectionError):
        client.download_media("https://cos.example.com/signed-url", str(tmp_path / "video.mp4"))
