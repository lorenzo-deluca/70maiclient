from __future__ import annotations

import pytest

from client70mai.client import CHANNEL_ID, DEFAULT_BASE_URL, MaiClient
from client70mai.exceptions import MaiResponseFormatError

from .helpers import FakeResponse, FakeSession, envelope, last_sent_body

TEST_UUID = "3FA85F64-5717-4562-B3FC-2C963F66AFA6"
EMAIL = "test@example.com"
PASSWORD = "hunter2"


def test_login_success_sets_token_and_returns_raw_response(
    client: MaiClient, fake_session: FakeSession
) -> None:
    resp = envelope({"token": "brand-new-token", "userID": 123, "userName": "M-DRV_123"})
    fake_session.queue_post(FakeResponse(json_data=resp))

    result = client.login(EMAIL, PASSWORD)

    assert result == resp
    assert client.token == "brand-new-token"


def test_login_sends_expected_body_and_uses_login_signing(
    client: MaiClient, fake_session: FakeSession, provider
) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"token": "t"})))

    client.login(EMAIL, PASSWORD, device_type=3)

    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/accountApi/V3/userLoginPwd"
    body = last_sent_body(fake_session)
    assert body["email"] == EMAIL
    assert body["channel"] == CHANNEL_ID
    assert body["uuid"] == TEST_UUID
    assert body["deviceType"] == 3
    assert body["passWord"] == provider.PASSWORD_HASH
    assert body["sig"] == provider.LOGIN_SIGNATURE
    assert "deviceToken" not in body  # constructor didn't set one

    assert provider.hash_password_calls == [PASSWORD]
    login_call = provider.sign_login_calls[-1]
    assert login_call.device_type == 3
    assert login_call.email == EMAIL
    assert login_call.password_hash == provider.PASSWORD_HASH
    assert login_call.channel == CHANNEL_ID


def test_login_includes_device_token_when_set_on_constructor(
    fake_session: FakeSession, provider
) -> None:
    client = MaiClient(uuid=TEST_UUID, session=fake_session, signature_provider=provider, device_token="fcm-abc")
    fake_session.queue_post(FakeResponse(json_data=envelope({"token": "t"})))

    client.login(EMAIL, PASSWORD)

    assert last_sent_body(fake_session)["deviceToken"] == "fcm-abc"


def test_login_raises_when_response_has_no_token(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"userID": 123})))  # no "token" key

    with pytest.raises(MaiResponseFormatError):
        client.login(EMAIL, PASSWORD)

    assert client.token is None


def test_login_raises_when_server_reports_error(client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(
        FakeResponse(json_data=envelope(None, error=True, error_code=500001, error_message="invalid password"))
    )

    with pytest.raises(MaiResponseFormatError):
        client.login(EMAIL, PASSWORD)

    assert client.token is None


def test_logout_clears_token_and_hits_expected_path(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(True)))

    result = authed_client.logout()

    assert result == envelope(True)
    assert authed_client.token is None
    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/accountApi/V3/userLogOut"


def test_logout_clears_token_even_on_server_error(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(None, error=True, error_code=1, error_message="boom")))

    authed_client.logout()

    assert authed_client.token is None
