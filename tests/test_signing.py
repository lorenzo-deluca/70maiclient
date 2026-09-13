"""Golden-vector tests for the recovered signing formulas.

Expected hashes below were computed independently (a standalone script,
not by importing BanyacKeyMd5SignatureProvider) from the exact formulas
documented in signing.py's module docstring, using SECRET =
"0c5269735ed4b129" and fixed, synthetic (non-real-account) inputs:

    sign():       md5(token + uuid + str(channel) + str(ts) + SECRET)
    hash_password(): md5("dashcam" + plain_password + SECRET)
    sign_login(): md5(str(device_type) + email + "null" + password_hash
                       + str(ts) + SECRET)

If any of these ever change, either the server-side scheme changed (real
traffic should confirm that first) or something broke the implementation.
"""
from __future__ import annotations

import pytest

from client70mai.exceptions import SigningNotImplementedError
from client70mai.signing import BanyacKeyMd5SignatureProvider, UnimplementedSignatureProvider

TOKEN = "test-token"
UUID = "TEST-UUID-0000"
CHANNEL = 3001013
TS = 1700000000000
PLAIN_PASSWORD = "hunter2"
EMAIL = "test@example.com"
DEVICE_TYPE = 3


@pytest.fixture
def provider() -> BanyacKeyMd5SignatureProvider:
    return BanyacKeyMd5SignatureProvider()


def test_sign_with_token(provider: BanyacKeyMd5SignatureProvider) -> None:
    params = {"token": TOKEN, "uuid": UUID, "channel": CHANNEL, "ts": TS}
    assert provider.sign(params) == "713a28073109fbe325241623d0bfda61"


def test_sign_without_token_uses_empty_string(provider: BanyacKeyMd5SignatureProvider) -> None:
    # get_ts()/login() precede having a token; sign() must not KeyError.
    params = {"uuid": UUID, "channel": CHANNEL, "ts": TS}
    assert provider.sign(params) == "3e6db526dd12ea2e1cdb8fbcaacfb62b"


def test_sign_ignores_endpoint_specific_fields(provider: BanyacKeyMd5SignatureProvider) -> None:
    """Only token/uuid/channel/ts feed the signature; extra request fields
    (deviceId, pageCount, ...) must not change it."""
    base = {"token": TOKEN, "uuid": UUID, "channel": CHANNEL, "ts": TS}
    with_extra = {**base, "deviceId": "some-device", "pageCount": 20}
    assert provider.sign(with_extra) == provider.sign(base)


def test_hash_password(provider: BanyacKeyMd5SignatureProvider) -> None:
    assert provider.hash_password(PLAIN_PASSWORD) == "2b7ccc470184853ef69ccf33bac1e693"


def test_hash_password_is_deterministic(provider: BanyacKeyMd5SignatureProvider) -> None:
    assert provider.hash_password(PLAIN_PASSWORD) == provider.hash_password(PLAIN_PASSWORD)


def test_sign_login(provider: BanyacKeyMd5SignatureProvider) -> None:
    password_hash = provider.hash_password(PLAIN_PASSWORD)
    sig = provider.sign_login(DEVICE_TYPE, EMAIL, password_hash, TS, CHANNEL)
    assert sig == "96cdcc6142aac24bf4721e32aaa71736"


def test_sign_login_includes_literal_null_marker(provider: BanyacKeyMd5SignatureProvider) -> None:
    """The login sig concatenates the literal 4-char string "null" (not an
    empty string, not omitted) between email and passWord. Regression
    guard: a build that dropped or JSON-encoded that marker would still
    produce *a* hash, just the wrong one, and silently fail auth against
    the real server."""
    password_hash = provider.hash_password(PLAIN_PASSWORD)
    with_null = provider.sign_login(DEVICE_TYPE, EMAIL, password_hash, TS, CHANNEL)

    class NoNullProvider(BanyacKeyMd5SignatureProvider):
        def sign_login(self, device_type, email, password_hash, ts, channel):  # type: ignore[override]
            import hashlib

            data = f"{device_type}{email}{password_hash}{ts}{self.SECRET}"
            return hashlib.md5(data.encode("utf-8")).hexdigest()

    without_null = NoNullProvider().sign_login(DEVICE_TYPE, EMAIL, password_hash, TS, CHANNEL)
    assert with_null != without_null


def test_unimplemented_signature_provider_sign_raises() -> None:
    with pytest.raises(SigningNotImplementedError):
        UnimplementedSignatureProvider().sign({"uuid": UUID, "channel": CHANNEL, "ts": TS})


def test_unimplemented_signature_provider_hash_password_raises() -> None:
    with pytest.raises(SigningNotImplementedError):
        UnimplementedSignatureProvider().hash_password(PLAIN_PASSWORD)


def test_unimplemented_signature_provider_sign_login_raises() -> None:
    with pytest.raises(SigningNotImplementedError):
        UnimplementedSignatureProvider().sign_login(DEVICE_TYPE, EMAIL, "hash", TS, CHANNEL)
