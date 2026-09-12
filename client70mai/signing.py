"""
Signing scheme for the 70mai API.

General `sig` (every call except userLoginPwd):
    sig = md5(token + uuid + str(channel) + str(ts) + SECRET).hexdigest()
Endpoint-specific fields (e.g. `deviceId`) are NOT part of the signed
content, only token/uuid/channel/ts.

`passWord` + login `sig` (userLoginPwd only, different construction):
    passWord = md5("dashcam" + plain_password + SECRET).hexdigest()
    sig = md5(str(deviceType) + email + "null" + passWord + str(ts) + SECRET).hexdigest()
Note the literal 4-character string "null" concatenated into the login
sig (not omitted, not JSON null): the signature won't match without it.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, Protocol, runtime_checkable

from .exceptions import SigningNotImplementedError


@runtime_checkable
class SignatureProvider(Protocol):
    def sign(self, params: Dict[str, Any]) -> str:
        """Return the value of the 'sig' field for this request body.

        `params` is the full body dict *before* 'sig' is added (it does
        include 'ts', 'uuid', 'channel', 'token' when present, and every
        endpoint-specific field).
        """
        ...

    def hash_password(self, plain_password: str) -> str:
        """Return the value of the 'passWord' field for userLoginPwd."""
        ...

    def sign_login(self, device_type: int, email: str, password_hash: str, ts: int, channel: int) -> str:
        """Return the value of the 'sig' field for userLoginPwd specifically
        (different construction than every other endpoint, see the module
        docstring). `password_hash` is the already-computed 'passWord'
        value (from `hash_password`)."""
        ...


class BanyacKeyMd5SignatureProvider:
    """Default signer, implementing the sig/passWord formulas described in
    the module docstring."""

    # Shared signing secret for channel 3001013 (and 2001001, used by the
    # login passWord hash).
    SECRET = "0c5269735ed4b129"

    # Fixed prefix concatenated before the plaintext password in the login
    # passWord hash.
    PASSWORD_PREFIX = "dashcam"

    def sign(self, params: Dict[str, Any]) -> str:
        token = params.get("token") or ""
        uuid_ = params["uuid"]
        channel = params["channel"]
        ts = params["ts"]
        data = f"{token}{uuid_}{channel}{ts}{self.SECRET}"
        return hashlib.md5(data.encode("utf-8")).hexdigest()

    def hash_password(self, plain_password: str) -> str:
        data = f"{self.PASSWORD_PREFIX}{plain_password}{self.SECRET}"
        return hashlib.md5(data.encode("utf-8")).hexdigest()

    def sign_login(self, device_type: int, email: str, password_hash: str, ts: int, channel: int) -> str:
        data = f"{device_type}{email}null{password_hash}{ts}{self.SECRET}"
        return hashlib.md5(data.encode("utf-8")).hexdigest()


class UnimplementedSignatureProvider:
    """Fails loudly instead of computing anything. Kept for cases where you
    want to force an explicit choice rather than relying on the default
    signer."""

    def sign(self, params: Dict[str, Any]) -> str:
        raise SigningNotImplementedError(
            "Use BanyacKeyMd5SignatureProvider (MaiClient's default) "
            "instead, or supply your own."
        )

    def hash_password(self, plain_password: str) -> str:
        raise SigningNotImplementedError(
            "Use BanyacKeyMd5SignatureProvider instead, or supply your own."
        )

    def sign_login(self, device_type: int, email: str, password_hash: str, ts: int, channel: int) -> str:
        raise SigningNotImplementedError(
            "Use BanyacKeyMd5SignatureProvider instead, or supply your own."
        )
