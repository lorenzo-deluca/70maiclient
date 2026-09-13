"""Shared test doubles: no real network traffic anywhere in this suite.

FakeSession stands in for requests.Session (passed to MaiClient's
`session=` constructor arg) so every test controls exactly what
"the server" returns, without mocking `requests` internals.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Union


class FakeResponse:
    """Minimal stand-in for requests.Response, including the context-manager
    protocol download_media() uses (`with session.get(...) as resp:`)."""

    def __init__(
        self,
        *,
        json_data: Any = None,
        status_code: int = 200,
        text: str = "",
        ok: Optional[bool] = None,
        chunks: Optional[List[bytes]] = None,
        json_error: bool = False,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self.ok = ok if ok is not None else (200 <= status_code < 400)
        self._json_data = json_data
        self._json_error = json_error
        self._chunks = chunks or []

    def json(self) -> Any:
        if self._json_error:
            raise ValueError("Invalid JSON (test double)")
        return self._json_data

    def iter_content(self, chunk_size: Optional[int] = None):
        yield from self._chunks

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc_info: Any) -> bool:
        return False


def envelope(result_body_object: Any = None, error: bool = False, error_code: int = 0,
             error_message: Optional[str] = None) -> Dict[str, Any]:
    """Build a MaiCommonResult<T>-shaped body, the way every real response
    from eu-api.70mai.com is shaped."""
    return {
        "error": error,
        "errorCode": error_code,
        "errorMessage": error_message,
        "resultBodyObject": result_body_object,
    }


class FakeSession:
    """Records every call; returns queued responses/exceptions in order, or
    a default success envelope with `resultBodyObject: None` if nothing was
    queued."""

    def __init__(self) -> None:
        self.headers: Dict[str, str] = {}
        self.post_calls: List[SimpleNamespace] = []
        self.get_calls: List[SimpleNamespace] = []
        self._post_queue: List[Union[FakeResponse, Exception]] = []
        self._get_queue: List[Union[FakeResponse, Exception]] = []

    def queue_post(self, item: Union[FakeResponse, Exception]) -> None:
        self._post_queue.append(item)

    def queue_get(self, item: Union[FakeResponse, Exception]) -> None:
        self._get_queue.append(item)

    def post(self, url: str, data: Optional[str] = None, timeout: Optional[float] = None) -> FakeResponse:
        self.post_calls.append(SimpleNamespace(url=url, data=data, timeout=timeout))
        item = self._post_queue.pop(0) if self._post_queue else FakeResponse(json_data=envelope())
        if isinstance(item, Exception):
            raise item
        return item

    def get(
        self, url: str, stream: Optional[bool] = None, timeout: Optional[float] = None
    ) -> FakeResponse:
        self.get_calls.append(SimpleNamespace(url=url, stream=stream, timeout=timeout))
        item = self._get_queue.pop(0) if self._get_queue else FakeResponse()
        if isinstance(item, Exception):
            raise item
        return item


class RecordingSignatureProvider:
    """Test double for SignatureProvider: never computes a real hash, just
    records what it was asked to sign so tests can assert on request-body
    assembly without duplicating the md5 formulas (those are covered on
    their own in test_signing.py)."""

    SIGNATURE = "RECORDED-SIG"
    PASSWORD_HASH = "RECORDED-PWHASH"
    LOGIN_SIGNATURE = "RECORDED-LOGIN-SIG"

    def __init__(self) -> None:
        self.sign_calls: List[Dict[str, Any]] = []
        self.hash_password_calls: List[str] = []
        self.sign_login_calls: List[SimpleNamespace] = []

    def sign(self, params: Dict[str, Any]) -> str:
        self.sign_calls.append(dict(params))
        return self.SIGNATURE

    def hash_password(self, plain_password: str) -> str:
        self.hash_password_calls.append(plain_password)
        return self.PASSWORD_HASH

    def sign_login(
        self, device_type: int, email: str, password_hash: str, ts: int, channel: int
    ) -> str:
        self.sign_login_calls.append(
            SimpleNamespace(
                device_type=device_type, email=email, password_hash=password_hash, ts=ts, channel=channel
            )
        )
        return self.LOGIN_SIGNATURE


def last_sent_body(fake_session: FakeSession) -> Dict[str, Any]:
    """Decode the JSON body of the most recent POST."""
    raw = fake_session.post_calls[-1].data
    assert raw is not None, "expected a JSON body, got None"
    return json.loads(raw)
