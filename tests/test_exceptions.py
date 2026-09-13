from __future__ import annotations

import pytest

from client70mai.exceptions import (
    MaiConnectionError,
    MaiError,
    MaiHTTPError,
    MaiNotAuthenticatedError,
    MaiResponseFormatError,
    MaiTimeoutError,
    SigningNotImplementedError,
)


@pytest.mark.parametrize(
    "exc_type",
    [
        SigningNotImplementedError,
        MaiConnectionError,
        MaiTimeoutError,
        MaiHTTPError,
        MaiResponseFormatError,
        MaiNotAuthenticatedError,
    ],
)
def test_all_exceptions_derive_from_mai_error(exc_type: type) -> None:
    assert issubclass(exc_type, MaiError)


def test_mai_http_error_carries_status_url_and_body() -> None:
    err = MaiHTTPError(404, "https://eu-api.70mai.com/x", "not found")
    assert err.status_code == 404
    assert err.url == "https://eu-api.70mai.com/x"
    assert err.body == "not found"
    assert "404" in str(err)
    assert "https://eu-api.70mai.com/x" in str(err)
    assert "not found" in str(err)


def test_mai_http_error_truncates_long_body_in_message() -> None:
    long_body = "x" * 1000
    err = MaiHTTPError(500, "https://eu-api.70mai.com/x", long_body)
    assert err.body == long_body  # attribute keeps the full body
    assert len(str(err)) < len(long_body)  # message truncates it
