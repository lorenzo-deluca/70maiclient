from __future__ import annotations


class MaiError(Exception):
    """Base class for all 70mai client errors."""


class SigningNotImplementedError(MaiError):
    """Raised when a request needs client-side crypto (sig / passWord hash)
    that the active SignatureProvider does not implement."""


class MaiConnectionError(MaiError):
    """Underlying HTTP transport failed (DNS, TCP, TLS)."""


class MaiTimeoutError(MaiError):
    """Request exceeded the configured timeout."""


class MaiHTTPError(MaiError):
    def __init__(self, status_code: int, url: str, body: str) -> None:
        self.status_code = status_code
        self.url = url
        self.body = body
        super().__init__(f"HTTP {status_code} calling {url}: {body[:500]}")


class MaiResponseFormatError(MaiError):
    """Response was not valid JSON, or lacked a field this library needs.

    Some endpoints' resultBodyObject shape is not yet confirmed; check
    each MaiClient method's docstring for what is/isn't documented.
    """


class MaiNotAuthenticatedError(MaiError):
    """An authenticated call was attempted before login()."""
