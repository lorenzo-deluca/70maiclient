# 70maiclient

[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg)](https://github.com/custom-components/hacs)
![Version](https://img.shields.io/github/v/release/lorenzo-deluca/70maiclient)
![Downloads](https://img.shields.io/github/downloads/lorenzo-deluca/70maiclient/total)
[![](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/lorenzo-deluca)
[![buy me a coffee](https://img.shields.io/badge/support-buymeacoffee-222222.svg?style=flat-square)](https://www.buymeacoffee.com/lorenzodeluca)

A reverse-engineered Python client for the 70mai dashcam cloud API
(`eu-api.70mai.com`), built from a Postman-exported HTTPS capture of the
official iOS app and cross-checked against a decompiled Android APK.

# Disclaimer
It's **not affiliated with, endorsed by, or supported by 70mai**. The underlying API is undocumented and can change without notice.
If someone from 70mai would like to contribute or collaborate please contact me at [me@lorenzodeluca.dev](mailto:me@lorenzodeluca.dev?subject=[GitHub]70maiclient)

Used by [homeassistant-70mai](https://github.com/lorenzo-deluca/homeassistant-70mai),
a Home Assistant integration built on top of this client.

## Install

PyPI project name is `70maiclient` (PyPI names can't start with a digit
in a way that's also a valid Python identifier, so the *distribution*
name differs from the *import* name below):

```
pip install 70maiclient
```

## Usage

```python
import uuid

from client70mai import MaiClient

client = MaiClient(uuid=str(uuid.uuid4()).upper())

client.login(email="your-email", plain_password="your-password")
devices = client.get_all_device_for_user()
print(devices)

detail = client.get_dashcam_detail(device_id="your-device-id")
print(detail)

client.logout()
```

See [`example.py`](./example.py) for the same script standalone, and
[`console.py`](./console.py) for an interactive `rich`-based CLI that
exercises every endpoint (Italian-language prompts):

```
pip install "70maiclient[console]"
python3 console.py
```

## Layout

- `client70mai/client.py` — `MaiClient`, the only class consumers use. Holds
  the session, the device `uuid`, the auth `token`, and one method per API
  endpoint.
- `client70mai/signing.py` — `SignatureProvider` protocol plus
  `BanyacKeyMd5SignatureProvider`, the verified implementation of the
  server's request-signing scheme.
- `client70mai/exceptions.py` — `MaiError` and subclasses for transport,
  HTTP, response-parsing, auth, and signing failures.
- `client70mai/__init__.py` — public re-exports.
- `example.py` — minimal login → list devices → detail → logout script.
- `console.py` — interactive `rich`-based CLI over `MaiClient` for manually
  exercising every endpoint (Italian-language prompts).
- `tests/` — network-free `pytest` suite covering `client70mai/`; see
  "For Developers" below.
- `re/` — the APK, extracted dex/native libs, and Ghidra/pyghidra scripts
  used to reverse the signing algorithm. Not imported by `client70mai`,
  and not shipped in the PyPI package.
- `api-refs/` — captured traffic used as ground truth: Postman exports
  (request-only, no response bodies) and `*.proxymanlogv2` archives (a zip
  of one JSON file per request, `request`/`response` `bodyData` fields
  base64-encoded — these DO carry real response bodies, unlike the Postman
  exports, and are how most "CONFIRMED response" notes in `client.py` were
  derived). Not shipped in the PyPI package.

## Authentication model

There is no `Authorization` header or cookie anywhere in the captured
traffic. Every authenticated call instead sends, inside its JSON body:

- `uuid` — per-install device UUID (caller-supplied, any valid UUID string).
- `channel` — constant `3001013` (`CHANNEL_ID` in `client.py`) on every
  request, including unauthenticated ones.
- `ts` — client epoch-millisecond timestamp, unique per request.
- `token` — opaque session token from `userLoginPwd`/`login()`, reused
  verbatim until `logout()`.
- `sig` — `md5(token + uuid + channel + ts + SECRET)`, `SECRET` recovered
  from the Android app's native `libbanyackey.so` (see signing below).

`MaiClient._signed_body()` assembles this envelope for every method except
`login()` and `get_ts()`. Calling any endpoint before `login()` raises
`MaiNotAuthenticatedError`.

`login()` uses a different, separately-verified construction for the
`passWord` field (`md5("dashcam" + plain_password + SECRET)`) and its own
`sig` (`md5(deviceType + email + "null" + passWord + ts + SECRET)`) — see
the `signing.py` module docstring for the full decompilation trail.

## Response envelope

Every call returns the raw parsed JSON body as `Dict[str, Any]`, matching
the confirmed `MaiCommonResult<T>` shape:

```json
{"error": bool, "errorCode": int, "errorMessage": str, "resultBodyObject": T}
```

`resultBodyObject`'s shape (`T`) is **not unwrapped** by the client. The
original Postman captures had no successful response bodies at all, so
every schema was originally a best-effort guess; a 2026-09 Proxyman
capture (`api-refs/*.proxymanlogv2`) since confirmed the real
`resultBodyObject` shape for many endpoints (each such method's docstring
in `client.py` says "CONFIRMED response" and gives the shape). Endpoints
without that note are still unconfirmed — treat any field access on their
response as unverified until you observe real traffic. `login()` is the
one method that always reads a specific field
(`resultBodyObject.token`), confirmed, because the client cannot function
without it.

## For Developers

### Local setup

```
git clone https://github.com/lorenzo-deluca/70maiclient.git
cd 70maiclient
pip install -e ".[test,console]"
```

`-e` (editable install) means changes to `client70mai/` take effect
immediately, no reinstall needed. The `test` extra pulls in `pytest`; the
`console` extra pulls in `rich` for `console.py`.

### Running tests

```
pytest
```

`tests/` is a from-scratch, network-free suite — nothing in it ever
calls the real `eu-api.70mai.com`:

- `tests/helpers.py` provides a `FakeSession`/`FakeResponse` test double
  (passed as `MaiClient(session=...)`) plus a `RecordingSignatureProvider`
  that stands in for real signing, so endpoint tests can assert on
  request-body assembly without duplicating the md5 formulas.
- `tests/test_signing.py` covers those formulas on their own, with
  golden values computed independently of the implementation.
- `tests/test_endpoints_simple.py` / `tests/test_endpoints_detailed.py`
  cover every `MaiClient` method's HTTP path and request body.

When adding a new endpoint method, add a case to whichever of those two
files fits: `test_endpoints_simple.py`'s table for a fixed path plus a
couple of pass-through fields, `test_endpoints_detailed.py` for anything
with defaults, optional fields, or nested structures. Run
`pytest --cov=client70mai --cov-report=term-missing` (needs `pytest-cov`)
to check the new method is actually exercised.

### Continuous integration

`.github/workflows/ci.yml` runs the full test suite on every push/PR to
`master`, across Python 3.10–3.13. `.github/workflows/publish.yml` runs
the same suite again as a gate before building/publishing a release — a
release with failing tests never reaches PyPI.

### Extending the client

- New endpoints follow the existing pattern: build an `extra` dict of
  endpoint-specific fields, pass it to `self._signed_body(extra)`, POST via
  `self._post(path, body)`.
- Do not invent response-field extraction beyond what a real captured
  response confirms — raise/return the raw dict instead, as every existing
  method does.
- If you reverse-engineer a new signing variant, add it to
  `SignatureProvider` (protocol) and `BanyacKeyMd5SignatureProvider`
  (implementation) rather than hardcoding it in `client.py`.
- Live view's control plane is implemented (`get_tutk_token()`,
  `living()`), but the actual P2P video is ThroughTek/TUTK's proprietary
  IOTC SDK — out of scope for this REST client. See `client.py`'s
  module docstring for what that would take.
- Add a test for anything you add or change — see "Running tests" above.

### Releasing

Tagging a GitHub Release publishes to PyPI automatically via
`.github/workflows/publish.yml` (trusted publishing, no stored token).
Bump `version` in `pyproject.toml` before tagging.

## License

GNU AGPLv3 © Lorenzo De Luca
