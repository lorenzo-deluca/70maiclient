from __future__ import annotations

import pytest

from client70mai.client import MaiClient

from .helpers import FakeSession, RecordingSignatureProvider

TEST_UUID = "3FA85F64-5717-4562-B3FC-2C963F66AFA6"


@pytest.fixture
def fake_session() -> FakeSession:
    return FakeSession()


@pytest.fixture
def provider() -> RecordingSignatureProvider:
    return RecordingSignatureProvider()


@pytest.fixture
def client(fake_session: FakeSession, provider: RecordingSignatureProvider) -> MaiClient:
    """A MaiClient wired to the fake session/provider, not yet logged in."""
    return MaiClient(uuid=TEST_UUID, session=fake_session, signature_provider=provider)


@pytest.fixture
def authed_client(client: MaiClient) -> MaiClient:
    """Same client, pre-authenticated (token set directly, no real login()
    call) so tests can exercise endpoints that require a session."""
    client.token = "existing-session-token"
    return client
