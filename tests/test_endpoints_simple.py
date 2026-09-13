"""Endpoints that just wrap self._signed_body(extra-or-none) with a fixed
path and (at most) a couple of pass-through fields. Table-driven: each
case checks the HTTP path hit, the extra body fields sent, that the
method requires an authenticated client, and that the raw response dict
comes back unmodified (no unwrapping of resultBodyObject).
"""
from __future__ import annotations

from typing import Any, Callable, Dict

import pytest

from client70mai.client import DEFAULT_BASE_URL, MaiClient
from client70mai.exceptions import MaiNotAuthenticatedError

from .helpers import FakeResponse, FakeSession, envelope, last_sent_body

SENTINEL = {"marker": "unwrapped-passthrough"}

# (method name, args, expected path, expected extra body fields)
CASES: list[tuple[str, tuple, str, Dict[str, Any]]] = [
    ("get_device_conf_file_url", (), "/baseServiceApi/V2/getDeviceConfFileUrl", {}),
    ("get_all_user_info", (), "/accountApi/getAllUserInfo", {}),
    ("get_user_country_code", (), "/accountApi/V4/getUserCountryCode", {}),
    ("get_account_notify_overview", (), "/accountApi/V4/getAccountNotifyOverview", {}),
    ("get_home_logos", (), "/advertisementApiV2/getHomeLogos", {}),
    ("get_dashcam_detail", ("dev-1",), "/dashcamApi/getDashcamDetail", {"deviceId": "dev-1"}),
    ("get_position", ("dev-1",), "/dashcamApi/getPosition", {"deviceId": "dev-1"}),
    ("get_sim_plugin_detail", ("dev-1",), "/dashcamApi/getSimPluginDetail", {"deviceId": "dev-1"}),
    ("get_supported_features", ("dev-1",), "/dashcamApi/getSupportedFeatures", {"deviceId": "dev-1"}),
    ("get_dashcam_status", ("dev-1",), "/dashcamApi/getDashcamStatus", {"deviceId": "dev-1"}),
    ("get_tutk_token", ("dev-1",), "/dashcamApi/getTutkToken", {"deviceId": "dev-1"}),
    ("get_device_switch", ("dev-1",), "/deviceSwitchApi/getDeviceSwitch", {"deviceId": "dev-1"}),
    ("get_offline_device_detail", ("aa:bb:cc:dd:ee:ff",), "/offlineDeviceApi/V2/getDeviceDetail", {"deviceId": "aa:bb:cc:dd:ee:ff"}),
    ("sim_plugin_support_out_power", ("dev-1",), "/offlineDeviceApi/V3/simPluginSupportOutPower", {"deviceId": "dev-1"}),
    ("get_websocket_address_for_app", ("dev-1",), "/accountApi/V3/getWebsocketAddressForApp", {"deviceId": "dev-1"}),
    ("update_device_token", ("fcm-xyz",), "/accountApi/V2/updateDeviceToken", {"deviceToken": "fcm-xyz"}),
    ("is_active_value_added_service", (7,), "/dashcamApi/isActiveValueAddedService", {"valueAddedService": 7}),
    ("get_file_details", (["file-1", "file-2"],), "/UserspaceApi/getFileDetails", {"fileIds": ["file-1", "file-2"]}),
    ("get_device_alarm", ("dev-1", "alarm-1"), "/dashcamApi/V2/getDeviceAlarm", {"deviceId": "dev-1", "alarmId": "alarm-1"}),
    ("living", ("dev-1", 8500), "/dashcamApi/living", {"deviceId": "dev-1", "time": 8500}),
]

CASE_IDS = [case[0] for case in CASES]


@pytest.mark.parametrize("method_name,args,expected_path,expected_extra", CASES, ids=CASE_IDS)
def test_simple_endpoint_requires_authentication(
    client: MaiClient, method_name: str, args: tuple, expected_path: str, expected_extra: Dict[str, Any]
) -> None:
    method: Callable = getattr(client, method_name)
    with pytest.raises(MaiNotAuthenticatedError):
        method(*args)


@pytest.mark.parametrize("method_name,args,expected_path,expected_extra", CASES, ids=CASE_IDS)
def test_simple_endpoint_hits_expected_path_and_body(
    authed_client: MaiClient,
    fake_session: FakeSession,
    provider,
    method_name: str,
    args: tuple,
    expected_path: str,
    expected_extra: Dict[str, Any],
) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(SENTINEL)))
    method: Callable = getattr(authed_client, method_name)

    result = method(*args)

    assert result == envelope(SENTINEL), "response must pass through unmodified"
    call = fake_session.post_calls[-1]
    assert call.url == f"{DEFAULT_BASE_URL}{expected_path}"

    body = last_sent_body(fake_session)
    for key, value in expected_extra.items():
        assert body[key] == value
    # standard signed envelope must always be present
    assert body["uuid"] == authed_client.uuid
    assert body["token"] == authed_client.token
    assert body["sig"] == provider.SIGNATURE


def test_update_device_token_also_updates_client_state(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(True)))
    authed_client.update_device_token("new-fcm-token")
    assert authed_client.device_token == "new-fcm-token"


def test_get_ts_is_unauthenticated_and_sends_no_body(client: MaiClient, fake_session: FakeSession) -> None:
    """get_ts() must work with no token at all, unlike every _signed_body()
    endpoint above."""
    fake_session.queue_post(FakeResponse(json_data=envelope(1735900000000)))

    result = client.get_ts()

    assert result == envelope(1735900000000)
    call = fake_session.post_calls[-1]
    assert call.url == f"{DEFAULT_BASE_URL}/baseServiceApi/V2/getTs"
    assert call.data is None
