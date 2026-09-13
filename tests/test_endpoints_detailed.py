"""Endpoints whose request body has defaults, optional/omitted fields,
nested structures, or a JSON-string-inside-JSON quirk — each gets its own
explicit test rather than a shared table.
"""
from __future__ import annotations

import json

import pytest

from client70mai.client import DEFAULT_BASE_URL, MaiClient
from client70mai.exceptions import MaiNotAuthenticatedError

from .helpers import FakeResponse, FakeSession, envelope, last_sent_body


# ------------------------------------------------------------------ #
# get_all_device_for_user
# ------------------------------------------------------------------ #
def test_get_all_device_for_user_defaults(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_all_device_for_user()
    body = last_sent_body(fake_session)
    assert body["lastBindTime"] is None
    assert body["pageCount"] == 50


def test_get_all_device_for_user_pagination_cursor(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_all_device_for_user(last_bind_time=1700000000000, page_count=10)
    body = last_sent_body(fake_session)
    assert body["lastBindTime"] == 1700000000000
    assert body["pageCount"] == 10


# ------------------------------------------------------------------ #
# get_advertisement_by_location
# ------------------------------------------------------------------ #
def test_get_advertisement_by_location_defaults(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_advertisement_by_location()
    body = last_sent_body(fake_session)
    assert body["advertisementType"] == 1003
    assert body["pageCount"] == 30
    assert body["lastOrderTimestamp"] is None
    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/advertisementApiV2/getAdvertisementByLocation"


def test_get_advertisement_by_location_custom_args(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_advertisement_by_location(
        advertisement_type=2000, page_count=5, last_order_timestamp=1700000000000
    )
    body = last_sent_body(fake_session)
    assert body["advertisementType"] == 2000
    assert body["pageCount"] == 5
    assert body["lastOrderTimestamp"] == 1700000000000


# ------------------------------------------------------------------ #
# sync_user_config
# ------------------------------------------------------------------ #
def test_sync_user_config_nests_time_offset(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"betaDeviceModuleList": []})))
    authed_client.sync_user_config(lang="en", timezone_offset=2)
    body = last_sent_body(fake_session)
    assert body["lang"] == "en"
    assert body["timeOffset"] == {"timezoneOffset": 2, "dstOffset": 0}


def test_sync_user_config_custom_dst_offset(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"betaDeviceModuleList": []})))
    authed_client.sync_user_config(lang="it", timezone_offset=1, dst_offset=1)
    body = last_sent_body(fake_session)
    assert body["timeOffset"] == {"timezoneOffset": 1, "dstOffset": 1}


# ------------------------------------------------------------------ #
# get_device_alarm_list
# ------------------------------------------------------------------ #
def test_get_device_alarm_list_omits_optional_filters_when_not_given(
    authed_client: MaiClient, fake_session: FakeSession
) -> None:
    """Matches real traffic: the app's own "recent alarms" screen sends
    only deviceId/pageCount, with no date range or alarm-type filter."""
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_device_alarm_list("dev-1")
    body = last_sent_body(fake_session)
    assert body["deviceId"] == "dev-1"
    assert body["pageCount"] == 20
    assert "beginTime" not in body
    assert "createTime" not in body
    assert "alramTypes" not in body


def test_get_device_alarm_list_includes_filters_when_given(
    authed_client: MaiClient, fake_session: FakeSession
) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))
    authed_client.get_device_alarm_list(
        "dev-1", begin_time_ms=1700000000000, create_time_ms=1700003600000, alarm_types=[101, 105], page_count=5
    )
    body = last_sent_body(fake_session)
    assert body["beginTime"] == 1700000000000
    assert body["createTime"] == 1700003600000
    # sic: verbatim typo in the real API, must round-trip unchanged
    assert body["alramTypes"] == [101, 105]
    assert body["pageCount"] == 5


# ------------------------------------------------------------------ #
# set_device_switch
# ------------------------------------------------------------------ #
def test_set_device_switch_body(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(None)))
    details = [{"eventType": 3, "resourceKeys": ["front_video"]}]

    authed_client.set_device_switch("dev-1", monitor_video_upload=True, details=details)

    body = last_sent_body(fake_session)
    assert body["deviceId"] == "dev-1"
    # sic: verbatim typo in the real API
    assert body["monitorVedioUpload"] is True
    assert body["details"] == details
    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/deviceSwitchApi/setDeviceSwitch"


# ------------------------------------------------------------------ #
# report_offline_device_statistics
# ------------------------------------------------------------------ #
def test_report_offline_device_statistics_nests_content_as_json_string(
    authed_client: MaiClient, fake_session: FakeSession
) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(True)))

    authed_client.report_offline_device_statistics("dev-1", "aa:bb:cc:dd:ee:ff")

    body = last_sent_body(fake_session)
    assert body["deviceId"] == "dev-1"
    assert isinstance(body["content"], str)  # a JSON string, not a nested object
    assert json.loads(body["content"]) == {"bssid": "aa:bb:cc:dd:ee:ff"}


# ------------------------------------------------------------------ #
# get_device_status_history_daily
# ------------------------------------------------------------------ #
def test_get_device_status_history_daily_body(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope([])))

    authed_client.get_device_status_history_daily(
        "dev-1", year=2026, month=9, day=13, key_index="1.4", smart_type=51, timezone_offset=2, dst_offset=1
    )

    body = last_sent_body(fake_session)
    assert body["deviceId"] == "dev-1"
    assert body["keyIndex"] == "1.4"
    assert body["year"] == 2026
    assert body["month"] == 9
    assert body["day"] == 13
    assert body["smartType"] == 51
    assert body["timeOffset"] == {"timezoneOffset": 2, "dstOffset": 1}
    assert (
        fake_session.post_calls[-1].url
        == f"{DEFAULT_BASE_URL}/offlineDeviceApi/V3/getDeviceStatusHistoryDaily"
    )


# ------------------------------------------------------------------ #
# check_new_rom_from_app
# ------------------------------------------------------------------ #
def test_check_new_rom_from_app_defaults(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"newVersion": False})))

    authed_client.check_new_rom_from_app(
        device_id="dev-1",
        device_module=65001,
        device_category=3,
        base_version="1.4.82.ww",
        device_type=65,
        device_channel=65001001,
        base_subversion="a",
    )

    body = last_sent_body(fake_session)
    assert body["deviceId"] == "dev-1"
    assert body["deviceModule"] == 65001
    assert body["deviceCategory"] == 3
    assert body["baseVersion"] == "1.4.82.ww"
    assert body["deviceType"] == 65
    assert body["deviceChannel"] == 65001001
    assert body["baseSubversion"] == "a"
    assert body["lang"] == "en"
    assert body["masterDeviceId"] is None
    assert body["masterDeviceCategory"] is None
    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/versionApi/V3/checkNewRomFromApp"


def test_check_new_rom_from_app_with_master_device(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope({"newVersion": False})))

    authed_client.check_new_rom_from_app(
        device_id="sub-dev",
        device_module=1,
        device_category=1,
        base_version="1.0",
        device_type=1,
        device_channel=1,
        base_subversion="a",
        lang="it",
        master_device_id="master-dev",
        master_device_category=3,
    )

    body = last_sent_body(fake_session)
    assert body["lang"] == "it"
    assert body["masterDeviceId"] == "master-dev"
    assert body["masterDeviceCategory"] == 3


# ------------------------------------------------------------------ #
# get_device_model_home_page_content
# ------------------------------------------------------------------ #
def test_get_device_model_home_page_content_defaults(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(None)))

    authed_client.get_device_model_home_page_content(device_type=65, device_module=65001)

    body = last_sent_body(fake_session)
    assert body["deviceType"] == 65
    assert body["deviceModule"] == 65001
    assert body["deviceChannel"] is None
    assert body["version"] == 1
    assert body["lang"] == "en"
    assert body["applicationCode"] == "70mai"
    assert (
        fake_session.post_calls[-1].url
        == f"{DEFAULT_BASE_URL}/helpCenterApi/deviceModel/getDeviceModelHomePageContent"
    )


# ------------------------------------------------------------------ #
# report_app_active
# ------------------------------------------------------------------ #
def test_report_app_active_maps_fields_to_camel_case(authed_client: MaiClient, fake_session: FakeSession) -> None:
    fake_session.queue_post(FakeResponse(json_data=envelope(None)))

    authed_client.report_app_active(
        system="ios",
        app_version="4.3.0",
        manufacturer="APPLE",
        brand="iphone",
        model="iPad8,6",
        product="iPad8,6",
        version="26.6",
        sdk="26.6",
    )

    body = last_sent_body(fake_session)
    assert body["system"] == "ios"
    assert body["appVersion"] == "4.3.0"
    assert body["manufacturer"] == "APPLE"
    assert body["brand"] == "iphone"
    assert body["model"] == "iPad8,6"
    assert body["product"] == "iPad8,6"
    assert body["version"] == "26.6"
    assert body["sdk"] == "26.6"
    assert fake_session.post_calls[-1].url == f"{DEFAULT_BASE_URL}/baseServiceApi/V2/apr"


def test_report_app_active_requires_authentication(client: MaiClient) -> None:
    """Matches real traffic: the app sends its (possibly stale) session
    token on this call too, via _signed_body()'s default require_token."""
    with pytest.raises(MaiNotAuthenticatedError):
        client.report_app_active(
            system="ios",
            app_version="4.3.0",
            manufacturer="APPLE",
            brand="iphone",
            model="iPad8,6",
            product="iPad8,6",
            version="26.6",
            sdk="26.6",
        )
