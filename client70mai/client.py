from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import requests

from .exceptions import (
    MaiConnectionError,
    MaiHTTPError,
    MaiNotAuthenticatedError,
    MaiResponseFormatError,
    MaiTimeoutError,
)
from .signing import BanyacKeyMd5SignatureProvider, SignatureProvider

DEFAULT_BASE_URL = "https://eu-api.70mai.com"

# Fixed channel id sent with every request, including unauthenticated ones
# (userLoginPwd, getTs).
CHANNEL_ID = 3001013

# Must stay percent-encoded: "70迈" is not valid Latin-1 and breaks header
# encoding if written out as the literal Han characters.
DEFAULT_USER_AGENT = "70%E8%BF%88/46 CFNetwork/3860.700.1 Darwin/25.6.0"

DEFAULT_HEADERS: Dict[str, str] = {
    "Content-Type": "application/json;application/x-www-form-urlencoded",
    "Charset": "UTF-8",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "User-Agent": DEFAULT_USER_AGENT,
}


class MaiClient:
    """
    Client for the 70mai dashcam cloud API (eu-api.70mai.com).

    Authentication: no Authorization header or cookie is used. Every
    authenticated call carries these fields in its JSON body:
      - "uuid": per-install device UUID, sent even on unauthenticated calls.
      - "channel": fixed channel id (CHANNEL_ID).
      - "ts": client epoch-millisecond timestamp, unique per request.
      - "token": session token from login(), reused until logout().
      - "sig": md5(token + uuid + channel + ts + <secret>); the exact
        formula lives in signing.py.

    Response envelope, returned as-is by every method (Dict[str, Any]):
        {"error": bool, "errorCode": int, "errorMessage": str,
         "resultBodyObject": T}
    T differs per endpoint; methods whose docstring documents a
    "Response:" shape have that shape verified against real traffic,
    others are best-effort from the request shape alone and should be
    validated before relying on a specific field.

    Live view (P2P over the ThroughTek/TUTK SDK, not RTSP/HLS/RTMP) is not
    implemented here.
    """

    def __init__(
        self,
        uuid: str,
        signature_provider: Optional[SignatureProvider] = None,
        base_url: str = DEFAULT_BASE_URL,
        device_token: Optional[str] = None,
        timeout: float = 15.0,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.uuid = uuid
        self.base_url = base_url.rstrip("/")
        self.device_token = device_token
        self.timeout = timeout
        self.signature_provider: SignatureProvider = (
            signature_provider or BanyacKeyMd5SignatureProvider()
        )
        self.session = session or requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.token: Optional[str] = None

    # ------------------------------------------------------------------ #
    # low-level transport
    # ------------------------------------------------------------------ #
    def _post(self, path: str, body: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        url = f"{self.base_url}{path}"
        try:
            resp = self.session.post(
                url,
                data=json.dumps(body) if body is not None else None,
                timeout=self.timeout,
            )
        except requests.Timeout as exc:
            raise MaiTimeoutError(f"Timed out calling {url}") from exc
        except requests.ConnectionError as exc:
            raise MaiConnectionError(f"Connection error calling {url}") from exc

        if not resp.ok:
            raise MaiHTTPError(resp.status_code, url, resp.text)

        try:
            return resp.json()
        except (ValueError, json.JSONDecodeError) as exc:
            raise MaiResponseFormatError(
                f"Non-JSON response from {url}: {resp.text[:500]!r}"
            ) from exc

    @staticmethod
    def _now_ms() -> int:
        return int(time.time() * 1000)

    def _signed_body(
        self, extra: Optional[Dict[str, Any]] = None, require_token: bool = True
    ) -> Dict[str, Any]:
        if require_token and not self.token:
            raise MaiNotAuthenticatedError("Call login() before using this method.")

        body: Dict[str, Any] = {
            "uuid": self.uuid,
            "channel": CHANNEL_ID,
            "ts": self._now_ms(),
        }
        if require_token:
            body["token"] = self.token
        if extra:
            body.update(extra)

        body["sig"] = self.signature_provider.sign(body)
        return body

    # ------------------------------------------------------------------ #
    # baseServiceApi
    # ------------------------------------------------------------------ #
    def get_ts(self) -> Dict[str, Any]:
        """POST /baseServiceApi/V2/getTs: a time-sync call, sent with an
        empty body and no auth fields. Response: resultBodyObject =
        current server epoch-ms timestamp (int)."""
        return self._post("/baseServiceApi/V2/getTs", None)

    # ------------------------------------------------------------------ #
    # accountApi: auth & profile
    # ------------------------------------------------------------------ #
    def login(self, email: str, plain_password: str, device_type: int = 3) -> Dict[str, Any]:
        """POST /accountApi/V3/userLoginPwd.

        Stores the session token from resultBodyObject.token for use by
        every other method. Uses a distinct passWord/sig construction from
        every other endpoint; see SignatureProvider.sign_login() in
        signing.py.
        """
        ts = self._now_ms()
        password_hash = self.signature_provider.hash_password(plain_password)
        sig = self.signature_provider.sign_login(device_type, email, password_hash, ts, CHANNEL_ID)

        body: Dict[str, Any] = {
            "email": email,
            "ts": ts,
            "passWord": password_hash,
            "channel": CHANNEL_ID,
            "uuid": self.uuid,
            "deviceType": device_type,
            "sig": sig,
        }
        if self.device_token:
            body["deviceToken"] = self.device_token

        data = self._post("/accountApi/V3/userLoginPwd", body)

        result_body = data.get("resultBodyObject")
        token = result_body.get("token") if isinstance(result_body, dict) else None
        if not token:
            raise MaiResponseFormatError(
                "Login response did not contain resultBodyObject.token "
                f"(error={data.get('error')!r}, errorCode={data.get('errorCode')!r}, "
                f"errorMessage={data.get('errorMessage')!r})."
            )
        self.token = token
        return data

    def logout(self) -> Dict[str, Any]:
        """POST /accountApi/V3/userLogOut."""
        result = self._post("/accountApi/V3/userLogOut", self._signed_body())
        self.token = None
        return result

    def get_all_user_info(self) -> Dict[str, Any]:
        """POST /accountApi/getAllUserInfo."""
        return self._post("/accountApi/getAllUserInfo", self._signed_body())

    def get_user_country_code(self) -> Dict[str, Any]:
        """POST /accountApi/V4/getUserCountryCode. Response:
        resultBodyObject = {"countryCode": str, "responseType": int}."""
        return self._post("/accountApi/V4/getUserCountryCode", self._signed_body())

    def get_account_notify_overview(self) -> Dict[str, Any]:
        """POST /accountApi/V4/getAccountNotifyOverview. Response:
        resultBodyObject = {"result": [{"type": int, "unreadCount":
        int|None, "lastAccountNotify": {"id", "userId", "deviceType",
        "deviceModule", "channel", "deviceId", "deviceNickName", "type",
        "body": <JSON-encoded str>, "status", "level", "createTimeStamp",
        "updateTimeStamp"}}]}."""
        return self._post("/accountApi/V4/getAccountNotifyOverview", self._signed_body())

    def sync_user_config(
        self, lang: str, timezone_offset: int, dst_offset: int = 0
    ) -> Dict[str, Any]:
        """POST /accountApi/V4/synUserConfig. `timezone_offset`/
        `dst_offset` are integer hour offsets. Response: resultBodyObject
        = {"betaDeviceModuleList": [...]}.
        """
        extra = {
            "lang": lang,
            "timeOffset": {"timezoneOffset": timezone_offset, "dstOffset": dst_offset},
        }
        return self._post("/accountApi/V4/synUserConfig", self._signed_body(extra))

    def update_device_token(self, device_token: str) -> Dict[str, Any]:
        """POST /accountApi/V2/updateDeviceToken: registers a push/FCM
        token. Response: resultBodyObject = bool."""
        self.device_token = device_token
        return self._post(
            "/accountApi/V2/updateDeviceToken",
            self._signed_body({"deviceToken": device_token}),
        )

    def get_all_device_for_user(
        self, last_bind_time: Optional[int] = None, page_count: int = 50
    ) -> Dict[str, Any]:
        """POST /accountApi/V3/getAllDeviceForUser.

        `last_bind_time` is an epoch-ms pagination cursor on `bindTime`
        (pass `None` for the first page); `page_count` caps the page size.

        Response: resultBodyObject = a list of device dicts directly (not
        wrapped further), one per bound device: {"userId", "type",
        "module", "channel", "deviceId", "nickName", "wifiMac", "btMac",
        "btAesKey", "ssid", "wifiPublicKey", "connectKey", "bindTime"}.
        `deviceId` is always present (a MAC string for offline/no-SIM
        devices, an opaque id for cloud-connected ones); `nickName` can be
        null, in which case fall back to another field (e.g. `ssid`) for
        display rather than `deviceId`.
        """
        extra: Dict[str, Any] = {"lastBindTime": last_bind_time, "pageCount": page_count}
        return self._post("/accountApi/V3/getAllDeviceForUser", self._signed_body(extra))

    # ------------------------------------------------------------------ #
    # advertisementApiV2
    # ------------------------------------------------------------------ #
    def get_home_logos(self) -> Dict[str, Any]:
        """POST /advertisementApiV2/getHomeLogos. Superseded by
        get_advertisement_by_location() in newer app builds; kept for
        compatibility."""
        return self._post("/advertisementApiV2/getHomeLogos", self._signed_body())

    def get_advertisement_by_location(
        self, advertisement_type: int = 1003, page_count: int = 30,
        last_order_timestamp: Optional[int] = None,
    ) -> Dict[str, Any]:
        """POST /advertisementApiV2/getAdvertisementByLocation: promo
        banners for the app home screen. `last_order_timestamp` is a
        pagination cursor on `orderTimestamp` (pass `None` for the first
        page).

        Response: resultBodyObject = list of {"id", "title", "detail",
        "logo": <URL>, "beginTimestamp", "endTimestamp", "orderTimestamp",
        "colorStyle"}.
        """
        extra = {
            "advertisementType": advertisement_type,
            "pageCount": page_count,
            "lastOrderTimestamp": last_order_timestamp,
        }
        return self._post(
            "/advertisementApiV2/getAdvertisementByLocation", self._signed_body(extra)
        )

    # ------------------------------------------------------------------ #
    # dashcamApi: cloud-connected ("online") device
    # ------------------------------------------------------------------ #
    def get_dashcam_detail(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getDashcamDetail. Response: resultBodyObject =
        {"deviceStatus", "simPluginActiveStatus", "geofenceActiveStatus",
        "device": {"id", "userId", "type", "deviceId", "connectKey",
        "nickName", "ssid", "channel", "module", "bindAblity",
        "bindAblityName", "accountCarId", "bindType", "isBetaDevice",
        "btMac", "wifiMac", "btAesKey", "wifiPublicKey", "bindTime",
        "reportTime", "createTimeStamp", "updateTimeStamp"}, "simPlugin":
        {...same shape as get_sim_plugin_detail()...}, "subdeviceList":
        list|None}."""
        return self._post(
            "/dashcamApi/getDashcamDetail", self._signed_body({"deviceId": device_id})
        )

    def get_position(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getPosition (last known GPS position).
        Response: resultBodyObject = {"status": int, "position":
        {"coordinatesLng": str, "coordinatesLat": str, "lastUpdateTime":
        int, "parkPicUrl": str|None, "parkPicLastUpdateTime": int|None,
        "parkingPhotoSwitch": int}}."""
        return self._post("/dashcamApi/getPosition", self._signed_body({"deviceId": device_id}))

    def get_sim_plugin_detail(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getSimPluginDetail (cellular/SIM add-on
        status). Response: resultBodyObject = {"pluginDeviceId",
        "pluginDeviceType", "pluginDeviceModule", "pluginDeviceChannel",
        "isBetaDevice", "imei", "pluginSoftwareVersion",
        "pluginSubSoftwareVersion", "createTimeStamp", "updateTimeStamp",
        "offlinedeviceserviceDevice"}."""
        return self._post(
            "/dashcamApi/getSimPluginDetail", self._signed_body({"deviceId": device_id})
        )

    def get_supported_features(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getSupportedFeatures. Response:
        resultBodyObject = {"supportedFeatures": {...}} (keys are
        device/feature-flag dependent)."""
        return self._post(
            "/dashcamApi/getSupportedFeatures", self._signed_body({"deviceId": device_id})
        )

    def get_dashcam_status(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getDashcamStatus (response shape not yet
        confirmed)."""
        return self._post(
            "/dashcamApi/getDashcamStatus", self._signed_body({"deviceId": device_id})
        )

    def is_active_value_added_service(self, value_added_service: int) -> Dict[str, Any]:
        """POST /dashcamApi/isActiveValueAddedService: checks a
        value-added-service (e.g. cloud storage plan) subscription
        status. Response: resultBodyObject = {"result": Any|None,
        "isActive": bool, "planType": str, "interval": Any|None}."""
        return self._post(
            "/dashcamApi/isActiveValueAddedService",
            self._signed_body({"valueAddedService": value_added_service}),
        )

    def get_device_alarm_list(
        self,
        device_id: str,
        begin_time_ms: int,
        create_time_ms: int,
        alarm_types: List[int],
        page_count: int = 20,
    ) -> Dict[str, Any]:
        """POST /dashcamApi/V2/getDeviceAlarmList returns alarm/event
        history for a device in [begin_time_ms, create_time_ms]. Response:
        resultBodyObject = list (item schema not yet confirmed)."""
        extra = {
            "deviceId": device_id,
            "beginTime": begin_time_ms,
            "createTime": create_time_ms,
            "alramTypes": alarm_types,  # sic: verbatim typo in the real API
            "pageCount": page_count,
        }
        return self._post("/dashcamApi/V2/getDeviceAlarmList", self._signed_body(extra))

    def get_device_alarm(self, device_id: str, alarm_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/V2/getDeviceAlarm returns a single alarm/event detail
        (response shape not yet confirmed)."""
        return self._post(
            "/dashcamApi/V2/getDeviceAlarm",
            self._signed_body({"deviceId": device_id, "alarmId": alarm_id}),
        )

    # ------------------------------------------------------------------ #
    # deviceSwitchApi: per-device feature toggles
    # ------------------------------------------------------------------ #
    def get_device_switch(self, device_id: str) -> Dict[str, Any]:
        """POST /deviceSwitchApi/getDeviceSwitch returns per-device feature
        toggle state (response shape not yet confirmed)."""
        return self._post(
            "/deviceSwitchApi/getDeviceSwitch", self._signed_body({"deviceId": device_id})
        )

    def set_device_switch(
        self, device_id: str, monitor_video_upload: bool, details: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """POST /deviceSwitchApi/setDeviceSwitch.

        `details` is passed through verbatim: a list of {"eventType":
        int, "resourceKeys": List[str]} (response shape not yet
        confirmed).
        """
        extra = {
            "deviceId": device_id,
            "monitorVedioUpload": monitor_video_upload,  # sic: verbatim typo in the real API
            "details": details,
        }
        return self._post("/deviceSwitchApi/setDeviceSwitch", self._signed_body(extra))

    # ------------------------------------------------------------------ #
    # offlineDeviceApi: locally-paired / no-SIM devices (deviceId is a MAC)
    # ------------------------------------------------------------------ #
    def get_offline_device_detail(self, device_id_mac: str) -> Dict[str, Any]:
        """POST /offlineDeviceApi/V2/getDeviceDetail."""
        return self._post(
            "/offlineDeviceApi/V2/getDeviceDetail",
            self._signed_body({"deviceId": device_id_mac}),
        )

    def report_offline_device_statistics(self, device_id: str, bssid: str) -> Dict[str, Any]:
        """POST /offlineDeviceApi/V2/reportOfflineDeviceStatistics.

        `content` is a JSON *string* nested inside the JSON body, not a
        nested object; it's built here via json.dumps(). Response:
        resultBodyObject = bool.
        """
        extra = {"deviceId": device_id, "content": json.dumps({"bssid": bssid})}
        return self._post(
            "/offlineDeviceApi/V2/reportOfflineDeviceStatistics", self._signed_body(extra)
        )

    def get_device_status_history_daily(
        self,
        device_id: str,
        year: int,
        month: int,
        day: int,
        key_index: str,
        smart_type: int,
        timezone_offset: int,
        dst_offset: int = 0,
    ) -> Dict[str, Any]:
        """POST /offlineDeviceApi/V3/getDeviceStatusHistoryDaily returns
        per-day telemetry history. `key_index` selects the telemetry
        channel; known values are "1.2", "1.3" and "1.4" ("1.4" looks
        like car-battery voltage in millivolts, though that isn't
        officially documented). `smart_type` is a fixed value of 51.

        Response: resultBodyObject = list of {"keyIndex": str, "timeGap":
        int, "max": int, "maxTs": int, "min": int, "minTs": int, "latest":
        int, "latestTs": int}, one entry per time bucket in the requested
        day (can be empty).
        """
        extra = {
            "deviceId": device_id,
            "keyIndex": key_index,
            "year": year,
            "month": month,
            "day": day,
            "smartType": smart_type,
            "timeOffset": {"timezoneOffset": timezone_offset, "dstOffset": dst_offset},
        }
        return self._post(
            "/offlineDeviceApi/V3/getDeviceStatusHistoryDaily", self._signed_body(extra)
        )

    def sim_plugin_support_out_power(self, device_id: str) -> Dict[str, Any]:
        """POST /offlineDeviceApi/V3/simPluginSupportOutPower. Response:
        resultBodyObject = bool."""
        return self._post(
            "/offlineDeviceApi/V3/simPluginSupportOutPower",
            self._signed_body({"deviceId": device_id}),
        )

    # ------------------------------------------------------------------ #
    # versionApi: firmware
    # ------------------------------------------------------------------ #
    def check_new_rom_from_app(
        self,
        device_id: str,
        device_module: int,
        device_category: int,
        base_version: str,
        device_type: int,
        device_channel: int,
        base_subversion: str,
        lang: str = "en",
        master_device_id: Optional[str] = None,
        master_device_category: Optional[int] = None,
    ) -> Dict[str, Any]:
        """POST /versionApi/V3/checkNewRomFromApp checks for a firmware
        update. The device_*/base_* fields identify the target
        hardware/firmware; pass the values matching the actual device.
        `master_device_id`/`master_device_category` identify a sub-device's
        master/hub device (pass `None` otherwise).

        Response: resultBodyObject = {"newVersion": bool, "version": str,
        "versionOrder": Any|None, "subVersion": str, "fileUrl": <URL>,
        "fileMd5": str, "fileSize": int, "desc": str, "targetDesc":
        Any|None, "packageId": int, "romVersionId": int, "releaseTime":
        int, "forced": bool}.
        """
        extra = {
            "deviceId": device_id,
            "deviceModule": device_module,
            "deviceCategory": device_category,
            "baseVersion": base_version,
            "deviceType": device_type,
            "deviceChannel": device_channel,
            "baseSubversion": base_subversion,
            "masterDeviceId": master_device_id,
            "masterDeviceCategory": master_device_category,
            "lang": lang,
        }
        return self._post("/versionApi/V3/checkNewRomFromApp", self._signed_body(extra))

    def get_websocket_address_for_app(self, device_id: str) -> Dict[str, Any]:
        """POST /accountApi/V3/getWebsocketAddressForApp is expected to
        return a live device-status push endpoint (response shape not yet
        confirmed)."""
        return self._post(
            "/accountApi/V3/getWebsocketAddressForApp", self._signed_body({"deviceId": device_id})
        )

    # ------------------------------------------------------------------ #
    # helpCenterApi
    # ------------------------------------------------------------------ #
    def get_device_model_home_page_content(
        self,
        device_type: int,
        device_module: int,
        version: int = 1,
        lang: str = "en",
        device_channel: Optional[int] = None,
        application_code: str = "70mai",
    ) -> Dict[str, Any]:
        """POST /helpCenterApi/deviceModel/getDeviceModelHomePageContent
        returns help-center/manual content for a device model (response
        shape not yet confirmed)."""
        extra = {
            "deviceType": device_type,
            "deviceModule": device_module,
            "deviceChannel": device_channel,
            "version": version,
            "lang": lang,
            "applicationCode": application_code,
        }
        return self._post(
            "/helpCenterApi/deviceModel/getDeviceModelHomePageContent", self._signed_body(extra)
        )

    # ------------------------------------------------------------------ #
    # UserspaceApi: file/media metadata
    # ------------------------------------------------------------------ #
    def get_file_details(self, file_ids: List[str]) -> Dict[str, Any]:
        """POST /UserspaceApi/getFileDetails. Response is expected to
        carry Tencent-COS pre-signed download URLs for
        eu4gmedia.70mai.com; those signatures are generated server-side
        and should never be built client-side."""
        return self._post("/UserspaceApi/getFileDetails", self._signed_body({"fileIds": file_ids}))

    def download_media(self, presigned_url: str, dest_path: str, chunk_size: int = 1 << 16) -> None:
        """Stream-download a media file from a pre-signed URL returned by
        get_file_details()/get_dashcam_detail(). Adds no auth of its own;
        the URL's query string already carries a valid COS signature."""
        try:
            with self.session.get(presigned_url, stream=True, timeout=self.timeout) as resp:
                if not resp.ok:
                    raise MaiHTTPError(resp.status_code, presigned_url, resp.text)
                with open(dest_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=chunk_size):
                        if chunk:
                            f.write(chunk)
        except requests.Timeout as exc:
            raise MaiTimeoutError(f"Timed out downloading {presigned_url}") from exc
        except requests.ConnectionError as exc:
            raise MaiConnectionError(f"Connection error downloading {presigned_url}") from exc
