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

    Live view is control-plane only here: get_tutk_token() fetches the
    session credential and living() sends the ~10s keepalive/quota
    heartbeat while the app has the stream open (see their docstrings for
    the confirmed request/response shapes and the exact call rhythm
    observed in real traffic). Neither call carries video. The actual
    video is P2P over ThroughTek's proprietary IOTC/Kalay SDK (native
    libIOTCAPIs.so/libTUTKGlobalAPIs.so, bundled in the app's
    arm64-v8a split APK) using the tutkUID/tutkToken from
    get_tutk_token() — not RTSP/HLS/RTMP, not going through this client's
    HTTP session, and (per the decompiled app) typically not visible to
    an HTTPS proxy like Proxyman/Charles/mitmproxy at all, since it's a
    native P2P/UDP transport most phones route outside the system HTTP
    proxy. Reimplementing that protocol in Python is out of scope here;
    intercepting the actual frames on a real device means either a raw
    packet capture (tcpdump/Wireshark on a rooted phone or a VPN
    gateway) to confirm the transport, or runtime instrumentation
    (Frida) hooking the native IOTC/AV functions (e.g. avClientStart2 /
    avRecvFrameData2) to dump decoded frames before/after the SDK's own
    encryption.
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
        current server epoch-ms timestamp (int).

        Example resultBodyObject: 1735900000000
        """
        return self._post("/baseServiceApi/V2/getTs", None)

    def get_device_conf_file_url(self) -> Dict[str, Any]:
        """POST /baseServiceApi/V2/getDeviceConfFileUrl: no extra fields
        beyond the signed envelope. CONFIRMED response: resultBodyObject
        is typed MaiCommonResult<String> in the decompiled app (a config
        file URL), observed as null in a real capture with nothing to
        resolve."""
        return self._post("/baseServiceApi/V2/getDeviceConfFileUrl", self._signed_body())

    def report_app_active(
        self,
        system: str,
        app_version: str,
        manufacturer: str,
        brand: str,
        model: str,
        product: str,
        version: str,
        sdk: str,
    ) -> Dict[str, Any]:
        """POST /baseServiceApi/V2/apr: a fire-and-forget app-open/liveness
        ping sent with device/OS metadata instead of a deviceId, fired
        once at app startup regardless of login state (the decompiled
        Android app calls it via a bare subscribe(), ignoring the
        result). Field names/casing match the real iOS capture exactly
        (`system`/`sdk`/`version` are the OS name/SDK level/OS release,
        `product`/`model`/`brand`/`manufacturer` the hardware, `app_version`
        the app's own version). Response: resultBodyObject is typed
        MaiCommonResult<Long> in the decompiled app; the only captured
        call failed with errorCode 500001 ("token无效") because it ran
        with a stale token, so the success shape is unconfirmed.
        """
        extra = {
            "system": system,
            "appVersion": app_version,
            "manufacturer": manufacturer,
            "brand": brand,
            "model": model,
            "product": product,
            "version": version,
            "sdk": sdk,
        }
        return self._post("/baseServiceApi/V2/apr", self._signed_body(extra))

    # ------------------------------------------------------------------ #
    # accountApi: auth & profile
    # ------------------------------------------------------------------ #
    def login(self, email: str, plain_password: str, device_type: int = 3) -> Dict[str, Any]:
        """POST /accountApi/V3/userLoginPwd.

        Stores the session token from resultBodyObject.token for use by
        every other method. Uses a distinct passWord/sig construction from
        every other endpoint; see SignatureProvider.sign_login() in
        signing.py.

        Example resultBodyObject (anonymized):
        {
          "token": "11111111-2222-3333-4444-555555555555",
          "waitForDelete": 0,
          "deleteDate": null,
          "channel": 3001005,
          "userID": 1000001,
          "userName": "M-DRV_0000000000001",
          "mobileNeeded": false,
          "confFileUrl": null,
          "guideStatus": 1,
          "applicationCode": null
        }
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
        """POST /accountApi/getAllUserInfo.

        CONFIRMED response, example resultBodyObject (anonymized):
        {
          "accountUser": {
            "id": 1000001,
            "userName": "M-DRV_0000000000001",
            "passWord": "5f4dcc3b5aa765d61d8327deb882cf99",
            "userToken": "11111111-2222-3333-4444-555555555555",
            "userToken2": null,
            "email": "user@example.com",
            "mobile": null,
            "lang": "en_IT",
            "mobileVerified": 0,
            "nickName": null,
            "status": 1,
            "status2": 1,
            "isBetaUser": null,
            "guideStatus": 1,
            "registIP": "203.0.113.10",
            "cityID": null,
            "coordinatesLat": null,
            "coordinatesLng": null,
            "appType": null,
            "xiaomiUserId": null,
            "channelUserId": null,
            "channelType": null,
            "deviceType": 3,
            "applicationCode": "70mai",
            "channel": 3001005,
            "lastLoginChannel": 3001013,
            "agreementVersion": 2,
            "createTimeStamp": 1700000000000,
            "updateTimeStamp": 1700000600000,
            "waitForDelete": 0,
            "deleteDate": null,
            "timeOffset": "{\\"dstOffset\\":4,\\"timezoneOffset\\":4}",
            "registerIp": null,
            "timezoneId": null,
            "countryCode": "IT",
            "transferStatus": 2
          },
          "accountUserInfo": {
            "id": 1000002,
            "userID": 1000001,
            "realName": null,
            "nickName": null,
            "gender": null,
            "birthday": null,
            "address": null,
            "faceImageUrl": null,
            "faceImageCdnFileName": null,
            "faceImageCdnConfigCode": null,
            "drivingExperience": null,
            "createTimeStamp": 1700000000000,
            "updateTimeStamp": 1700000000000
          },
          "carCount": null,
          "deviceCount": null
        }
        """
        return self._post("/accountApi/getAllUserInfo", self._signed_body())

    def get_user_country_code(self) -> Dict[str, Any]:
        """POST /accountApi/V4/getUserCountryCode. Response:
        resultBodyObject = {"countryCode": str, "responseType": int}.

        Example resultBodyObject: {"countryCode": "IT", "responseType": 2}
        """
        return self._post("/accountApi/V4/getUserCountryCode", self._signed_body())

    def get_account_notify_overview(self) -> Dict[str, Any]:
        """POST /accountApi/V4/getAccountNotifyOverview. Response:
        resultBodyObject = {"result": [{"type": int, "unreadCount":
        int|None, "lastAccountNotify": {"id", "userId", "deviceType",
        "deviceModule", "channel", "deviceId", "deviceNickName", "type",
        "body": <JSON-encoded str>, "status", "level", "createTimeStamp",
        "updateTimeStamp"}}]}.

        Example resultBodyObject (anonymized):
        {
          "result": [
            {
              "type": 6,
              "unreadCount": null,
              "lastAccountNotify": {
                "id": 100000001,
                "userId": 1000001,
                "deviceType": 65,
                "deviceModule": 65001,
                "channel": 65001001,
                "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
                "deviceNickName": null,
                "type": 6,
                "body": "{\\"deviceId\\":\\"deadbeefdeadbeefdeadbeefdeadbeef\\",\\"timestamp\\":1700000000000,\\"triggerType\\":2901,\\"vedioId\\":\\"1\\"}",
                "status": 2,
                "level": 0,
                "createTimeStamp": 1700000000000,
                "updateTimeStamp": 1700000600000
              }
            }
          ]
        }
        """
        return self._post("/accountApi/V4/getAccountNotifyOverview", self._signed_body())

    def sync_user_config(
        self, lang: str, timezone_offset: int, dst_offset: int = 0
    ) -> Dict[str, Any]:
        """POST /accountApi/V4/synUserConfig. `timezone_offset`/
        `dst_offset` are integer hour offsets. Response: resultBodyObject
        = {"betaDeviceModuleList": [...]}.

        Example resultBodyObject: {"betaDeviceModuleList": []}
        """
        extra = {
            "lang": lang,
            "timeOffset": {"timezoneOffset": timezone_offset, "dstOffset": dst_offset},
        }
        return self._post("/accountApi/V4/synUserConfig", self._signed_body(extra))

    def update_device_token(self, device_token: str) -> Dict[str, Any]:
        """POST /accountApi/V2/updateDeviceToken: registers a push/FCM
        token. Response: resultBodyObject = bool.

        Example resultBodyObject: true
        """
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

        Example resultBodyObject (anonymized; one cloud-connected device
        with an active SIM plugin, one offline/no-SIM device):
        [
          {
            "userId": 1000001,
            "type": 65,
            "module": 65001,
            "channel": 65001001,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "nickName": "Front Dashcam",
            "wifiMac": "aa:bb:cc:dd:ee:02",
            "btMac": "aa:bb:cc:dd:ee:01",
            "btAesKey": "00112233445566778899aabbccddeeff",
            "ssid": "70mai_A810_0000",
            "wifiPublicKey": "<base64-encoded RSA public key>",
            "connectKey": null,
            "bindTime": 1700000000000
          },
          {
            "userId": 1000001,
            "type": 8,
            "module": 8001,
            "channel": 8001005,
            "deviceId": "aa:bb:cc:dd:ee:03",
            "nickName": "Garage Cam",
            "wifiMac": null,
            "btMac": null,
            "btAesKey": null,
            "ssid": "70mai_d01_0000",
            "wifiPublicKey": null,
            "connectKey": "00000000000000000000000000000000",
            "bindTime": 1600000000000
          }
        ]
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

        Example resultBodyObject (anonymized/genericized banner copy):
        [
          {
            "id": 142,
            "title": "Summer Promo",
            "detail": "Summer promo banner, Italy",
            "logo": "https://de-resource.70mai.com/advertisementLogo/2026-01-01/promo-banner.jpg",
            "beginTimestamp": 1700000000000,
            "endTimestamp": 1800000000000,
            "orderTimestamp": 1700000000000,
            "colorStyle": null
          }
        ]
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
        list|None}.

        Example resultBodyObject (anonymized):
        {
          "deviceStatus": 1,
          "simPluginActiveStatus": 1,
          "geofenceActiveStatus": 0,
          "device": {
            "id": 500001,
            "userId": 1000001,
            "type": 65,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "connectKey": null,
            "nickName": "Front Dashcam",
            "ssid": "70mai_A810_0000",
            "channel": 65001001,
            "module": 65001,
            "bindAblity": 0,
            "bindAblityName": null,
            "accountCarId": null,
            "bindType": null,
            "isBetaDevice": null,
            "btMac": "aa:bb:cc:dd:ee:01",
            "wifiMac": "aa:bb:cc:dd:ee:02",
            "btAesKey": "00112233445566778899aabbccddeeff",
            "wifiPublicKey": "<base64-encoded RSA public key>",
            "bindTime": 1700000000000,
            "reportTime": null,
            "createTimeStamp": 1700000000000,
            "updateTimeStamp": 1700000600000
          },
          "simPlugin": {
            "pluginDeviceId": "cafebabecafebabecafebabecafebabe",
            "pluginDeviceType": 48,
            "pluginDeviceModule": 48002,
            "pluginDeviceChannel": 48002001,
            "isBetaDevice": null,
            "imei": "000000000000000",
            "pluginSoftwareVersion": null,
            "pluginSubSoftwareVersion": null,
            "createTimeStamp": null,
            "updateTimeStamp": null,
            "offlinedeviceserviceDevice": null
          },
          "subdeviceList": null
        }
        """
        return self._post(
            "/dashcamApi/getDashcamDetail", self._signed_body({"deviceId": device_id})
        )

    def get_position(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getPosition (last known GPS position).
        Response: resultBodyObject = {"status": int, "position":
        {"coordinatesLng": str, "coordinatesLat": str, "lastUpdateTime":
        int, "parkPicUrl": str|None, "parkPicLastUpdateTime": int|None,
        "parkingPhotoSwitch": int}}.

        Example resultBodyObject (coordinates anonymized):
        {
          "status": 3,
          "position": {
            "coordinatesLng": "9.000000",
            "coordinatesLat": "45.000000",
            "lastUpdateTime": 1700000000000,
            "parkPicUrl": null,
            "parkPicLastUpdateTime": null,
            "parkingPhotoSwitch": 0
          }
        }
        """
        return self._post("/dashcamApi/getPosition", self._signed_body({"deviceId": device_id}))

    def get_sim_plugin_detail(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getSimPluginDetail (cellular/SIM add-on
        status). Response: resultBodyObject = {"pluginDeviceId",
        "pluginDeviceType", "pluginDeviceModule", "pluginDeviceChannel",
        "isBetaDevice", "imei", "pluginSoftwareVersion",
        "pluginSubSoftwareVersion", "createTimeStamp", "updateTimeStamp",
        "offlinedeviceserviceDevice"}.

        Example resultBodyObject (anonymized):
        {
          "pluginDeviceId": "cafebabecafebabecafebabecafebabe",
          "pluginDeviceType": 48,
          "pluginDeviceModule": 48002,
          "pluginDeviceChannel": 48002001,
          "isBetaDevice": null,
          "imei": "000000000000000",
          "pluginSoftwareVersion": "1.4.82.ww",
          "pluginSubSoftwareVersion": "a",
          "createTimeStamp": null,
          "updateTimeStamp": null,
          "offlinedeviceserviceDevice": null
        }
        """
        return self._post(
            "/dashcamApi/getSimPluginDetail", self._signed_body({"deviceId": device_id})
        )

    def get_supported_features(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getSupportedFeatures. Response:
        resultBodyObject = {"supportedFeatures": {...}} (keys are
        device/feature-flag dependent).

        Example resultBodyObject (this device had none enabled):
        {"supportedFeatures": {}}
        """
        return self._post(
            "/dashcamApi/getSupportedFeatures", self._signed_body({"deviceId": device_id})
        )

    def get_dashcam_status(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getDashcamStatus. CONFIRMED response:
        resultBodyObject = {"status": int, "allowPullAlive": int,
        "deviceNetworkLevel": int}.

        Example resultBodyObject:
        {"status": 3, "allowPullAlive": 1, "deviceNetworkLevel": 0}
        """
        return self._post(
            "/dashcamApi/getDashcamStatus", self._signed_body({"deviceId": device_id})
        )

    def get_tutk_token(self, device_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/getTutkToken: fetches a short-lived credential
        for the device's ThroughTek/TUTK P2P live-view session. This
        method only fetches that credential; it does not open the P2P
        video stream itself (see the module-level note on live view).
        Pair it with living() while the stream is open: the decompiled
        app calls this once to start a session, then living() on a
        ~10s heartbeat, calling this again only once the session's
        `remainingTs` budget runs out. CONFIRMED response:
        resultBodyObject = {"tutkToken": str, "tutkUID": str, "region":
        str, "remainingTs": int}. `remainingTs` (ms) is a per-account
        live-view time budget that counts down across the session (NOT
        a fixed token TTL): two real calls ~90s apart returned
        1794533 and then 1756442 (see living() for how it's spent).

        Example resultBodyObject (tutkToken/tutkUID are opaque secrets,
        redacted rather than faked):
        {
          "tutkToken": "<opaque base64 TUTK session token>",
          "tutkUID": "<opaque TUTK device UID>",
          "region": "eu",
          "remainingTs": 1794533
        }
        """
        return self._post("/dashcamApi/getTutkToken", self._signed_body({"deviceId": device_id}))

    def living(self, device_id: str, elapsed_ms: int) -> Dict[str, Any]:
        """POST /dashcamApi/living: the live-view heartbeat. While a P2P
        session opened via get_tutk_token() is on screen, the decompiled
        app calls this roughly every 10 seconds with `elapsed_ms` = the
        real time elapsed since the previous heartbeat, capped at 10000
        (min(now - lastCheck, 10000)); on pausing/closing the view it
        sends one final uncapped call with the leftover elapsed time
        (real captures show trailing values like 8089 and 3524 for that
        last call). The server responds with the live-view time budget
        remaining across the whole session; the app treats
        `remainingTs <= 0` as "budget exhausted" and tears down the P2P
        connection. This call carries no video data itself — see the
        module-level docstring for why the actual stream needs separate
        tooling. CONFIRMED response: resultBodyObject = {"remainingTs":
        int}.

        Example resultBodyObject (four consecutive real heartbeats
        during one session; remainingTs counts down from the value
        get_tutk_token() returned):
        {"remainingTs": 1784532}
        {"remainingTs": 1774532}
        {"remainingTs": 1764531}
        {"remainingTs": 1756442}
        """
        extra = {"deviceId": device_id, "time": elapsed_ms}
        return self._post("/dashcamApi/living", self._signed_body(extra))

    def is_active_value_added_service(self, value_added_service: int) -> Dict[str, Any]:
        """POST /dashcamApi/isActiveValueAddedService: checks a
        value-added-service (e.g. cloud storage plan) subscription
        status. Response: resultBodyObject = {"result": Any|None,
        "isActive": bool, "planType": str, "interval": Any|None}.

        Example resultBodyObject (this account had no active plan):
        {"result": null, "isActive": false, "planType": "pt_vip_0",
        "interval": null}
        """
        return self._post(
            "/dashcamApi/isActiveValueAddedService",
            self._signed_body({"valueAddedService": value_added_service}),
        )

    def get_device_alarm_list(
        self,
        device_id: str,
        begin_time_ms: Optional[int] = None,
        create_time_ms: Optional[int] = None,
        alarm_types: Optional[List[int]] = None,
        page_count: int = 20,
    ) -> Dict[str, Any]:
        """POST /dashcamApi/V2/getDeviceAlarmList returns alarm/event
        history for a device, optionally filtered to
        [begin_time_ms, create_time_ms] and to `alarm_types`. All three
        are optional and omitted from the request entirely when `None`:
        a real capture shows the app's own alarm-list screen calling this
        with only deviceId/pageCount to fetch the most recent alarms,
        with no date range or type filter at all.

        CONFIRMED response: resultBodyObject = list of {"id": str,
        "alramType": int, "eventStatus": int|None, "deviceId",
        "deviceType", "deviceModule", "deviceChannel", "deviceNickName":
        str|None, "fenceName": str|None, "userId", "happenTime":
        int, "coordinatesLat": float|None, "coordinatesLng": float|None,
        "body": Any|None, "pictureUrl": str|None, "videoUrl": <COS
        URL>|None, "coverUrl": <COS URL>|None, "cdnKey", "cdnCoverKey",
        "sychronized": int, "codec", "videoLocalName", "deleted": int,
        "createTimestamp", "updateTimestamp", "attachment":
        <JSON-encoded str>|None (a list of {"key", "userspaceFileId"},
        feed straight into get_file_details()), "deviceSwitchDetail":
        <JSON-encoded str>|None, "videoAttachmentList": Any|None}.
        `alramType`/`eventStatus` are undocumented enums; values observed
        in real traffic: alramType 101 (collision, has GPS + often a
        video attachment), 104/105/107 (seen with no GPS/video — likely
        parking/motion/other trigger types), eventStatus 2 and 3 (seen
        alongside alramType 101, sync/processing state guesses).

        Example resultBodyObject (anonymized; one alarm with no video,
        one collision alarm with an attached front/rear video pair):
        [
          {
            "id": "200000001",
            "alramType": 105,
            "eventStatus": null,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "deviceType": 65,
            "deviceModule": 65001,
            "deviceChannel": 65001001,
            "deviceNickName": "Front Dashcam",
            "fenceName": null,
            "userId": 1000001,
            "happenTime": 1700000000000,
            "coordinatesLat": null,
            "coordinatesLng": null,
            "body": null,
            "pictureUrl": null,
            "videoUrl": null,
            "coverUrl": null,
            "cdnKey": null,
            "cdnCoverKey": null,
            "sychronized": 0,
            "codec": null,
            "videoLocalName": null,
            "deleted": 0,
            "createTimestamp": 1700000000000,
            "updateTimestamp": 1700000000000,
            "attachment": null,
            "deviceSwitchDetail": null,
            "videoAttachmentList": null
          },
          {
            "id": "200000002",
            "alramType": 101,
            "eventStatus": 3,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "deviceType": 65,
            "deviceModule": 65001,
            "deviceChannel": 65001001,
            "deviceNickName": null,
            "fenceName": null,
            "userId": 1000001,
            "happenTime": 1700000000000,
            "coordinatesLat": 45.0,
            "coordinatesLng": 9.0,
            "body": null,
            "pictureUrl": null,
            "videoUrl": "<Tencent COS pre-signed URL>",
            "coverUrl": "<Tencent COS pre-signed URL>",
            "cdnKey": null,
            "cdnCoverKey": null,
            "sychronized": 1,
            "codec": null,
            "videoLocalName": null,
            "deleted": 0,
            "createTimestamp": 1700000600000,
            "updateTimestamp": 1700000900000,
            "attachment": "[{\\"key\\":\\"front_video\\",\\"userspaceFileId\\":\\"aaaa0000aaaa0000aaaa0000aaaa0000\\"},{\\"key\\":\\"backend_video\\",\\"userspaceFileId\\":\\"bbbb0000bbbb0000bbbb0000bbbb0000\\"}]",
            "deviceSwitchDetail": "[{\\"eventType\\":3,\\"resourceKeys\\":[\\"front_video\\",\\"backend_video\\"]},{\\"eventType\\":6,\\"resourceKeys\\":[\\"front_video\\",\\"backend_video\\"]},{\\"eventType\\":9,\\"resourceKeys\\":[]}]",
            "videoAttachmentList": null
          }
        ]
        """
        extra: Dict[str, Any] = {"deviceId": device_id, "pageCount": page_count}
        if begin_time_ms is not None:
            extra["beginTime"] = begin_time_ms
        if create_time_ms is not None:
            extra["createTime"] = create_time_ms
        if alarm_types is not None:
            extra["alramTypes"] = alarm_types  # sic: verbatim typo in the real API
        return self._post("/dashcamApi/V2/getDeviceAlarmList", self._signed_body(extra))

    def get_device_alarm(self, device_id: str, alarm_id: str) -> Dict[str, Any]:
        """POST /dashcamApi/V2/getDeviceAlarm returns a single alarm/event
        detail. CONFIRMED response: resultBodyObject = same item shape as
        get_device_alarm_list() (a single dict, not wrapped in a list).

        Example resultBodyObject (anonymized; same alarm as the second
        item in get_device_alarm_list()'s example):
        {
          "id": "200000002",
          "alramType": 101,
          "eventStatus": 3,
          "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
          "deviceType": 65,
          "deviceModule": 65001,
          "deviceChannel": 65001001,
          "deviceNickName": null,
          "fenceName": null,
          "userId": 1000001,
          "happenTime": 1700000000000,
          "coordinatesLat": 45.0,
          "coordinatesLng": 9.0,
          "body": null,
          "pictureUrl": null,
          "videoUrl": "<Tencent COS pre-signed URL>",
          "coverUrl": "<Tencent COS pre-signed URL>",
          "cdnKey": null,
          "cdnCoverKey": null,
          "sychronized": 1,
          "codec": null,
          "videoLocalName": null,
          "deleted": 0,
          "createTimestamp": 1700000600000,
          "updateTimestamp": 1700000900000,
          "attachment": "[{\\"key\\":\\"front_video\\",\\"userspaceFileId\\":\\"aaaa0000aaaa0000aaaa0000aaaa0000\\"},{\\"key\\":\\"backend_video\\",\\"userspaceFileId\\":\\"bbbb0000bbbb0000bbbb0000bbbb0000\\"}]",
          "deviceSwitchDetail": "[{\\"eventType\\":3,\\"resourceKeys\\":[\\"front_video\\",\\"backend_video\\"]},{\\"eventType\\":6,\\"resourceKeys\\":[\\"front_video\\",\\"backend_video\\"]},{\\"eventType\\":9,\\"resourceKeys\\":[]}]",
          "videoAttachmentList": null
        }
        """
        return self._post(
            "/dashcamApi/V2/getDeviceAlarm",
            self._signed_body({"deviceId": device_id, "alarmId": alarm_id}),
        )

    # ------------------------------------------------------------------ #
    # deviceSwitchApi: per-device feature toggles
    # ------------------------------------------------------------------ #
    def get_device_switch(self, device_id: str) -> Dict[str, Any]:
        """POST /deviceSwitchApi/getDeviceSwitch returns per-device feature
        toggle state. CONFIRMED response: resultBodyObject =
        {"monitorVedioUpload": bool, "details": [{"eventType": int,
        "resourceKeys": List[str]}]} (same shape set_device_switch()
        writes).

        Example resultBodyObject:
        {
          "monitorVedioUpload": true,
          "details": [
            {"eventType": 3, "resourceKeys": ["front_video", "backend_video"]},
            {"eventType": 9, "resourceKeys": []}
          ]
        }
        """
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

        Example resultBodyObject: true
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

        Example resultBodyObject (a real capture only observed an empty
        list, i.e. `[]`, for a day with no buckets)."""
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
        resultBodyObject = bool.

        Example resultBodyObject: true
        """
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

        Example resultBodyObject (fileUrl/fileMd5 genericized):
        {
          "newVersion": true,
          "version": "1.4.82.ww",
          "versionOrder": null,
          "subVersion": "a",
          "fileUrl": "https://de-resource.70mai.com/48002001/OTA_example_full.bin",
          "fileMd5": "00000000000000000000000000000000",
          "fileSize": 5265284,
          "desc": "Fixed intermittent connection failure issue;\\nFixed other known issues.",
          "targetDesc": null,
          "packageId": 1325,
          "romVersionId": 2144,
          "releaseTime": 1700000000000,
          "forced": false
        }
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
        """POST /accountApi/V3/getWebsocketAddressForApp: a live
        device-status push endpoint. CONFIRMED response: resultBodyObject
        = {"websocketAddress": <wss:// URL>, "websocketToken": str,
        "websocketAesKey": <base64 str>, "appToken": Any|None}. The
        websocket handshake/message protocol itself is not implemented
        here.

        Example resultBodyObject (websocketToken/websocketAesKey are
        secrets, redacted rather than faked):
        {
          "websocketAddress": "wss://eu-websocketforapp.example.com:10004/websocket",
          "websocketToken": "<opaque session token>",
          "websocketAesKey": "<base64-encoded AES key>",
          "appToken": null
        }
        """
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
        """POST /UserspaceApi/getFileDetails. `file_ids` are
        `userspaceFileId` values from an alarm's `attachment` field (see
        get_device_alarm_list()/get_device_alarm()). CONFIRMED response:
        resultBodyObject = list of {"fileId", "fileName", "fileOrigName",
        "fileType": int, "fileSubType": int, "deviceId",
        "genDeviceType", "genDeviceModule", "genDeviceChannel",
        "createTimestamp", "fileStartTs", "fileEndTs", "uploadTimestamp",
        "fileStatus": int, "mainUrl": <COS URL>, "mainSize": int,
        "mainWidth": int, "mainHeight": int, "videoCodec": str,
        "videoCoverUrl": <COS URL>, "videoCoverSize"/"videoCoverWidth"/
        "videoCoverHeight": int, "rsUrl": Any|None}. Tencent-COS
        pre-signed download URLs for eu4gmedia.70mai.com; those
        signatures are generated server-side and should never be built
        client-side.

        Example resultBodyObject (anonymized; a front+rear video pair
        from one collision alarm):
        [
          {
            "fileId": "aaaa0000aaaa0000aaaa0000aaaa0000",
            "fileName": "V2_PA20250101-000000-000001F.MP4",
            "fileOrigName": "PA20250101-000000-000001F.MP4",
            "fileType": 1,
            "fileSubType": 101,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "genDeviceType": 65,
            "genDeviceModule": 65001,
            "genDeviceChannel": 65001001,
            "createTimestamp": 1700000000000,
            "fileStartTs": 1700000000000,
            "fileEndTs": 1700000030000,
            "uploadTimestamp": 1700000300000,
            "fileStatus": 3,
            "mainUrl": "<Tencent COS pre-signed URL>",
            "mainSize": 8438194,
            "mainWidth": 848,
            "mainHeight": 480,
            "videoCodec": "h264",
            "videoCoverUrl": "<Tencent COS pre-signed URL>",
            "videoCoverSize": 11784,
            "videoCoverWidth": 640,
            "videoCoverHeight": 360,
            "rsUrl": null
          },
          {
            "fileId": "bbbb0000bbbb0000bbbb0000bbbb0000",
            "fileName": "V2_PA20250101-000000-000001B.MP4",
            "fileOrigName": "PA20250101-000000-000001B.MP4",
            "fileType": 1,
            "fileSubType": 101,
            "deviceId": "deadbeefdeadbeefdeadbeefdeadbeef",
            "genDeviceType": 65,
            "genDeviceModule": 65001,
            "genDeviceChannel": 65001001,
            "createTimestamp": 1700000000000,
            "fileStartTs": 1700000000000,
            "fileEndTs": 1700000030000,
            "uploadTimestamp": 1700000400000,
            "fileStatus": 3,
            "mainUrl": "<Tencent COS pre-signed URL>",
            "mainSize": 33339765,
            "mainWidth": 1920,
            "mainHeight": 1080,
            "videoCodec": "h264",
            "videoCoverUrl": "<Tencent COS pre-signed URL>",
            "videoCoverSize": 15968,
            "videoCoverWidth": 640,
            "videoCoverHeight": 360,
            "rsUrl": null
          }
        ]
        """
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
