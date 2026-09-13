"""
Interactive console for client70mai: login, list dashcams, pick one, then
drive its device-specific API calls. Every response is pretty-printed as
colored JSON via `rich`.

Run: python3 console.py
"""
from __future__ import annotations

import getpass
import json
import time
import uuid as uuid_module
from datetime import date
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from client70mai import MaiClient
from client70mai.exceptions import MaiError

console = Console()

# "deviceId" is always present, "nickName" can be null (see
# get_all_device_for_user() in client70mai/client.py). The extra
# fallbacks below only matter for an older/different device dict shape.
DEVICE_ID_KEYS = ("deviceId", "id", "device_id", "sn", "deviceSn")
DEVICE_NAME_KEYS = ("nickName", "deviceName", "name", "alias", "model")


def print_json(data: Any) -> None:
    console.print_json(json.dumps(data, ensure_ascii=False))


def print_error(exc: Exception) -> None:
    console.print(f"[bold red]Error:[/bold red] {exc}")


def call(label: str, fn, *args, **kwargs) -> Optional[Dict[str, Any]]:
    """Run a MaiClient method, print its (pretty, colored) JSON result or
    a red error line, and return the parsed result (None on failure)."""
    console.print(f"\n[bold cyan]>> {label}[/bold cyan]")
    try:
        result = fn(*args, **kwargs)
    except MaiError as exc:
        print_error(exc)
        return None
    print_json(result)
    return result


def extract_device_list(result_body: Any) -> List[Dict[str, Any]]:
    if isinstance(result_body, list):
        return [d for d in result_body if isinstance(d, dict)]
    if isinstance(result_body, dict):
        for value in result_body.values():
            if isinstance(value, list) and value and isinstance(value[0], dict):
                return value
    return []


def guess_field(item: Dict[str, Any], keys: tuple) -> Optional[str]:
    for key in keys:
        if key in item and item[key] is not None:
            return str(item[key])
    return None


def choose_device(devices: List[Dict[str, Any]]) -> Optional[str]:
    if not devices:
        console.print("[yellow]No devices found in the response.[/yellow]")
        manual = console.input("Enter a deviceId manually (blank to cancel): ").strip()
        return manual or None

    table = Table(title="Available dashcams")
    table.add_column("#", justify="right")
    table.add_column("deviceId")
    table.add_column("nickName")
    for i, item in enumerate(devices):
        table.add_row(str(i), guess_field(item, DEVICE_ID_KEYS) or "?", guess_field(item, DEVICE_NAME_KEYS) or "")
    console.print(table)

    choice = console.input("Pick an index (or paste a deviceId): ").strip()
    if choice.isdigit() and int(choice) < len(devices):
        device_id = guess_field(devices[int(choice)], DEVICE_ID_KEYS)
        if device_id:
            return device_id
        console.print("[yellow]Couldn't find a deviceId field on that entry.[/yellow]")
        return console.input("Paste the deviceId manually: ").strip() or None
    return choice or None


def do_login(client: MaiClient) -> bool:
    email = console.input("Email: ").strip()
    password = getpass.getpass("Password: ")
    result = call("login", client.login, email=email, plain_password=password)
    return result is not None and client.token is not None


def device_menu(client: MaiClient, device_id: str) -> None:
    while True:
        console.print(f"\n[bold]Selected dashcam:[/bold] {device_id}")
        console.print(
            "1) Dashcam detail     2) GPS position       3) SIM status\n"
            "4) Offline detail     5) SIM out-power       6) Alarm list\n"
            "7) Alarm detail       8) Daily history        9) Report WiFi (offline)\n"
            "10) File details      11) Supported features 12) Dashcam status\n"
            "13) Value-added svc   14) Device switch       15) Set device switch\n"
            "0) Back to main menu"
        )
        choice = console.input("> ").strip()

        if choice == "1":
            call("getDashcamDetail", client.get_dashcam_detail, device_id)
        elif choice == "2":
            call("getPosition", client.get_position, device_id)
        elif choice == "3":
            call("getSimPluginDetail", client.get_sim_plugin_detail, device_id)
        elif choice == "4":
            call("getDeviceDetail (offline)", client.get_offline_device_detail, device_id)
        elif choice == "5":
            call("simPluginSupportOutPower", client.sim_plugin_support_out_power, device_id)
        elif choice == "6":
            now_ms = int(time.time() * 1000)
            week_ms = 7 * 24 * 60 * 60 * 1000
            begin = console.input(f"beginTime ms [default: -7d = {now_ms - week_ms}]: ").strip()
            create = console.input(f"createTime ms [default: now = {now_ms}]: ").strip()
            page = console.input("pageCount [default 20]: ").strip()
            call(
                "getDeviceAlarmList",
                client.get_device_alarm_list,
                device_id,
                int(begin) if begin else now_ms - week_ms,
                int(create) if create else now_ms,
                [105, 108],
                int(page) if page else 20,
            )
        elif choice == "7":
            alarm_id = console.input("alarmId: ").strip()
            if alarm_id:
                call("getDeviceAlarm", client.get_device_alarm, device_id, alarm_id)
        elif choice == "8":
            today = date.today()
            year = console.input(f"year [default {today.year}]: ").strip()
            month = console.input(f"month [default {today.month}]: ").strip()
            day = console.input(f"day [default {today.day}]: ").strip()
            key_index = console.input("keyIndex [default 1.2]: ").strip() or "1.2"
            call(
                "getDeviceStatusHistoryDaily",
                client.get_device_status_history_daily,
                device_id,
                int(year) if year else today.year,
                int(month) if month else today.month,
                int(day) if day else today.day,
                key_index,
                51,
                0,
            )
        elif choice == "9":
            bssid = console.input("bssid (WiFi MAC, e.g. aa:bb:cc:dd:ee:ff): ").strip()
            if bssid:
                call("reportOfflineDeviceStatistics", client.report_offline_device_statistics, device_id, bssid)
        elif choice == "10":
            raw = console.input("Comma-separated fileIds: ").strip()
            file_ids = [f.strip() for f in raw.split(",") if f.strip()]
            if file_ids:
                call("getFileDetails", client.get_file_details, file_ids)
        elif choice == "11":
            call("getSupportedFeatures", client.get_supported_features, device_id)
        elif choice == "12":
            call("getDashcamStatus", client.get_dashcam_status, device_id)
        elif choice == "13":
            vas = console.input("valueAddedService [default 2]: ").strip()
            call(
                "isActiveValueAddedService",
                client.is_active_value_added_service,
                int(vas) if vas else 2,
            )
        elif choice == "14":
            call("getDeviceSwitch", client.get_device_switch, device_id)
        elif choice == "15":
            upload = console.input("monitorVedioUpload true/false [default true]: ").strip().lower()
            monitor_video_upload = upload != "false"
            call(
                "setDeviceSwitch",
                client.set_device_switch,
                device_id,
                monitor_video_upload,
                [
                    {"eventType": 3, "resourceKeys": ["front_video", "backend_video"]},
                    {"eventType": 9, "resourceKeys": []},
                ],
            )
        elif choice == "0":
            return
        else:
            console.print("[yellow]Invalid choice.[/yellow]")


def main() -> None:
    console.print("[bold green]70mai console[/bold green]")
    default_uuid = str(uuid_module.uuid4()).upper()
    client_uuid = console.input(f"Device UUID [default {default_uuid}]: ").strip() or default_uuid
    device_token = console.input("FCM device token (optional, press enter to skip): ").strip() or None

    client = MaiClient(uuid=client_uuid, device_token=device_token)
    selected_device_id: Optional[str] = None

    while True:
        logged_in = client.token is not None
        console.print(
            f"\n[bold]Main menu[/bold] ({'logged in' if logged_in else 'not logged in'})"
        )
        console.print(
            "1) Login              2) Account info (getAllUserInfo)\n"
            "3) List dashcams       4) Select dashcam / open dashcam menu\n"
            "5) Ads (getAdvertisementByLocation)\n"
            "0) Logout and quit"
        )
        choice = console.input("> ").strip()

        if choice == "1":
            do_login(client)
        elif choice == "2":
            if not client.token:
                console.print("[yellow]Log in first.[/yellow]")
                continue
            call("getAllUserInfo", client.get_all_user_info)
        elif choice == "3":
            if not client.token:
                console.print("[yellow]Log in first.[/yellow]")
                continue
            result = call("getAllDeviceForUser", client.get_all_device_for_user)
            if result is not None:
                devices = extract_device_list(result.get("resultBodyObject"))
                picked = choose_device(devices)
                if picked:
                    selected_device_id = picked
                    console.print(f"[green]Selected dashcam: {selected_device_id}[/green]")
        elif choice == "4":
            if not client.token:
                console.print("[yellow]Log in first.[/yellow]")
                continue
            if not selected_device_id:
                selected_device_id = console.input("No dashcam selected. Paste a deviceId: ").strip() or None
            if selected_device_id:
                device_menu(client, selected_device_id)
        elif choice == "5":
            if not client.token:
                console.print("[yellow]Log in first.[/yellow]")
                continue
            call("getAdvertisementByLocation", client.get_advertisement_by_location)
        elif choice == "0":
            if client.token:
                call("logout", client.logout)
            console.print("[bold green]Bye![/bold green]")
            return
        else:
            console.print("[yellow]Invalid choice.[/yellow]")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[bold green]Interrupted.[/bold green]")
