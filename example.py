"""
Usage example.

The default signer (BanyacKeyMd5SignatureProvider) is used automatically,
so there's nothing to configure for that. If you already have a session
token from elsewhere, set client.token directly and skip login().
"""
import uuid

from client70mai import MaiClient


def main() -> None:
    client = MaiClient(uuid=str(uuid.uuid4()).upper())

    client.login(email="your-email", plain_password="your-password")
    devices = client.get_all_device_for_user()
    print(devices)

    detail = client.get_dashcam_detail(device_id="your-device-id")
    print(detail)

    client.logout()


if __name__ == "__main__":
    main()
