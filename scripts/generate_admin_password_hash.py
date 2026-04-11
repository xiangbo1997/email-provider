#!/usr/bin/env python3
from __future__ import annotations

import argparse
import getpass

from services.admin_auth_service import admin_auth_service
from services.crypto_utils import generate_random_key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate admin password hash / data encryption key")
    parser.add_argument("--password", default=None, help="Admin password in plain text (omit to use prompt)")
    parser.add_argument(
        "--generate-data-key",
        action="store_true",
        help="Generate a random EMAIL_PROVIDER_DATA_ENCRYPTION_KEY",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.generate_data_key:
        print("EMAIL_PROVIDER_DATA_ENCRYPTION_KEY=" + generate_random_key())
        return 0

    password = args.password or getpass.getpass("Admin password: ")
    if not password:
        raise SystemExit("password is empty")

    encoded = admin_auth_service.create_password_hash(password)
    print("EMAIL_PROVIDER_ADMIN_PASSWORD_HASH=" + encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
