#!/usr/bin/env python3
"""
Create or update user accounts for the Diphtheria EQA portal.

Examples:
    python data/add_user.py lab3
    python data/add_user.py --admin admin2
    python data/add_user.py --password MyTempPass! --totp-secret ABCDEF1234567890 lab4
    python data/add_user.py --force lab1  # regenerate password/TOTP for existing user

Outputs:
    - Updates data/users.db with the hashed password + TOTP secret.
    - Writes/updates the corresponding row in data/initial_credentials.csv so you can share the credentials.
"""

import argparse
import csv
import secrets
import sqlite3
import sys
from pathlib import Path

import bcrypt
import pyotp

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT
AUTH_DB = DATA_DIR / "users.db"
INITIAL_CREDENTIALS = DATA_DIR / "initial_credentials.csv"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def ensure_db_ready():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(AUTH_DB) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                must_change_password INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.commit()


def read_existing_user(username: str):
    with sqlite3.connect(AUTH_DB) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT username, password_hash, totp_secret, is_admin FROM users WHERE lower(username)=lower(?)",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def upsert_user(username: str, password: str, totp_secret: str, is_admin: bool, force: bool):
    with sqlite3.connect(AUTH_DB) as conn:
        conn.row_factory = sqlite3.Row
        existing = conn.execute(
            "SELECT username FROM users WHERE lower(username)=lower(?)",
            (username,),
        ).fetchone()
        if existing and not force:
            return False, "User already exists. Use --force to regenerate credentials."

        password_hash = hash_password(password)
        if existing:
            conn.execute(
                """
                UPDATE users
                SET password_hash = ?, totp_secret = ?, is_admin = ?, must_change_password = 1
                WHERE lower(username)=lower(?)
                """,
                (password_hash, totp_secret, int(is_admin), username),
            )
        else:
            conn.execute(
                """
                INSERT INTO users (username, password_hash, totp_secret, is_admin, must_change_password)
                VALUES (?, ?, ?, ?, 1)
                """,
                (username, password_hash, totp_secret, int(is_admin)),
            )
        conn.commit()
    return True, None


def update_initial_credentials(username: str, password: str, totp_secret: str, is_admin: bool):
    rows = []
    if INITIAL_CREDENTIALS.exists():
        with open(INITIAL_CREDENTIALS, newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            rows = list(reader)

    filtered = [row for row in rows if (row.get("username") or "").lower() != username.lower()]
    filtered.append(
        {
            "username": username,
            "password": password,
            "totp_secret": totp_secret,
            "is_admin": str(int(is_admin)),
        }
    )

    with open(INITIAL_CREDENTIALS, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["username", "password", "totp_secret", "is_admin"])
        writer.writeheader()
        writer.writerows(filtered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("username", help="Username to create or update.")
    parser.add_argument("--admin", action="store_true", help="Mark the user as an administrator.")
    parser.add_argument("--password", help="Specify a temporary password (default: generated).")
    parser.add_argument("--totp-secret", help="Provide an explicit TOTP secret (default: generated).")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Allow updating an existing user (regenerates password/TOTP and sets must_change_password).",
    )
    args = parser.parse_args()

    ensure_db_ready()

    username = args.username.strip()
    if not username:
        parser.error("Username cannot be empty.")

    password = args.password or secrets.token_urlsafe(12)
    totp_secret = args.totp_secret or pyotp.random_base32()

    success, message = upsert_user(username, password, totp_secret, args.admin, args.force)
    if not success:
        print(f"[!] {message}")
        return 1

    update_initial_credentials(username, password, totp_secret, args.admin)

    print("[+] Credentials recorded:")
    print(f"    username:     {username}")
    print(f"    temp password:{password}")
    print(f"    TOTP secret:  {totp_secret}")
    print(f"    admin:        {'yes' if args.admin else 'no'}")
    print(f"[+] initial_credentials.csv updated (previous entries kept).")
    print("[!] Remember to run data/generate_totp_qr.py to refresh QR codes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
