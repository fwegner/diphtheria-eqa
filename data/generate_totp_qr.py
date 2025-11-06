#!/usr/bin/env python3
"""
Utility for creating QR codes from the seeded initial credentials.

Usage:
    python data/generate_totp_qr.py

Outputs:
- PNG files under data/totp_qr/ with per-user TOTP provisioning QR codes.
- data/totp_qr/totp_qr_embeds.csv containing username, path, provisioning URI, and a base64 data URI
  that can be embedded directly in HTML emails.
"""

import base64
import csv
import io
import sys
from pathlib import Path

import pyotp
import qrcode

ROOT = Path(__file__).resolve().parent
INITIAL_CREDENTIALS = ROOT / "initial_credentials.csv"
OUTPUT_DIR = ROOT / "totp_qr"
ISSUER_NAME = "Diphtheria EQA Portal"


def encode_png_to_data_uri(image) -> str:
    buf = io.BytesIO()
    image.save(buf, format="PNG")
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def main():
    if not INITIAL_CREDENTIALS.exists():
        print(f"[!] No credentials file at {INITIAL_CREDENTIALS}. Run the app once to generate it.")
        return 1

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(INITIAL_CREDENTIALS, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        rows = list(reader)

    if not rows:
        print("[!] initial_credentials.csv is empty; nothing to do.")
        return 1

    created, skipped = [], []
    for idx, row in enumerate(rows, start=2):
        username = (row.get("username") or "").strip()
        secret = (row.get("totp_secret") or "").strip()
        if not username or not secret:
            skipped.append((idx, username or "<missing>"))
            continue
        try:
            uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)
        except Exception as exc:  # pragma: no cover - defensive; pyotp handles most validation
            skipped.append((idx, f"{username} ({exc})"))
            continue
        qr_image = qrcode.make(uri)
        image_path = OUTPUT_DIR / f"{username}_totp.png"
        qr_image.save(image_path)
        created.append(
            {
                "username": username,
                "image_path": image_path.as_posix(),
                "provisioning_uri": uri,
                "data_uri": encode_png_to_data_uri(qr_image),
            }
        )

    if not created:
        print("[!] No valid users found; see skipped entries above.")
        return 1

    output_csv = OUTPUT_DIR / "totp_qr_embeds.csv"
    with open(output_csv, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["username", "image_path", "provisioning_uri", "data_uri"])
        for entry in created:
            writer.writerow(
                [
                    entry["username"],
                    entry["image_path"],
                    entry["provisioning_uri"],
                    entry["data_uri"],
                ]
            )

    print(f"[+] Generated {len(created)} QR codes in {OUTPUT_DIR}")
    print(f"[+] Email embed data written to {output_csv}")
    if skipped:
        print("[!] Skipped entries:")
        for row in skipped:
            print(f"    line {row[0]} -> {row[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
