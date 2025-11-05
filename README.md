# Diphtheria EQA Portal

## Running the app

- Install dependencies with `pip install -r requirements.txt`.
- Launch Streamlit: `streamlit run app.py`.

## Authentication workflow

- On first launch the app seeds `data/users.db` with users from `users.csv` (or defaults) and generates strong random passwords plus TOTP secrets.
- The temporary credentials are written once to `data/initial_credentials.csv`; distribute them securely, then delete or move the file.
- Users log in with username + password and then the 6-digit TOTP from their authenticator app.
- Users can scan a QR code (or manually enter the secret) and change their password from the **Account settings** page.

## Email-ready QR codes

- Run `python data/generate_totp_qr.py`.
- PNG files are created under `data/totp_qr/` and `data/totp_qr/totp_qr_embeds.csv` contains the provisioning URI plus a base64 `data:` URL per user for embedding directly into emails.
