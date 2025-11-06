
import io
import json
import os
import secrets
import sqlite3
import datetime as dt
from pathlib import Path
from typing import Dict, Optional

import bcrypt
import pandas as pd
import pyotp
import streamlit as st
import qrcode

st.set_page_config(page_title="Diphtheria EQA Portal", layout="wide")

DATA_DIR = Path("data")
SUBMIT_DIR = DATA_DIR / "submissions"
SUBMIT_DIR.mkdir(parents=True, exist_ok=True)
AUTH_DB = DATA_DIR / "users.db"
INITIAL_CREDENTIALS_PATH = DATA_DIR / "initial_credentials.csv"
DEFAULT_USERS = [
    {"username": "admin", "is_admin": True},
    {"username": "lab1", "is_admin": False},
    {"username": "lab2", "is_admin": False},
]


def _get_seed_users():
    """Collect the initial set of users from users.csv (if present) or fall back to defaults."""
    users_csv = Path("users.csv")
    seed_users = []
    if users_csv.exists():
        import csv

        with open(users_csv, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                username = (row.get("username") or "").strip()
                if not username:
                    continue
                seed_users.append(
                    {
                        "username": username,
                        "is_admin": username.lower() == "admin",
                    }
                )
    return seed_users or DEFAULT_USERS


def _export_initial_credentials(rows):
    """Persist the one-time credentials so admins can distribute them securely."""
    if not rows or INITIAL_CREDENTIALS_PATH.exists():
        return
    INITIAL_CREDENTIALS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(INITIAL_CREDENTIALS_PATH, "w", encoding="utf-8") as handle:
        handle.write("username,password,totp_secret,is_admin\n")
        for row in rows:
            handle.write(
                f"{row['username']},{row['password']},{row['totp_secret']},{int(row['is_admin'])}\n"
            )


def _get_connection():
    conn = sqlite3.connect(AUTH_DB)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


def initialize_user_store():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with _get_connection() as conn:
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
        existing_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if existing_count:
            return

        seed_users = _get_seed_users()
        issued_credentials = []
        for user in seed_users:
            random_password = secrets.token_urlsafe(12)
            password_hash = hash_password(random_password)
            totp_secret = pyotp.random_base32()
            conn.execute(
                """
                INSERT INTO users (username, password_hash, totp_secret, is_admin, must_change_password)
                VALUES (?, ?, ?, ?, 1)
                """,
                (
                    user["username"],
                    password_hash,
                    totp_secret,
                    1 if user["is_admin"] else 0,
                ),
            )
            issued_credentials.append(
                {
                    "username": user["username"],
                    "password": random_password,
                    "totp_secret": totp_secret,
                    "is_admin": user["is_admin"],
                }
            )
        conn.commit()
    _export_initial_credentials(issued_credentials)


def get_user(username: str) -> Optional[Dict]:
    if not username:
        return None
    with _get_connection() as conn:
        row = conn.execute(
            """
            SELECT username, password_hash, totp_secret, is_admin, must_change_password
            FROM users
            WHERE lower(username) = lower(?)
            """,
            (username,),
        ).fetchone()
    if not row:
        return None
    return {
        "username": row["username"],
        "password_hash": row["password_hash"],
        "totp_secret": row["totp_secret"],
        "is_admin": bool(row["is_admin"]),
        "must_change_password": bool(row["must_change_password"]),
    }


def verify_totp(secret: str, token: str) -> bool:
    if not secret or not token:
        return False
    token = token.strip().replace(" ", "")
    if not token.isdigit():
        return False
    totp = pyotp.TOTP(secret)
    return bool(totp.verify(token, valid_window=1))


def update_password(username: str, new_password: str):
    hashed = hash_password(new_password)
    with _get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET password_hash = ?, must_change_password = 0
            WHERE username = ?
            """,
            (hashed, username),
        )
        conn.commit()


initialize_user_store()

# --- Authentication helpers ---
def ensure_session_defaults():
    if "auth" not in st.session_state:
        st.session_state.auth = {
            "ok": False,
            "user": None,
            "is_admin": False,
            "must_change_password": False,
        }
    st.session_state.setdefault("login_stage", "credentials")
    st.session_state.setdefault("pending_user", None)


def render_credentials_step():
    st.title("Diphtheria (Corynebacterium) EQA Portal")
    st.caption("University of Zurich — External Quality Assessment (ring trial)")
    with st.form("login_credentials_form", clear_on_submit=False):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Continue")
    if submitted:
        user_record = get_user(username)
        if not user_record or not verify_password(password, user_record["password_hash"]):
            st.error("Invalid username or password.")
        else:
            st.session_state.pending_user = user_record
            st.session_state.login_stage = "totp"
            st.rerun()


def render_totp_step():
    pending = st.session_state.get("pending_user")
    if not pending:
        st.session_state.login_stage = "credentials"
        st.rerun()
    st.title("Two-factor authentication")
    st.caption(
        "Enter the 6-digit code from your authenticator app. Codes refresh every 30 seconds."
    )
    totp_code = st.text_input("Authenticator code", max_chars=6, type="password")
    col1, col2 = st.columns([1, 1])
    verify = col1.button("Verify", use_container_width=True)
    back = col2.button("Back", use_container_width=True)
    if back:
        st.session_state.login_stage = "credentials"
        st.session_state.pending_user = None
        st.rerun()
    if verify:
        if verify_totp(pending["totp_secret"], totp_code):
            st.session_state.auth.update(
                {
                    "ok": True,
                    "user": pending["username"],
                    "is_admin": pending["is_admin"],
                    "must_change_password": pending["must_change_password"],
                }
            )
            st.session_state.login_stage = "credentials"
            st.session_state.pending_user = None
            st.success("Authentication successful.")
            st.rerun()
        else:
            st.error("Invalid authentication code.")


def require_login():
    ensure_session_defaults()
    if st.session_state.login_stage == "credentials":
        render_credentials_step()
    else:
        render_totp_step()
    st.stop()


ensure_session_defaults()

if not st.session_state.auth["ok"]:
    require_login()

# --- App starts ---
user = st.session_state.auth["user"]
is_admin = st.session_state.auth["is_admin"]
must_change_password = st.session_state.auth.get("must_change_password", False)

st.sidebar.markdown("### Navigation")
if must_change_password:
    st.sidebar.warning("Please change your password in Account settings.")
nav_options = ["Submit results"]
if is_admin:
    nav_options.append("Download (admin)")
nav_options.append("Account settings")
page = st.sidebar.radio("Go to", nav_options)
if st.sidebar.button("Log out"):
    st.session_state.auth = {
        "ok": False,
        "user": None,
        "is_admin": False,
        "must_change_password": False,
    }
    st.session_state.login_stage = "credentials"
    st.session_state.pending_user = None
    st.rerun()

# Shared helpers
def save_json(obj, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)

def load_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

# ---------- Submit results (per lab) ----------
if page == "Submit results":
    st.header("Lab Submission")
    st.write("Fill in information for **10 samples** and your **capacity needs**. You can save and resume later with the same login.")

    # Load or init draft
    draft_path = SUBMIT_DIR / f"{user}.json"
    data = load_json(draft_path, default={"lab_info": {}, "samples": {}, "needs": {}})

    with st.expander("Institution & Contact", expanded=True):
        cols = st.columns(3)
        data["lab_info"]["institution"] = cols[0].text_input("Institution", value=data["lab_info"].get("institution",""))
        data["lab_info"]["address"] = cols[1].text_input("Address", value=data["lab_info"].get("address",""))
        data["lab_info"]["city"] = cols[2].text_input("City", value=data["lab_info"].get("city",""))
        cols2 = st.columns(3)
        data["lab_info"]["country"] = cols2[0].text_input("Country", value=data["lab_info"].get("country",""))
        data["lab_info"]["contact_name"] = cols2[1].text_input("Contact name", value=data["lab_info"].get("contact_name",""))
        data["lab_info"]["email"] = cols2[2].text_input("Email", value=data["lab_info"].get("email",""))
        cols3 = st.columns(3)
        st.write("Date of specimen reception")
        data["lab_info"]["year"] = cols3[0].number_input("Year", value=int(data["lab_info"].get("year", dt.date.today().year)), step=1)
        data["lab_info"]["month"] = cols3[1].number_input("Month", value=int(data["lab_info"].get("month", dt.date.today().month)), min_value=1, max_value=12, step=1)
        data["lab_info"]["day"] = cols3[2].number_input("Day", value=int(data["lab_info"].get("day", dt.date.today().day)), min_value=1, max_value=31, step=1)

    st.markdown("---")
    st.subheader("Per-sample results")

    sample_tabs = st.tabs([f"Sample {i}" for i in range(1,11)])
    antibiotic_list = ['Benzylpenicillin', 'Amoxicillin', 'Cefotaxime', 'Meropenem', 'Ciprofloxacin', 'Erythromycin', 'Clindamycin', 'Doxycycline', 'Tetracycline', 'Linezolid', 'Rifampicin', 'Trimethoprim-sulfamethoxazole']

    for i, tab in enumerate(sample_tabs, start=1):
        with tab:
            sid = str(i)
            sdat = data["samples"].get(sid, {})

            # ---- Species identification ----
            st.markdown("#### Species identification")
            c1, c2, c3 = st.columns([1.2, 1, 1])

            # Species name (free text)
            sdat["species_identified"] = c1.text_input(
                "Species identified",
                value=sdat.get("species_identified", ""),
                key=f"sid_species_{i}",
            )

            # ID Method (selectbox)
            with c2:
                _id_method_options = [
                    "",
                    "API",
                    "MALDI-TOF MS",
                    "PCR",
                    "16S rRNA sequencing",
                    "rpoB sequencing",
                    "WGS",
                    "BD PhoenixTM",
                    "VITEK",
                    "Other (specify in comments)",
                ]
                current = sdat.get("id_method", "")
                sdat["id_method"] = st.selectbox(
                    "ID Method",
                    _id_method_options,
                    index=(_id_method_options.index(current) if current in _id_method_options else 0),
                    key=f"sid_method_{i}",
                )

            # Company / Kit (free text)
            sdat["company"] = c3.text_input(
                "Company / Kit",
                value=sdat.get("company", ""),
                key=f"sid_company_{i}",
            )

            # Comments (ID) — use this if "Other (specify in comments)" was chosen above
            sdat["id_comments"] = st.text_area(
                "Comments (ID)",
                value=sdat.get("id_comments", ""),
                key=f"sid_id_comments_{i}",
            )
            # ---- End Species identification ----

            # ---- Antibiotic susceptibility testing (AST) ----
            st.markdown("#### Antibiotic susceptibility testing (AST)")
            st.caption("Enter values where applicable. Leave blank if not tested.")

            import pandas as pd
            from streamlit import column_config as cc  # for SelectboxColumn

            # Options
            _method_options = [
                "disk diffusion",
                "MIC test strip",
                "broth microdilution",
                "automated- Vitek®",
                "automated- PhoenixTM",
                "other (please specify which in Details)",
            ]
            _guideline_options = [
                "EUCAST",
                "CLSI",
                "other (please specify which in Details)",
            ]

            # Build (or load) the table
            ast_df = pd.DataFrame(sdat.get("ast_table", [])) if sdat.get("ast_table") else pd.DataFrame({
                "Antibiotic": antibiotic_list,
                "Disk content (µg)": ["" for _ in antibiotic_list],
                "Zone diameter (mm)": ["" for _ in antibiotic_list],
                "MIC (mg/L)": ["" for _ in antibiotic_list],
                "Reported result (S/I/R)": ["" for _ in antibiotic_list],
                "Method": ["" for _ in antibiotic_list],
                "Guideline": ["" for _ in antibiotic_list],
            })

            
            # Per-row editor with dropdowns for Method & Guideline
            ast_df = st.data_editor(
                ast_df,
                num_rows="fixed",
                key=f"ast_table_{i}",
                column_config={
                    "Method": cc.SelectboxColumn(
                        "Method",
                        help="Select testing method per antibiotic.",
                        options=_method_options + [""] ,  # keep '' to allow clearing
                    ),
                    "Guideline": cc.SelectboxColumn(
                        "Guideline",
                        help="Select guideline per antibiotic.",
                        options=_guideline_options + [""],
                    ),
                    "Reported result (S/I/R)": cc.TextColumn("Reported result (S/I/R)"),
                    "Disk content (µg)": cc.TextColumn("Disk content (µg)"),
                    "Zone diameter (mm)": cc.TextColumn("Zone diameter (mm)"),
                    "MIC (mg/L)": cc.TextColumn("MIC (mg/L)"),
                },
                use_container_width=True,
            )

            # Persist table + comments + remember chosen globals
            sdat["ast_table"] = ast_df.to_dict(orient="records")
            sdat["ast_comments"] = st.text_area(
                "Comments (AST)",
                value=sdat.get("ast_comments", ""),
                key=f"sid_ast_comments_{i}",
            )
            
            # ---- End AST ----

            # st.markdown("#### Antibiotic susceptibility testing (AST)")
            # st.caption("Enter values where applicable. Leave blank if not tested.")
            # import pandas as pd
            # ast_df = pd.DataFrame(sdat.get("ast_table", [])) if sdat.get("ast_table") else pd.DataFrame({
            #     "Antibiotic": antibiotic_list,
            #     "Disk content (µg)": ["" for _ in antibiotic_list],
            #     "Zone diameter (mm)": ["" for _ in antibiotic_list],
            #     "MIC (mg/L)": ["" for _ in antibiotic_list],
            #     "Reported result (S/I/R)": ["" for _ in antibiotic_list],
            #     "Method": ["" for _ in antibiotic_list],
            #     "Guideline": ["" for _ in antibiotic_list],
            # })
            # ast_df = st.data_editor(ast_df, num_rows="fixed", key=f"ast_table_{i}")
            # sdat["ast_table"] = ast_df.to_dict(orient="records")
            # sdat["ast_comments"] = st.text_area("Comments (AST)", value=sdat.get("ast_comments",""), key=f"sid_ast_comments_{i}")

            st.markdown("#### Diphtheria toxin testing")
            c1, c2, c3 = st.columns(3)
            sdat["pcr_result"] = c1.selectbox("PCR result", ["", "Positive", "Negative", "Not done"], index=["","Positive","Negative","Not done"].index(sdat.get("pcr_result","")) if sdat.get("pcr_result","") in ["","Positive","Negative","Not done"] else 0, key=f"sid_pcrres_{i}")
            sdat["pcr_protocol"] = c2.text_input("PCR protocol", value=sdat.get("pcr_protocol",""), key=f"sid_pcrprot_{i}")
            sdat["elek_result"] = c3.selectbox("Elek test result", ["", "Positive", "Negative", "Not done"], index=["","Positive","Negative","Not done"].index(sdat.get("elek_result","")) if sdat.get("elek_result","") in ["","Positive","Negative","Not done"] else 0, key=f"sid_elekres_{i}")
            sdat["elek_protocol"] = st.text_input("Elek test protocol", value=sdat.get("elek_protocol",""), key=f"sid_elekprot_{i}")
            sdat["additional_tests"] = st.text_area("Additional tests (e.g. lateral flow immuno assays, others)", value=sdat.get("additional_tests",""), key=f"sid_addtests_{i}")
            sdat["toxin_comments"] = st.text_area("Comments (Toxin)", value=sdat.get("toxin_comments",""), key=f"sid_toxcomm_{i}")

                        # ---- Genomics / WGS (order matches Excel) ----
            st.markdown("#### Genomics / WGS")

            # Row 1: Sequencing Method / Technology / library method
            c1, c2, c3 = st.columns(3)
            with c1:
                sdat["Sequencing Method"] = st.selectbox(
                    "Sequencing Method",
                    ["", "short read", "long read"],
                    index=(["", "short read", "long read"].index(sdat.get("Sequencing Method", ""))
                           if sdat.get("Sequencing Method", "") in ["", "short read", "long read"] else 0),
                    key=f"sid_seqm_{i}",
                )
            with c2:
                sdat["Technology"] = st.selectbox(
                    "Technology",
                    ["", "Illumina", "Oxford Nanopore", "PacBio", "MGI", "other"],
                    index=(["", "Illumina", "Oxford Nanopore", "PacBio", "MGI", "other"].index(sdat.get("Technology", ""))
                           if sdat.get("Technology", "") in ["", "Illumina", "Oxford Nanopore", "PacBio", "MGI", "other"] else 0),
                    key=f"sid_tech_{i}",
                )
            with c3:
                sdat["library method"] = st.text_input(
                    "library method",
                    value=sdat.get("library method", ""),
                    key=f"sid_lib_{i}",
                )

            # Row 2: (median) read length / mean depth / Species identified
            c4, c5, c6 = st.columns(3)
            with c4:
                sdat["(median) read length"] = st.text_input(
                    "(median) read length",
                    value=sdat.get("(median) read length", ""),
                    key=f"sid_readlen_{i}",
                )
            with c5:
                sdat["mean read depth"] = st.text_input(
                    "mean read depth",
                    value=sdat.get("mean read depth", ""),
                    key=f"sid_depth_{i}",
                )
            with c6:
                sdat["Species identified"] = st.text_input(
                    "Species identified",
                    value=sdat.get("Species identified", ""),
                    key=f"sid_speciesid_{i}",
                )

            # Row 3: Method of species ID / MLST/Sequence Type / Genome Comparison Method
            c7, c8, c9 = st.columns(3)
            with c7:
                sdat["Method of species ID"] = st.text_input(
                    "Method of species ID",
                    value=sdat.get("Method of species ID", ""),
                    key=f"sid_idmethod_{i}",
                )
            with c8:
                sdat["MLST/Sequence Type"] = st.text_input(
                    "MLST/Sequence Type",
                    value=sdat.get("MLST/Sequence Type", ""),
                    key=f"sid_mlst_{i}",
                )
            with c9:
                sdat["Genome Comparison Method"] = st.selectbox(
                    "Genome Comparison Method",
                    ["", "SNP phylogeny", "cgMLST", "kmer", "other"],
                    index=(["", "SNP phylogeny", "cgMLST", "kmer", "other"].index(sdat.get("Genome Comparison Method", ""))
                           if sdat.get("Genome Comparison Method", "") in ["", "SNP phylogeny", "cgMLST", "kmer", "other"] else 0),
                    key=f"sid_comp_{i}",
                )

            # Row 4: Relevant software / Closest related isolate / distance to closest related isolate (with units!)
            c10, c11, c12 = st.columns(3)
            with c10:
                sdat["Relevant software"] = st.text_input(
                    "Relevant software",
                    value=sdat.get("Relevant software", ""),
                    key=f"sid_sw_{i}",
                )
            with c11:
                sdat["Closest related isolate"] = st.text_input(
                    "Closest related isolate",
                    value=sdat.get("Closest related isolate", ""),
                    key=f"sid_closest_{i}",
                )
            with c12:
                sdat["distance to closest related isolate (with units!)"] = st.text_input(
                    "distance to closest related isolate (with units!)",
                    value=sdat.get("distance to closest related isolate (with units!)", ""),
                    key=f"sid_distance_{i}",
                )

            # Row 5: AMR detected genes (textarea) / AMR detection method / AMR database
            c13, c14, c15 = st.columns(3)
            with c13:
                sdat["Detected AMR genes"] = st.text_area(
                    "Detected AMR geness",
                    value=sdat.get("Detected AMR genes", ""),
                    key=f"sid_amrgenes_{i}",
                )
            with c14:
                sdat["AMR gene detection method"] = st.text_input(
                    "AMR gene detection method",
                    value=sdat.get("AMR gene detection method", ""),
                    key=f"sid_amrmethod_{i}",
                )
            with c15:
                sdat["AMR database"] = st.text_input(
                    "AMR database",
                    value=sdat.get("AMR database", ""),
                    key=f"sid_amrdb_{i}",
                )

            # Row 6: DT detected / DT detection method / Comments
            c16, c17 = st.columns([1, 2])
            with c16:
                sdat["DT detected"] = st.selectbox(
                    "DT detected",
                    ["", "Yes", "No"],
                    index=(["", "Yes", "No"].index(sdat.get("DT detected", ""))
                           if sdat.get("DT detected", "") in ["", "Yes", "No"] else 0),
                    key=f"sid_dt_{i}",
                )
                sdat["DT detection method"] = st.text_input(
                    "DT detection method",
                    value=sdat.get("DT detection method", ""),
                    key=f"sid_dtmethod_{i}",
                )
            with c17:
                sdat["wgs_comments"] = st.text_area(
                    "Comments (WGS)",
                    value=sdat.get("wgs_comments", ""),
                    key=f"geno_comments_{i}",
                )
            # ---- End Genomics / WGS ----




            data["samples"][sid] = sdat

    st.markdown("---")
    st.subheader("Survey — Needs related to lab capacity")
    needs = data.get("needs", {})
    for need in ['supply of selective media', 'DT-PCR capacity', 'supply of Elek basal medium', 'supply of diphtheria antitoxin', 'availability of a rapid toxin test', 'antibiotic resistance testing', 'supply of reference material °', 'sequencing capacity', 'EQA distribution', 'laboratory training workshop']:
        needs[need] = st.slider(need, min_value=1, max_value=5, value=int(needs.get(need,3)))
    needs["reference_material"] = st.text_area("°If interested, what reference material would you be interested in?", value=needs.get("reference_material",""))
    needs["other_notes"] = st.text_area("Additional notes / requests", value=needs.get("other_notes",""))
    data["needs"] = needs

    csave, csubmit = st.columns([1,1])
    if csave.button("💾 Save draft"):
        save_json(data, draft_path)
        st.success("Draft saved. You can come back and continue later.")
    if csubmit.button("✅ Final submit"):
        data["submitted_at"] = dt.datetime.utcnow().isoformat() + "Z"
        save_json(data, draft_path)
        st.success("Submission saved. Thank you!")

if page == "Account settings":
    st.header("Account settings")
    st.write(f"Logged in as **{user}**.")
    account = get_user(user)
    if not account:
        st.error("Unable to load your account details.")
    else:
        with st.expander("Authenticator setup (TOTP)", expanded=False):
            st.write(
                "Scan the QR code below or enter the secret manually in Google Authenticator, Microsoft Authenticator, or any TOTP-compatible app."
            )
            provisioning_uri = pyotp.TOTP(account["totp_secret"]).provisioning_uri(
                name=account["username"], issuer_name="Diphtheria EQA Portal"
            )
            qr_img = qrcode.make(provisioning_uri)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            buf.seek(0)
            st.image(buf, caption="Authenticator QR code", use_column_width=False)
            st.write("Manual secret:")
            st.code(account["totp_secret"])
            st.write("Provisioning URI:")
            st.code(provisioning_uri)
        st.markdown("---")
        st.subheader("Change password")
        with st.form("change_password_form"):
            current_password = st.text_input("Current password", type="password")
            new_password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            submitted = st.form_submit_button("Update password")
        if submitted:
            if not current_password or not new_password or not confirm_password:
                st.error("All password fields are required.")
            elif not verify_password(current_password, account["password_hash"]):
                st.error("Current password is incorrect.")
            elif new_password != confirm_password:
                st.error("New password entries do not match.")
            elif len(new_password) < 10:
                st.error("Password must be at least 10 characters.")
            elif verify_password(new_password, account["password_hash"]):
                st.error("New password must be different from the current password.")
            else:
                update_password(account["username"], new_password)
                st.session_state.auth["must_change_password"] = False
                st.success("Password updated successfully.")
                # Refresh local details so subsequent operations see the updated hash
                account = get_user(user)

# ---------- Admin download ----------
if page == "Download (admin)" and is_admin:
    st.header("Admin — Download Submissions")
    files = sorted(SUBMIT_DIR.glob("*.json"))
    st.write(f"Found **{len(files)}** submissions.")
    if not files:
        st.stop()

    # Aggregate into flat tables
    lab_rows, id_rows, ast_rows, toxin_rows, gen_rows, need_rows = [], [], [], [], [], []

    for fp in files:
        obj = json.load(open(fp, "r", encoding="utf-8"))
        lab = Path(fp).stem
        li = obj.get("lab_info", {})
        lab_rows.append({"lab": lab, **li, "submitted_at": obj.get("submitted_at")})
        # needs
        n = obj.get("needs", {}).copy()
        other = n.pop("other_notes", "")
        for k,v in n.items():
            need_rows.append({"lab": lab, "need": k, "rating": v})
        if other:
            need_rows.append({"lab": lab, "need": "other_notes", "rating": "", "text": other})
        # per sample
        for sid, sdat in obj.get("samples", {}).items():
            id_rows.append({"lab": lab, "sample": sid, "species_identified": sdat.get("species_identified",""), "id_method": sdat.get("id_method",""), "company": sdat.get("company",""), "id_comments": sdat.get("id_comments","")})
            # AST rows per antibiotic
            for rec in sdat.get("ast_table", []):
                row = {"lab": lab, "sample": sid}
                row.update(rec)
                ast_rows.append(row)
            toxin_rows.append({
                "lab": lab, "sample": sid, "pcr_result": sdat.get("pcr_result",""), "pcr_protocol": sdat.get("pcr_protocol",""),
                "elek_result": sdat.get("elek_result",""), "elek_protocol": sdat.get("elek_protocol",""),
                "additional_tests": sdat.get("additional_tests",""), "toxin_comments": sdat.get("toxin_comments","")
            })
            gen_rows.append({
                "lab": lab, "sample": sid, "seq_method": sdat.get("seq_method",""), "platform": sdat.get("platform",""),
                "read_length": sdat.get("read_length",""), "comparison_method": sdat.get("comparison_method",""),
                "sequence_type": sdat.get("sequence_type",""), "closest_rel": sdat.get("closest_rel",""),
                "amr_genes": sdat.get("amr_genes",""), "dt_detected": sdat.get("dt_detected",""),
                "genomics_comments": sdat.get("genomics_comments","")
            })

    dfs = {
        "labs.csv": pd.DataFrame(lab_rows),
        "id_results.csv": pd.DataFrame(id_rows),
        "ast_results.csv": pd.DataFrame(ast_rows),
        "toxin_results.csv": pd.DataFrame(toxin_rows),
        "genomics_results.csv": pd.DataFrame(gen_rows),
        "needs_results.csv": pd.DataFrame(need_rows),
    }

    for name, df in dfs.items():
        st.download_button(f"Download {name}", data=df.to_csv(index=False).encode("utf-8"), file_name=name, mime="text/csv")
        st.dataframe(df, use_container_width=True)
