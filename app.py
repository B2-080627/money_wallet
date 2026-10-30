"""Friendly Games Wallet - send/receive virtual rupees for poker nights and friendly games.

* Every player starts with Rs 10,000.
* One shared ledger (on the app server) keeps everyone's balance so money can move between players.
* Each player's OWN balance + transactions are backed up to THEIR OWN Google Drive
  (Sign in with Google -> file is created in the player's My Drive).
* Backups are signed, so a player can't edit the file to give themselves more money.
* A no-Google fallback lets players download / upload their backup file manually.
"""
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import threading
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

START_BALANCE = 100000
DATA_FILE = "wallet_data.json"
BACKUP_NAME = "friendly_games_wallet_backup.json"
SCOPES = ["https://www.googleapis.com/auth/drive.file"]  # only files this app creates
IST = timezone(timedelta(hours=5, minutes=30))

st.set_page_config(page_title="Friendly Games Wallet", page_icon="🃏", layout="centered")


def now_str() -> str:
    return datetime.now(IST).strftime("%d %b %Y, %I:%M:%S %p")


def inr(x: int) -> str:
    """Format with Indian digit grouping, e.g. 100000 -> ₹1,00,000."""
    s = str(abs(int(x)))
    if len(s) > 3:
        s = re.sub(r"(\d)(?=(\d\d)+$)", r"\1,", s[:-3]) + "," + s[-3:]
    return ("-" if x < 0 else "") + "₹" + s


def secret(path, default=None):
    """Safe read from st.secrets (works even if no secrets file exists)."""
    try:
        cur = st.secrets
        for p in path.split("."):
            cur = cur[p]
        return cur
    except Exception:
        return default


# ------------------------------------------------------------------------ Store
class Store:
    """Shared, thread-safe ledger (one instance for all browser sessions)."""

    def __init__(self):
        self.lock = threading.RLock()
        self.data = {"secret": secrets.token_hex(32), "users": {}, "transactions": []}
        self._load_local()
        self._save_local()

    # -- local persistence
    def _load_local(self):
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, encoding="utf-8") as f:
                    loaded = json.load(f)
                self.data.update(loaded)
            except Exception:
                pass

    def _save_local(self):
        tmp = DATA_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, DATA_FILE)

    # -- signed personal backups
    def _key(self) -> bytes:
        # Set `backup_secret` in Streamlit secrets so backups stay valid even if the server is wiped.
        return str(secret("backup_secret") or self.data["secret"]).encode()

    def _sign(self, payload: dict) -> str:
        msg = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._key(), msg, hashlib.sha256).hexdigest()

    def make_backup(self, key: str) -> dict:
        with self.lock:
            u = dict(self.data["users"][key])
            txs = [t for t in self.data["transactions"] if t["from"] == u["name"] or t["to"] == u["name"]]
        payload = {"app": "friendly-games-wallet", "saved_at": now_str(), "uv": u.get("uv", 0),
                   "user": u, "transactions": txs}
        return {"payload": payload, "sig": self._sign(payload)}

    def read_backup(self, blob):
        """Return payload if the signature is valid, else None."""
        try:
            payload, sig = blob["payload"], blob["sig"]
            if hmac.compare_digest(sig, self._sign(payload)) and payload.get("app") == "friendly-games-wallet":
                return payload
        except Exception:
            pass
        return None

    def needs_restore(self, payload) -> bool:
        key = payload["user"]["name"].lower()
        cur = self.data["users"].get(key)
        # An account the player deleted can't be brought back by an old backup file
        if cur is None and payload.get("uv", 0) <= self.data.get("deleted", {}).get(key, -1):
            return False
        return cur is None or payload.get("uv", 0) > cur.get("uv", 0)

    def delete_account(self, key: str, pin: str):
        """Permanently remove a player. Their balance leaves the game with them."""
        ok, _ = self.login(key, pin)
        if not ok:
            return False, "Wrong PIN."
        with self.lock:
            u = self.data["users"].pop(key)
            self.data.setdefault("deleted", {})[key] = u.get("uv", 0)
            name = u["name"]
            kept = []
            for t in self.data["transactions"]:
                if t["from"] == "BANK" and t["to"] == name:
                    continue  # starting-balance entry disappears with the account
                # keep payments in other players' histories, but free the name for reuse
                if t["from"] == name:
                    t = dict(t, **{"from": f"{name} (deleted)"})
                if t["to"] == name:
                    t = dict(t, to=f"{name} (deleted)")
                kept.append(t)
            self.data["transactions"] = kept
            self._save_local()
        return True, f"Account '{name}' deleted."

    def restore(self, payload):
        with self.lock:
            if not self.needs_restore(payload):
                return False, "The app already has your latest balance."
            u = payload["user"]
            self.data["users"][u["name"].lower()] = u
            have = {t["id"] for t in self.data["transactions"]}
            self.data["transactions"].extend(t for t in payload["transactions"] if t["id"] not in have)
            self._save_local()
        return True, f"Restored {u['name']} with {inr(u['balance'])}."

    # -- auth
    @staticmethod
    def _hash(pin: str, salt: str) -> str:
        return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 120_000).hex()

    def register(self, name: str, pin: str):
        name = " ".join(name.split())
        key = name.lower()
        if not (2 <= len(name) <= 24):
            return False, "Name must be 2–24 characters."
        if not (pin.isdigit() and 4 <= len(pin) <= 8):
            return False, "PIN must be 4–8 digits."
        with self.lock:
            if key in self.data["users"]:
                return False, "That name is already taken."
            salt = secrets.token_hex(16)
            self.data["users"][key] = {
                "name": name, "salt": salt, "pin_hash": self._hash(pin, salt),
                "balance": START_BALANCE, "joined": now_str(), "uv": 1,
            }
            self.data["transactions"].append(
                {"id": uuid.uuid4().hex[:8], "time": now_str(), "from": "BANK", "to": name,
                 "amount": START_BALANCE, "note": "Starting balance"}
            )
            self._save_local()
        return True, key

    def login(self, name: str, pin: str):
        key = " ".join(name.split()).lower()
        with self.lock:
            u = self.data["users"].get(key)
            if not u or not hmac.compare_digest(u["pin_hash"], self._hash(pin, u["salt"])):
                return False, "Wrong name or PIN."
        return True, key

    # -- money
    def transfer(self, from_key: str, to_key: str, amount: int, note: str):
        if amount <= 0:
            return False, "Amount must be more than ₹0."
        if from_key == to_key:
            return False, "You can't send money to yourself."
        with self.lock:
            users = self.data["users"]
            if to_key not in users:
                return False, "Recipient not found."
            if users[from_key]["balance"] < amount:
                return False, "Not enough balance."
            users[from_key]["balance"] -= amount
            users[to_key]["balance"] += amount
            users[from_key]["uv"] = users[from_key].get("uv", 0) + 1
            users[to_key]["uv"] = users[to_key].get("uv", 0) + 1
            self.data["transactions"].append(
                {"id": uuid.uuid4().hex[:8], "time": now_str(), "from": users[from_key]["name"],
                 "to": users[to_key]["name"], "amount": amount, "note": note.strip()[:80]}
            )
            self._save_local()
        return True, f"Sent {inr(amount)} to {users[to_key]['name']}."


@st.cache_resource
def get_store() -> Store:
    return Store()


store = get_store()

# ------------------------------------------------------ Google sign-in (per player)
def oauth_cfg():
    cid, sec, redir = secret("google_oauth.client_id"), secret("google_oauth.client_secret"), secret("google_oauth.redirect_uri")
    return (cid, sec, redir) if cid and sec and redir else None


def make_flow():
    from google_auth_oauthlib.flow import Flow

    cid, sec, redir = oauth_cfg()
    if redir.startswith("http://localhost"):
        os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
    cfg = {"web": {"client_id": cid, "client_secret": sec,
                   "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                   "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": [redir]}}
    return Flow.from_client_config(cfg, scopes=SCOPES, redirect_uri=redir, autogenerate_code_verifier=False)


def drive_svc():
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    return build("drive", "v3", credentials=Credentials(**st.session_state.gcreds), cache_discovery=False)


def drive_find(svc):
    res = svc.files().list(q=f"name='{BACKUP_NAME}' and trashed=false", spaces="drive",
                           fields="files(id)", orderBy="modifiedTime desc").execute()
    files = res.get("files", [])
    return files[0]["id"] if files else None


def drive_download(svc):
    from googleapiclient.http import MediaIoBaseDownload

    fid = drive_find(svc)
    if not fid:
        return None
    buf = io.BytesIO()
    dl = MediaIoBaseDownload(buf, svc.files().get_media(fileId=fid))
    done = False
    while not done:
        _, done = dl.next_chunk()
    raw = buf.getvalue().decode("utf-8").strip()
    return json.loads(raw) if raw else None


def drive_delete(svc):
    fid = drive_find(svc)
    while fid:
        svc.files().delete(fileId=fid).execute()
        fid = drive_find(svc)


def drive_upload(svc, blob):
    from googleapiclient.http import MediaIoBaseUpload

    media = MediaIoBaseUpload(io.BytesIO(json.dumps(blob, indent=2).encode()), mimetype="application/json")
    fid = drive_find(svc)
    if fid:
        svc.files().update(fileId=fid, media_body=media).execute()
    else:
        svc.files().create(body={"name": BACKUP_NAME}, media_body=media, fields="id").execute()


# Handle the redirect back from Google ( ?code=... )
if "code" in st.query_params and "gcreds" not in st.session_state and oauth_cfg():
    try:
        flow = make_flow()
        flow.fetch_token(code=st.query_params["code"])
        c = flow.credentials
        st.session_state.gcreds = {"token": c.token, "refresh_token": c.refresh_token,
                                   "token_uri": c.token_uri, "client_id": c.client_id,
                                   "client_secret": c.client_secret, "scopes": SCOPES}
        about = drive_svc().about().get(fields="user(emailAddress)").execute()
        st.session_state.gmail = about["user"]["emailAddress"]
    except Exception as e:
        st.session_state.pop("gcreds", None)
        st.session_state.drive_msg = ("err", f"Google sign-in failed: {e}")
    st.query_params.clear()
    st.rerun()

connected = "gcreds" in st.session_state

# --------------------------------------------------------------------- Sidebar
st.title("🃏 Friendly Games Wallet")
st.caption("Virtual rupees for poker nights & friendly games — no real money involved.")

with st.sidebar:
    st.header("1 · Your Google Drive")
    if connected:
        st.success(f"Connected: {st.session_state.get('gmail', 'Google account')}")
        if st.button("Disconnect", use_container_width=True):
            for k in ("gcreds", "gmail", "remote_blob", "synced_uv", "drive_msg", "remote_checked"):
                st.session_state.pop(k, None)
            st.rerun()
    elif oauth_cfg():
        url, _ = make_flow().authorization_url(access_type="offline", prompt="consent")
        st.markdown(f'<a href="{url}" target="_self" style="display:block;text-align:center;padding:.5rem;'
                    f'border:1px solid #888;border-radius:.5rem;text-decoration:none;">'
                    f'🔐 Sign in with Google</a>', unsafe_allow_html=True)
        st.caption("Connect **first**, then log in below. Your backup is saved in *your own* Drive.")
    else:
        st.info("Google sign-in isn't set up on this server yet. You can still use the manual backup below.")

    st.header("2 · Account")
    if "user" not in st.session_state:
        tab_login, tab_join = st.tabs(["Log in", "Join"])
        with tab_login:
            n = st.text_input("Name", key="li_name")
            p = st.text_input("PIN", type="password", key="li_pin")
            if st.button("Log in", use_container_width=True):
                ok, res = store.login(n, p)
                if ok:
                    st.session_state.user = res
                    st.rerun()
                else:
                    st.error(res)
        with tab_join:
            n2 = st.text_input("Pick a name", key="jn_name")
            p2 = st.text_input("Choose a 4–8 digit PIN", type="password", key="jn_pin")
            if st.button(f"Join with {inr(START_BALANCE)}", use_container_width=True):
                ok, res = store.register(n2, p2)
                if ok:
                    st.session_state.user = res
                    st.rerun()
                else:
                    st.error(res)
    else:
        me = store.data["users"][st.session_state.user]
        st.success(f"Logged in as **{me['name']}**")
        if st.button("Log out", use_container_width=True):
            del st.session_state["user"]
            st.session_state.pop("synced_uv", None)
            st.rerun()

        with st.expander("🗑️ Delete my account"):
            st.warning("This permanently removes your account and your balance "
                       f"({inr(me['balance'])}). It can't be undone."
                       + (" Your backup in Google Drive will be deleted too." if connected else ""))
            del_pin = st.text_input("Enter your PIN to confirm", type="password", key="del_pin")
            del_ok = st.checkbox("Yes, delete my account for good", key="del_ok")
            if st.button("Delete account", type="primary", disabled=not del_ok, use_container_width=True):
                ok, msg = store.delete_account(st.session_state.user, del_pin)
                if not ok:
                    st.error(msg)
                else:
                    note = ""
                    if connected:
                        try:
                            drive_delete(drive_svc())
                        except Exception as e:
                            note = f" (Could not remove the Drive backup file automatically: {e})"
                    for k in ("user", "synced_uv", "remote_blob", "remote_checked", "drive_msg"):
                        st.session_state.pop(k, None)
                    st.session_state.flash = msg + note
                    st.rerun()

# ---------------------------------------------------- Drive sync / restore logic
def drive_sync_logged_in(key):
    me = store.data["users"][key]
    try:
        svc = drive_svc()
        if not st.session_state.get("remote_checked"):
            st.session_state.remote_checked = True
            blob = drive_download(svc)
            payload = store.read_backup(blob) if blob else None
            if payload and payload["user"]["name"].lower() == key and store.needs_restore(payload):
                store.restore(payload)
                me = store.data["users"][key]
        if st.session_state.get("synced_uv") != me["uv"]:
            drive_upload(svc, store.make_backup(key))
            st.session_state.synced_uv = me["uv"]
            st.session_state.drive_msg = ("ok", f"Saved to your Drive · {inr(me['balance'])} · {now_str()}")
    except Exception as e:
        st.session_state.drive_msg = ("err", f"Drive backup failed: {e}")


def offer_restore_before_login():
    """Not logged in but Drive connected: look for the player's backup (e.g. after a server reset)."""
    try:
        if "remote_blob" not in st.session_state:
            st.session_state.remote_blob = drive_download(drive_svc())
        blob = st.session_state.remote_blob
        payload = store.read_backup(blob) if blob else None
        if blob and not payload:
            st.warning("Found a backup in your Drive but it failed the security check, so it can't be restored.")
        elif payload and store.needs_restore(payload):
            u = payload["user"]
            st.info(f"Found your backup in Google Drive: **{u['name']}** with **{inr(u['balance'])}**.")
            if st.button("♻️ Restore my account from Drive", type="primary"):
                ok, msg = store.restore(payload)
                st.session_state.pop("remote_blob", None)
                (st.success if ok else st.warning)(msg + " Now log in with your old PIN.")
        elif payload:
            st.success("Your Drive is connected and your account is up to date. Log in from the sidebar.")
        else:
            st.caption("No backup in your Drive yet — it will be created as soon as you join or log in.")
    except Exception as e:
        st.session_state.drive_msg = ("err", f"Could not read your Drive: {e}")


# ------------------------------------------------------------------------- Main
users = store.data["users"]
logged_in = "user" in st.session_state
if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

if logged_in and connected:
    drive_sync_logged_in(st.session_state.user)

if not logged_in:
    st.info(f"Connect Google Drive (optional but recommended), then log in or join. Everyone begins with **{inr(START_BALANCE)}**.")
    if connected:
        offer_restore_before_login()
else:
    key = st.session_state.user
    me = users[key]
    st.metric("Your balance", inr(me["balance"]))

    st.subheader("Send money")
    others = {u["name"]: k for k, u in users.items() if k != key}
    if not others:
        st.info("No other players yet — ask your friends to join!")
    else:
        with st.form("send", clear_on_submit=True):
            to_name = st.selectbox("Send to", sorted(others))
            amount = st.number_input("Amount (₹)", min_value=1, max_value=max(1, me["balance"]),
                                     value=min(100, max(1, me["balance"])), step=50)
            note = st.text_input("Note (optional)", placeholder="e.g. Poker round 3")
            if st.form_submit_button("Send", type="primary", use_container_width=True):
                ok, msg = store.transfer(key, others[to_name], int(amount), note)
                if ok:
                    st.toast(msg, icon="✅")
                    st.rerun()
                else:
                    st.error(msg)

    st.subheader("Your transactions")
    mine = [t for t in reversed(store.data["transactions"]) if t["from"] == me["name"] or t["to"] == me["name"]]
    if mine:
        rows = []
        for t in mine:
            sent = t["from"] == me["name"]
            rows.append({"Time": t["time"], "Type": "Sent" if sent else "Received",
                         "With": t["to"] if sent else t["from"],
                         "Amount": -t["amount"] if sent else t["amount"], "Note": t["note"]})
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

# Backup status panel
st.subheader("☁️ Backup")
msg = st.session_state.get("drive_msg")
if msg:
    (st.success if msg[0] == "ok" else st.error)(msg[1])
elif not connected:
    st.caption("Google Drive not connected — use the manual backup below, or connect from the sidebar.")
if logged_in and connected and st.button("Back up to my Drive now"):
    st.session_state.pop("synced_uv", None)
    st.rerun()

with st.expander("Manual backup (no Google needed)"):
    if logged_in:
        blob = store.make_backup(st.session_state.user)
        st.download_button("⬇️ Download my backup file", json.dumps(blob, indent=2),
                           file_name=BACKUP_NAME, mime="application/json")
        st.caption("Save this file anywhere — e.g. upload it to your Drive by hand.")
    up = st.file_uploader("Restore from a backup file", type="json")
    if up is not None and st.button("♻️ Restore from this file"):
        try:
            payload = store.read_backup(json.load(up))
            if not payload:
                st.error("That file failed the security check (edited, or from another app).")
            else:
                ok, m = store.restore(payload)
                (st.success if ok else st.warning)(m)
        except Exception as e:
            st.error(f"Couldn't read that file: {e}")

st.subheader("🏆 Leaderboard")
if users:
    board = sorted(users.values(), key=lambda u: u["balance"], reverse=True)
    st.dataframe(pd.DataFrame([{"Rank": i + 1, "Player": u["name"], "Balance": u["balance"]}
                               for i, u in enumerate(board)]), hide_index=True, use_container_width=True)
else:
    st.caption("No players yet.")

if st.button("🔄 Refresh"):
    st.rerun()
