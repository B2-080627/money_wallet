"""Friendly Games Wallet - send/receive virtual rupees for poker nights and friendly games.

* Every player starts with Rs 1,00,000.
* All balances and transactions live in a Turso (libSQL) database, so nothing is lost when the
  app restarts or redeploys, and every transfer is one atomic database transaction.
* Without Turso credentials the app falls back to a local file (wallet.db) for development.
"""
import hashlib
import hmac
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone

import pandas as pd
import streamlit as st

START_BALANCE = 100000
LOCAL_DB = "wallet.db"
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


def setting(name):
    """Read a setting from Streamlit secrets, then environment variables."""
    try:
        if name in st.secrets:
            return str(st.secrets[name])
    except Exception:
        pass
    return os.environ.get(name)


# --------------------------------------------------------------------- Database
class TxAbort(Exception):
    """Raised inside a transaction for an expected failure (e.g. not enough balance)."""


def _fatal(e: BaseException) -> bool:
    """The native libSQL driver can surface a broken connection as a non-Exception panic,
    so database calls catch BaseException — except real interpreter-exit signals."""
    return isinstance(e, (KeyboardInterrupt, SystemExit, GeneratorExit))


SCHEMA = [
    """CREATE TABLE IF NOT EXISTS users (
        key      TEXT PRIMARY KEY,
        name     TEXT NOT NULL,
        salt     TEXT NOT NULL,
        pin_hash TEXT NOT NULL,
        balance  INTEGER NOT NULL CHECK (balance >= 0),
        joined   TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS transactions (
        seq       INTEGER PRIMARY KEY AUTOINCREMENT,
        time      TEXT NOT NULL,
        from_key  TEXT,
        from_name TEXT NOT NULL,
        to_key    TEXT,
        to_name   TEXT NOT NULL,
        amount    INTEGER NOT NULL CHECK (amount > 0),
        note      TEXT NOT NULL DEFAULT ''
    )""",
    "CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_key)",
    "CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_key)",
]


class Db:
    """One shared connection, guarded by a lock, that reconnects if Turso drops it."""

    def __init__(self):
        self.lock = threading.RLock()
        self.url = setting("TURSO_DATABASE_URL")
        self.token = setting("TURSO_AUTH_TOKEN")
        self.remote = bool(self.url)
        self.conn = None
        self._connect()
        with self.lock:
            for stmt in SCHEMA:
                self.conn.execute(stmt)
            self.conn.commit()

    def _connect(self):
        import libsql

        if self.remote:
            self.conn = libsql.connect(database=self.url, auth_token=self.token or "")
        else:
            self.conn = libsql.connect(LOCAL_DB)

    def _reconnect(self):
        try:
            self.conn.close()
        except BaseException as e:
            if _fatal(e):
                raise
        self._connect()

    def _rollback(self):
        try:
            self.conn.rollback()
        except BaseException as e:
            if _fatal(e):
                raise

    def read(self, sql, params=()):
        with self.lock:
            for attempt in (0, 1):
                try:
                    return self.conn.execute(sql, params).fetchall()
                except BaseException as e:
                    if _fatal(e) or attempt:
                        raise
                    self._reconnect()

    def tx(self, fn):
        """Run fn(conn) and commit. A dropped connection is retried once, but only if it
        failed *before* the commit, so a payment can never be applied twice."""
        with self.lock:
            for attempt in (0, 1):
                stage = "work"
                try:
                    result = fn(self.conn)
                    stage = "commit"
                    self.conn.commit()
                    return result
                except TxAbort:
                    self._rollback()
                    raise
                except BaseException as e:
                    if _fatal(e):
                        raise
                    self._rollback()
                    if stage == "commit" or attempt:
                        raise
                    self._reconnect()

    @property
    def label(self):
        if not self.remote:
            return f"Local file ({LOCAL_DB}) — set Turso secrets for permanent storage"
        host = re.sub(r"^\w+://", "", self.url).split("/")[0]
        return f"Turso · {host}"


@st.cache_resource
def get_db() -> Db:
    return Db()


try:
    db = get_db()
except Exception as e:
    st.error(f"Could not connect to the database: {e}")
    st.info("Check `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` in your Streamlit secrets "
            "(see README), and that the `libsql` package is installed.")
    st.stop()


# ------------------------------------------------------------------ Wallet logic
def _hash(pin: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), 120_000).hex()


def register(name: str, pin: str):
    name = " ".join(name.split())
    key = name.lower()
    if not (2 <= len(name) <= 24):
        return False, "Name must be 2–24 characters."
    if not (pin.isdigit() and 4 <= len(pin) <= 8):
        return False, "PIN must be 4–8 digits."
    salt = secrets.token_hex(16)
    pin_hash = _hash(pin, salt)

    def work(c):
        if c.execute("SELECT 1 FROM users WHERE key = ?", (key,)).fetchone():
            raise TxAbort("That name is already taken.")
        c.execute("INSERT INTO users (key, name, salt, pin_hash, balance, joined) VALUES (?,?,?,?,?,?)",
                  (key, name, salt, pin_hash, START_BALANCE, now_str()))
        c.execute("INSERT INTO transactions (time, from_key, from_name, to_key, to_name, amount, note) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (now_str(), None, "BANK", key, name, START_BALANCE, "Starting balance"))

    try:
        db.tx(work)
    except TxAbort as e:
        return False, str(e)
    return True, key


def login(name: str, pin: str):
    key = " ".join(name.split()).lower()
    rows = db.read("SELECT salt, pin_hash FROM users WHERE key = ?", (key,))
    if not rows or not hmac.compare_digest(rows[0][1], _hash(pin, rows[0][0])):
        return False, "Wrong name or PIN."
    return True, key


def get_user(key: str):
    rows = db.read("SELECT name, balance FROM users WHERE key = ?", (key,))
    return {"name": rows[0][0], "balance": rows[0][1]} if rows else None


def transfer(from_key: str, to_key: str, amount: int, note: str):
    if amount <= 0:
        return False, "Amount must be more than ₹0."
    if from_key == to_key:
        return False, "You can't send money to yourself."

    def work(c):
        s = c.execute("SELECT name FROM users WHERE key = ?", (from_key,)).fetchone()
        r = c.execute("SELECT name FROM users WHERE key = ?", (to_key,)).fetchone()
        if not s:
            raise TxAbort("Your account no longer exists.")
        if not r:
            raise TxAbort("Recipient not found.")
        # Conditional debit: succeeds only if the balance is enough, atomically
        c.execute("UPDATE users SET balance = balance - ? WHERE key = ? AND balance >= ?",
                  (amount, from_key, amount))
        if c.execute("SELECT changes()").fetchone()[0] != 1:
            raise TxAbort("Not enough balance.")
        c.execute("UPDATE users SET balance = balance + ? WHERE key = ?", (amount, to_key))
        c.execute("INSERT INTO transactions (time, from_key, from_name, to_key, to_name, amount, note) "
                  "VALUES (?,?,?,?,?,?,?)",
                  (now_str(), from_key, s[0], to_key, r[0], amount, note.strip()[:80]))
        return r[0]

    try:
        to_name = db.tx(work)
    except TxAbort as e:
        return False, str(e)
    return True, f"Sent {inr(amount)} to {to_name}."


def delete_account(key: str, pin: str):
    """Permanently remove a player. Their balance leaves the game with them."""
    ok, _ = login(key, pin)
    if not ok:
        return False, "Wrong PIN."

    def work(c):
        row = c.execute("SELECT name FROM users WHERE key = ?", (key,)).fetchone()
        if not row:
            raise TxAbort("Account not found.")
        # starting-balance entry disappears with the account
        c.execute("DELETE FROM transactions WHERE from_name = 'BANK' AND to_key = ?", (key,))
        # keep payments in other players' histories, but free the name for reuse
        c.execute("UPDATE transactions SET from_name = from_name || ' (deleted)', from_key = NULL "
                  "WHERE from_key = ?", (key,))
        c.execute("UPDATE transactions SET to_name = to_name || ' (deleted)', to_key = NULL "
                  "WHERE to_key = ?", (key,))
        c.execute("DELETE FROM users WHERE key = ?", (key,))
        return row[0]

    try:
        name = db.tx(work)
    except TxAbort as e:
        return False, str(e)
    return True, f"Account '{name}' deleted."


def history(key: str):
    return db.read("SELECT time, from_key, from_name, to_name, amount, note FROM transactions "
                   "WHERE from_key = ? OR to_key = ? ORDER BY seq DESC LIMIT 200", (key, key))


def leaderboard():
    return db.read("SELECT name, balance FROM users ORDER BY balance DESC, name")


def other_players(key: str):
    return {n: k for k, n in db.read("SELECT key, name FROM users WHERE key != ? ORDER BY name", (key,))}


# --------------------------------------------------------------------- Sidebar
st.title("🃏 Friendly Games Wallet")
st.caption("Virtual rupees for poker nights & friendly games — no real money involved.")

with st.sidebar:
    st.header("Account")
    if "user" in st.session_state and get_user(st.session_state.user) is None:
        del st.session_state["user"]  # account was deleted elsewhere

    if "user" not in st.session_state:
        tab_login, tab_join = st.tabs(["Log in", "Join"])
        with tab_login:
            n = st.text_input("Name", key="li_name")
            p = st.text_input("PIN", type="password", key="li_pin")
            if st.button("Log in", use_container_width=True):
                ok, res = login(n, p)
                if ok:
                    st.session_state.user = res
                    st.rerun()
                else:
                    st.error(res)
        with tab_join:
            n2 = st.text_input("Pick a name", key="jn_name")
            p2 = st.text_input("Choose a 4–8 digit PIN", type="password", key="jn_pin")
            if st.button(f"Join with {inr(START_BALANCE)}", use_container_width=True):
                ok, res = register(n2, p2)
                if ok:
                    st.session_state.user = res
                    st.rerun()
                else:
                    st.error(res)
    else:
        me = get_user(st.session_state.user)
        st.success(f"Logged in as **{me['name']}**")
        if st.button("Log out", use_container_width=True):
            del st.session_state["user"]
            st.rerun()

        with st.expander("🗑️ Delete my account"):
            st.warning(f"This permanently removes your account and your balance ({inr(me['balance'])}). "
                       "It can't be undone.")
            del_pin = st.text_input("Enter your PIN to confirm", type="password", key="del_pin")
            del_ok = st.checkbox("Yes, delete my account for good", key="del_ok")
            if st.button("Delete account", type="primary", disabled=not del_ok, use_container_width=True):
                ok, msg = delete_account(st.session_state.user, del_pin)
                if not ok:
                    st.error(msg)
                else:
                    st.session_state.pop("user", None)
                    st.session_state.flash = msg
                    st.rerun()

    st.divider()
    st.subheader("🗄️ Database")
    (st.success if db.remote else st.warning)(db.label)

# ------------------------------------------------------------------------- Main
if "flash" in st.session_state:
    st.success(st.session_state.pop("flash"))

if "user" not in st.session_state:
    st.info(f"Log in or join from the sidebar to start playing. Everyone begins with **{inr(START_BALANCE)}**.")
else:
    key = st.session_state.user
    me = get_user(key)
    st.metric("Your balance", inr(me["balance"]))

    st.subheader("Send money")
    others = other_players(key)
    if not others:
        st.info("No other players yet — ask your friends to join!")
    else:
        with st.form("send", clear_on_submit=True):
            to_name = st.selectbox("Send to", list(others))
            amount = st.number_input("Amount (₹)", min_value=1, max_value=max(1, me["balance"]),
                                     value=min(100, max(1, me["balance"])), step=50)
            note = st.text_input("Note (optional)", placeholder="e.g. Poker round 3")
            if st.form_submit_button("Send", type="primary", use_container_width=True):
                ok, msg = transfer(key, others[to_name], int(amount), note)
                if ok:
                    st.toast(msg, icon="✅")
                    st.rerun()
                else:
                    st.error(msg)

    st.subheader("Your transactions")
    rows = []
    for t, from_key, from_name, to_name_, amt, note_ in history(key):
        sent = from_key == key
        rows.append({"Time": t, "Type": "Sent" if sent else "Received",
                     "With": to_name_ if sent else from_name,
                     "Amount": -amt if sent else amt, "Note": note_})
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

st.subheader("🏆 Leaderboard")
board = leaderboard()
if board:
    st.dataframe(pd.DataFrame([{"Rank": i + 1, "Player": n, "Balance": b} for i, (n, b) in enumerate(board)]),
                 hide_index=True, use_container_width=True)
else:
    st.caption("No players yet.")

if st.button("🔄 Refresh"):
    st.rerun()
