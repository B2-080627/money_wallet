# Friendly Games Wallet

Streamlit app for sending and receiving **virtual** rupees during friendly games (poker etc.).
Every new player starts with ₹1,00,000. Players can delete their own account from the sidebar
(PIN + confirmation).

All data (players, balances, transactions) is stored in a **Turso** database, so nothing is lost
when the app restarts or is redeployed, and every payment is a single atomic database
transaction (no double-spend, no negative balances, even if several people pay at once).

## Set up Turso (one time, ~3 minutes)

```bash
# install the CLI: https://docs.turso.tech/cli/installation
turso auth signup                      # or: turso auth login
turso db create friendly-wallet
turso db show friendly-wallet --url    # -> libsql://friendly-wallet-<org>.turso.io
turso db tokens create friendly-wallet # -> the auth token
```

(You can also create the database and token from the Turso dashboard.)

Then put both values in `.streamlit/secrets.toml` — or, on Streamlit Community Cloud,
in **App settings → Secrets**:

```toml
TURSO_DATABASE_URL = "libsql://friendly-wallet-<org>.turso.io"
TURSO_AUTH_TOKEN   = "eyJ..."
```

Environment variables with the same names also work. The tables are created automatically on first start.

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

If no Turso settings are found, the app uses a local file (`wallet.db`) so you can try it out.
The sidebar shows which database is in use. Local files are **not** permanent on cloud hosts,
so use Turso for real games.

## Notes

- PINs are salted + hashed (PBKDF2), never stored in plain text.
- Deleting an account removes the player and their balance. Their past payments remain in other
  players' histories as "Name (deleted)", and the name becomes available again.
- Money is virtual only; the app is meant for friendly games among friends.
- Data from the earlier Google Drive version isn't migrated; players re-join with the new balance.
