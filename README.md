# Friendly Games Wallet

Streamlit app for sending and receiving **virtual** rupees during friendly games (poker etc.).
Every new player starts with ₹1,00,000. Players can delete their own account from the sidebar
(PIN + confirmation); this also removes their backup file from their Google Drive.

## How backup works (per player, in their own Google Drive)

- Players click **Sign in with Google**. The app creates `friendly_games_wallet_backup.json`
  in **that player's own My Drive** and keeps it updated with their latest balance + transactions.
  The app can only see files it created itself (`drive.file` scope), never the rest of their Drive.
- **On every login/startup** the app checks the player's Drive backup: if it is newer than what the
  server has (e.g. the host restarted and lost data) it offers to restore it, otherwise it uploads the latest amount.
- **After every transaction** the sender's Drive is updated immediately. A receiver's Drive is
  updated the next time they open the app.
- Backups are **signed** (HMAC), so editing the file to add money makes it invalid.
- **No-Google fallback:** "Manual backup" lets players download their signed backup file and restore it later.

## One-time setup by the app owner (players never touch Google Cloud)

Automatic saving into a person's own Drive needs Google's "Sign in with Google" (OAuth), which
requires one OAuth client ID. This is free and done once by whoever hosts the app:

1. https://console.cloud.google.com → create a project → **APIs & Services → Library** → enable **Google Drive API**.
2. **OAuth consent screen**: User type **External**, fill app name + your email, add scope
   `.../auth/drive.file`. Then click **Publish app** (otherwise only listed test users can sign in,
   and their sign-in expires after 7 days). `drive.file` is a non-sensitive scope, so no Google review is needed.
3. **Credentials → Create credentials → OAuth client ID → Web application**. Add your app URL as an
   **Authorized redirect URI** (e.g. `https://yourapp.streamlit.app/` or `http://localhost:8501/` for local runs).
4. Add to `.streamlit/secrets.toml` (or Streamlit Cloud → Settings → Secrets):

```toml
backup_secret = "any-long-random-string"   # keep this constant so old backups stay valid

[google_oauth]
client_id = "xxxx.apps.googleusercontent.com"
client_secret = "xxxx"
redirect_uri = "https://yourapp.streamlit.app/"   # must match step 3 exactly
```

Without the `[google_oauth]` block the app still works; players just use the manual backup file.

## Run

```bash
pip install -r requirements.txt
streamlit run app.py
```

## Notes

- Balances live in one shared ledger on the app server (needed so players can pay each other).
  Each player's Drive backup is what restores their money if the server is reset.
- PINs are salted + hashed (PBKDF2). Money is virtual only.
