# tracl

Honest study tracking. Tap to start, tap to stop.

## What's in here

```
server.js          — Node.js backend (Express + SQLite)
public/index.html  — Frontend (served by the backend)
tracl.db           — SQLite database (auto-created on first run)
```

## Run locally

```bash
npm install
npm start
```

Open http://localhost:3000 — that's it.

The database (`tracl.db`) is created automatically on first run. All your data lives there.

## API

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/signup | — | Create account |
| POST | /auth/login | — | Sign in |
| GET | /auth/me | ✓ | Validate token |
| POST | /sessions/start | ✓ | Start session, returns server timestamp |
| POST | /sessions/end | ✓ | End session, saves duration |
| GET | /sessions/today | ✓ | Today's sessions + active session |
| GET | /sessions/week | ✓ | Last 7 days |
| GET | /sessions/stats | ✓ | Streak, weekly total, avg session |

## Deploy to Railway (free, 5 minutes)

1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Select your repo
4. Railway auto-detects Node.js and runs `npm start`
5. Go to Settings → Variables → add:
   ```
   JWT_SECRET=any-long-random-string-here
   PORT=3000
   ```
6. Go to Settings → Networking → Generate Domain
7. Copy your Railway URL (e.g. https://tracl-production.up.railway.app)
8. In public/index.html, find this line:
   ```js
   const API = window.location.hostname === 'localhost' ...
   ```
   The empty string `''` means same-origin — this works automatically since
   the frontend is served by the backend. No changes needed.

Done. Your data syncs across every device.

## NFC dock setup

Write these strings to your NFC tags using any NFC writing app (e.g. NFC Tools):

- Tag A (drop-in): plain text → `tracl-start`
- Tag B (pull-out): plain text → `tracl-stop`

Works on Android Chrome. iOS Safari does not support Web NFC.

## Security note

Passwords are hashed with SHA-256 + a server secret. For a production app
serving many users, replace with bcrypt. The JWT expiry is 90 days.
