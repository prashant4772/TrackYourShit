# tracl

Honest study tracking. Tap to start, tap to stop.

## What's in here

```
server.js            — Node.js backend (Express, no native dependencies)
public/index.html    — Frontend (served by the backend)
tracl.db.json        — Database (auto-created on first run, plain JSON file)
```

## Run locally

```bash
npm install
npm start
```

Open http://localhost:3000

The database (`tracl.db.json`) is created automatically. All data lives there.
Back it up by copying the file.

## Deploy to Railway (free, 5 minutes)

1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub → select your repo
3. Railway auto-detects Node.js and runs `npm start`
4. Go to Settings → Variables → add:
   ```
   JWT_SECRET=any-long-random-string-you-make-up
   PORT=3000
   ```
5. Go to Settings → Networking → Generate Domain
6. Your app is live at the Railway URL — open it on any device and data syncs

No native binaries. No external database. Just Node.js and two npm packages.

## API endpoints

| Method | Path             | Auth | What it does                          |
|--------|------------------|------|---------------------------------------|
| POST   | /auth/signup     | —    | Create account                        |
| POST   | /auth/login      | —    | Sign in, returns token                |
| GET    | /auth/me         | ✓    | Validate token, return user           |
| POST   | /sessions/start  | ✓    | Start session, returns server timestamp |
| POST   | /sessions/end    | ✓    | End session, saves duration           |
| GET    | /sessions/today  | ✓    | Today's sessions + any active session |
| GET    | /sessions/week   | ✓    | Last 7 days of sessions               |
| GET    | /sessions/stats  | ✓    | Streak, weekly total, avg session     |

## NFC dock setup

Write these to your NFC tags using any NFC writing app (e.g. NFC Tools on Android):

- Tag A (drop-in):  plain text → `tracl-start`
- Tag B (pull-out): plain text → `tracl-stop`

Works on Android Chrome. iOS Safari does not support Web NFC.
