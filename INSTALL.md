# Installation Guide

This guide covers what to install and how to run NexGuard AI.
For how to use each feature, see [USAGE.md](USAGE.md).

---

## 1. What to install

### Required

| Software | Version | Download |
|---|---|---|
| Python | 3.12 or newer (tick **"Add python.exe to PATH"** during setup) | https://www.python.org/downloads/ |
| Node.js | 22 LTS or newer | https://nodejs.org/ |
| Git | any recent version | https://git-scm.com/downloads |

### Optional (needed only for some scan types)

| Software | Needed for | Download |
|---|---|---|
| Tesseract OCR | Screenshot scans | Windows: https://github.com/UB-Mannheim/tesseract/wiki (install to the default folder `C:\Program Files\Tesseract-OCR`) |
| ffmpeg | mp3 / mp4 / m4a voice files (WAV works without it) | https://ffmpeg.org/download.html (add it to PATH) |
| Ollama | Free AI answers in the support chat | https://ollama.com/download |

On **Linux** install the system packages instead:

```bash
sudo apt install tesseract-ocr libzbar0 ffmpeg
```

---

## 2. Get the code

```bash
git clone https://github.com/smitlalvadiya7-ui/NexGuard_v-2.0.git
cd NexGuard_v-2.0
```

---

## 3. Configure your settings

Create your own settings file from the template:

```bash
# Windows
copy backend\.env.example backend\.env

# Linux / macOS
cp backend/.env.example backend/.env
```

Open `backend/.env` in a text editor and fill in the values below.
**Never share or upload this file.** It holds your passwords and keys.

### Required

| Setting | What to put |
|---|---|
| `NEXGUARD_DEPLOYMENT_PROFILE` | Keep `noncommercial` (this is a free demo build) |
| `JWT_SECRET` | A long random string. Generate one with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `ADMIN_PASSWORD` | Password for the built-in `admin@nexguard.local` account |
| `SUPERADMIN_PASSWORD` | Password for the built-in `superadmin@nexguard.local` account |
| `NEXGUARD_ALLOWED_ORIGINS` | Leave empty on your own computer. On a server, put your website address, e.g. `https://yourdomain.com` |

### Recommended (better detection)

All of these have a free plan. Without them the scanner still works using its own rules and ML model.

| Setting | Get a free key at |
|---|---|
| `VIRUSTOTAL_API_KEY` | https://www.virustotal.com/gui/my-apikey |
| `GOOGLE_SAFEBROWSING_API_KEY` | https://developers.google.com/safe-browsing/v4/get-started |
| `URLHAUS_AUTH_KEY` | https://urlhaus.abuse.ch/api/ |
| `URLSCAN_API_KEY` | https://urlscan.io/user/profile/ (enables the live page preview) |

Optional features (Telegram bot, Gmail, voice, support emails) are set up in [section 8](#8-optional-features).

---

## 4. Build the dashboard

Run this once, and again whenever the frontend code changes:

```bash
cd frontend
npm ci
npm run build
cd ..
```

---

## 5. Run on Windows

From the project folder:

```cmd
run.cmd
```

- The **first run** creates a Python virtual environment and installs all
  dependencies (about 2 GB on disk). This takes several minutes. Later runs
  start in a few seconds.
- When you see `Dashboard : http://127.0.0.1:8000`, open that address in your browser.
- Stop the server with **Ctrl + C**.

Other commands:

| Command | What it does |
|---|---|
| `run.cmd check` | Shows which settings are present or missing, without starting |
| `run.cmd setup` | Re-installs the Python dependencies |
| `run.cmd test` | Runs the backend test suite |
| `npm start` | Same as `run.cmd` |

---

## 6. Run on Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

cd backend
python -m uvicorn main:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000 in your browser.

---

## 7. Install the Chrome extension

1. Open `chrome://extensions` in Chrome (or `edge://extensions` in Edge).
2. Turn on **Developer mode** (top-right).
3. Click **Load unpacked** and select the `extension` folder of this project.
4. Right-click the NexGuard icon → **Options**:
   - **Backend URL**: keep `http://127.0.0.1:8000` unless your server runs elsewhere
   - **Sign in** with your NexGuard account. Without sign-in the extension is
     limited to 5 scans per day.

The NexGuard server must be running for the extension to work.

---

## 8. Optional features

### Telegram bot

1. In Telegram, open **@BotFather** → `/newbot` → copy the token.
2. In `backend/.env` set `NEXGUARD_TELEGRAM_TOKEN=<your token>`.
   Optionally set `NEXGUARD_BOT_EMAIL` and `NEXGUARD_BOT_PASSWORD` to a NexGuard
   account so the bot gets that account's daily limit.
3. Start the server (section 5), then in a **second** terminal:
   ```cmd
   cd backend
   ..\.venv\Scripts\python.exe telegram_bot.py
   ```
4. Run only **one** copy of the bot at a time, or every message is answered twice.

### Voice scans

| Option | Settings | Notes |
|---|---|---|
| Offline (recommended) | `NEXGUARD_ENABLE_WHISPER=1` and `NEXGUARD_WHISPER_MODEL=small` | Works without internet. The model (~460 MB) downloads on first use. Handles Hindi and English. |
| Online | `NEXGUARD_ENABLE_ONLINE_STT=1` | Uses a free online speech service. For personal testing only. |

### Gmail inbox scan (personal use)

1. In [Google Cloud Console](https://console.cloud.google.com/), enable the **Gmail API**
   and create **OAuth client ID → Desktop app** credentials.
2. Download the file and save it as `backend/credentials.json`
   (the format is shown in `backend/credentials.json.example`).
3. Restart the server and click **Scan inbox (Gmail)**. The first time, a Google
   login window opens and a `token.json` file is created.

Keep `credentials.json` and `token.json` private. This feature is meant for your own
account; offering it to the public needs Google's app verification.

### AI answers in the support chat

```bash
ollama pull qwen2.5:7b
```
Then set `NEXGUARD_OLLAMA_MODEL=qwen2.5:7b` in `backend/.env`.
The first answer after a while can take 1–2 minutes while the model loads.

### AI image check

The detection model (~300 MB) downloads automatically on first use.
Set `NEXGUARD_IMAGE_MODEL=off` to turn the model off.

### Support ticket emails

Fill in the `NEXGUARD_SMTP_*` settings and `NEXGUARD_SUPPORT_TO`.
For Gmail, use an **App Password** (Google Account → Security → App passwords),
not your normal password.

---

## 9. Run the tests

```bash
# Backend (from the project folder)
pip install pytest
python -m pytest

# Chrome extension
node --test extension/tests/*.cjs

# Dashboard
cd frontend
npm test
```

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| `Python not found` | Reinstall Python and tick **"Add python.exe to PATH"** |
| `run.cmd` says **NOT READY** | Fill in the missing required settings it lists in `backend/.env` |
| Port 8000 already in use | Another copy of the server is running. Close it, or restart your computer |
| Dashboard does not show recent changes | Run `npm run build` in the `frontend` folder again |
| Forgot the admin password | Change `ADMIN_PASSWORD` in `backend/.env` and restart. If it was left empty, a random password was printed once in the server window |
| Screenshot scan fails | Install Tesseract OCR to its default folder |
| mp3 / mp4 voice scan fails | Install ffmpeg and add it to PATH |
| Telegram bot replies twice | Two copies of the bot are running. Close one |
| Extension does nothing | Make sure the server is running and you are signed in from the extension Options page |
