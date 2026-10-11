# User Guide

Step-by-step guide for every task in NexGuard AI.
To install and start NexGuard first, see [INSTALL.md](INSTALL.md).

Open the dashboard at **http://127.0.0.1:8000** (or your server's address).

---

## Understanding a result

Every scan shows:

| Item | Meaning |
|---|---|
| **Verdict** | 🟢 **SAFE**: no warning signs found · 🟡 **SUSPICIOUS**: be careful · 🔴 **MALICIOUS**: do not open, reply or pay |
| **Risk score** | 0–100; higher means more dangerous |
| **Confidence** | How sure the scanner is about the verdict |
| **Reasons** | The warning signs that were found, in plain words |

If a verdict looks wrong, use the feedback buttons under the result to report it.

---

## Account

### Create an account
1. Open the dashboard → **Register** tab.
2. Enter your email and a password → submit.
3. You are signed in on the **Free** plan (10 scans per day).

### Sign in / sign out
- **Login** tab → email and password.
- Sign out from the sidebar.
- You can also scan without an account (5 scans per day).

### Get Premium (demo, no payment)
1. Go to **Settings**.
2. Under **Upgrade to Premium**, click **⭐ Request Premium (approval)**.
3. An admin approves the request. Your plan then shows **Premium**.

---

## Scanning

All scans are on the **Scan** page. Pick a tab at the top.

### Check a link (URL)
1. **Scan → URL**.
2. Paste the link, e.g. `https://example.com/login`.
3. Click **Scan URL**.

### Check a QR code
1. **Scan → QR code**.
2. Upload a photo or screenshot of the QR code.
3. NexGuard reads the hidden link and scans it.

### Check an email
1. **Scan → Email → Upload email file**.
2. Upload the email as an `.eml` file. In Gmail use **⋮ → Download message**;
   in Outlook use **File → Save As**.
3. The result covers the sender's authenticity, the wording and every link in the email.

### Scan your Gmail inbox
1. **Scan → Email → Scan inbox (Gmail)** (needs the one-time setup in INSTALL.md).
2. Sign in with Google the first time.
3. Your recent emails are listed with a verdict for each.

### Check a screenshot
1. **Scan → Screenshot**.
2. Upload a screenshot of a chat, SMS or web page.
3. NexGuard reads the text in the image and checks it for scam patterns.

### Check a voice message or call recording
1. **Scan → Voice**.
2. Upload the audio file (WAV, or mp3 / mp4 / m4a if ffmpeg is installed).
3. The speech is converted to text (Hindi and English) and checked for scam phrases.

### Live protection during a call
1. **Scan → Voice → Live Scam Protection** (Chrome or Edge).
2. Allow microphone access and put the call on speaker.
3. NexGuard listens and **warns out loud** if it hears scam phrases.

### Is an image AI-generated?
1. **Scan → AI Image**.
2. Upload the photo.
3. The result says **AI-generated (confirmed)**, **Likely AI-generated**,
   **Likely a real photo** or **Uncertain**, with the reasons.
   Images forwarded on WhatsApp lose their details, so **Uncertain** is more common there.

### Scan many links at once (Premium)
1. **Scan → Batch**.
2. Paste up to **200** links, one per line → start the scan.
3. When it finishes, download the results as **CSV** or **PDF**.

---

## History, watchlist and reports

### See past scans
- **Activity → History** lists every scan with its verdict.
- Use **Re-scan** on any entry to check it again with fresh data.

### Watch a link over time (Premium)
1. **Activity → Watchlist** → add a URL.
2. Click **Re-scan** to check all saved URLs again, so you notice when a safe link turns dangerous.

### Download a PDF report
1. Go to **Reports**.
2. Pick a scan → click **📄 Generate PDF**.

### Dashboard
The **Dashboard** shows your scan totals, verdict charts, a threat map, the live
threat feed and real-time alerts.

---

## Chrome extension

Install it first (INSTALL.md, section 7) and sign in from its **Options** page.

| Task | How |
|---|---|
| Automatic protection | Just browse. Dangerous pages are blocked with a warning before they load |
| Check a link before clicking | Hover over it; risky links are marked |
| Scan anything manually | Right-click a link, image or selected text → **Scan … with NexGuard** |
| Email sender check | Open an email in Gmail or Outlook web; a badge shows if the sender looks fake |
| Change protection level | Options → **Protection level** (stricter blocks more, relaxed only warns) |
| Trust a site | Options → add it to your trusted sites |

---

## Telegram bot

1. Open your NexGuard bot in Telegram and send **/start**.
2. Send any of these:
   - a **link**
   - a **photo** (QR code, screenshot, or an image for the AI check)
   - a **voice note**
   - an **`.eml`** email file
3. The bot replies with the verdict, the risk level, the reasons and a safety tip.

You can write in any language; replies are in English.

---

## Developer API

1. Go to **Settings → API keys** → create a key. Copy it right away; it is shown only once.
2. Send a URL to scan:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/scan \
  -H "X-API-Key: <your key>" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

3. Revoke a key anytime from the same page.

---

## Help and support

- **Support** page: ask a question in the help chat, or open a support ticket.
- Replies to your tickets appear on the same page.

---

## Admin tasks (admin and superadmin only)

Open **Admin** from the sidebar.

| Tab | What you can do |
|---|---|
| **Users** | See all users, change plan (Free / Premium), suspend or activate accounts |
| **Requests** | Approve or reject Premium requests |
| **Feedback** | Review "wrong verdict" reports from users |
| **Support** | Read and reply to support tickets |
| **Stats** | Usage statistics for all users |
| **Audit** | *(superadmin)* Log of every admin action |

Superadmins can also promote a user to admin or demote an admin.
