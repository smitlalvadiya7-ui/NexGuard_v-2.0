"""
Built-in support FAQ + a zero-dependency assistant (WORK_PLAN Task 12).

The assistant keyword-scores the curated FAQ below and returns the best
match with a confidence, plus a few related questions. No API key, no cost,
works offline. A real Claude-powered assistant can replace answer_question()
later without changing the endpoint or UI (the user chose the FAQ bot first).

Leaf module: stdlib-only.
"""
import re
from collections import Counter

# Each entry: question (shown), answer (plain language), keywords (extra match
# terms beyond the words already in the question).
FAQ = [
    {
        "question": "How does the URL scanner work?",
        "answer": (
            "Paste any link and NexGuard checks it against live threat feeds "
            "(VirusTotal, Google Safe Browsing, URLHaus), follows redirects, "
            "inspects the page content, and runs a machine-learning model — then "
            "gives a SAFE / SUSPICIOUS / MALICIOUS verdict with the reasons."
        ),
        "keywords": ["url", "link", "website", "phishing", "scan a link"],
    },
    {
        "question": "How do I scan a QR code?",
        "answer": (
            "Open Scan → QR code and upload a photo or screenshot of the QR. "
            "NexGuard decodes the hidden link and runs it through the full URL "
            "scanner, so a malicious QR is caught before you ever open it."
        ),
        "keywords": ["qr", "qr code", "barcode", "scan qr"],
    },
    {
        "question": "How does the email analyzer detect phishing?",
        "answer": (
            "Upload a .eml file or paste an email. NexGuard checks the sender's "
            "SPF/DKIM/DMARC authentication, verifies whether it genuinely comes "
            "from the brand it claims (see 'verified sender'), scans every link "
            "and attachment, and scores scam wording."
        ),
        "keywords": ["email", "phishing email", "spf", "dkim", "dmarc", "eml"],
    },
    {
        "question": "What does 'Verified sender' mean?",
        "answer": (
            "It means the email really comes from the company it claims to be — "
            "the sender's domain matches that brand's official domains AND the "
            "SPF/DKIM/DMARC authentication passed. A genuine bank email is not "
            "penalised for talking about OTPs or accounts. 'Sender impersonation' "
            "means it claims a brand but was sent from a domain that is not theirs."
        ),
        "keywords": ["verified sender", "sender", "impersonation", "genuine",
                     "really from", "spoof", "origin"],
    },
    {
        "question": "How do I scan my Gmail inbox?",
        "answer": (
            "Open Scan → Email → 'Scan inbox (Gmail)'. The first time, add your "
            "Google OAuth credentials.json to the backend and authorize read-only "
            "access; after that NexGuard scores your recent messages. Not "
            "connected? You can preview with sample emails, clearly labelled."
        ),
        "keywords": ["gmail", "inbox", "connect gmail", "google mail"],
    },
    {
        "question": "How does the voice / call scam scanner work?",
        "answer": (
            "Upload a call recording (wav, mp3, mp4, or WhatsApp audio). NexGuard "
            "transcribes it — in any language, translating to English — and scores "
            "it for scam intent (bank/OTP, delivery-fee, job, investment, lottery, "
            "and more), giving a '% likely scam' rating and confidence."
        ),
        "keywords": ["voice", "call", "audio", "phone", "scam call", "vishing",
                     "recording", "language", "hindi"],
    },
    {
        "question": "How does the screenshot scanner work?",
        "answer": (
            "Upload a screenshot of a message or web page. NexGuard reads the text "
            "with OCR and flags scam wording and dangerous links. If the image is "
            "too blurry to read, it honestly says UNKNOWN rather than guessing SAFE."
        ),
        "keywords": ["screenshot", "image", "ocr", "capture", "picture"],
    },
    {
        "question": "How do I scan many URLs at once (batch)?",
        "answer": (
            "Batch scanning is a Premium feature: open Scan → Batch, upload a CSV/TXT "
            "or paste one URL per line, and NexGuard scans them all with live progress "
            "and a downloadable report."
        ),
        "keywords": ["batch", "many urls", "bulk", "csv", "list of urls"],
    },
    {
        "question": "What do SAFE, SUSPICIOUS and MALICIOUS mean?",
        "answer": (
            "Every scan gives a risk score 0–100. 0–39 is SAFE, 40–69 is SUSPICIOUS "
            "(be careful), and 70–100 is MALICIOUS (do not open / do not act). "
            "UNKNOWN means there wasn't enough to analyze — treat it as 'not cleared'."
        ),
        "keywords": ["verdict", "safe", "suspicious", "malicious", "risk score",
                     "unknown", "what does the score mean"],
    },
    {
        "question": "Is the 89% or the 97% the real accuracy?",
        "answer": (
            "The headline real-world number is what matters: the full scanner "
            "pipeline scores ~98% precision and recall on live phishing vs "
            "legitimate URLs. The lower ~92% figure is only the offline "
            "machine-learning component — one channel inside the scanner, not the "
            "whole product. Both are shown on the Model page."
        ),
        "keywords": ["accuracy", "89", "92", "97", "98", "precision", "recall",
                     "how accurate", "model"],
    },
    {
        "question": "What is the difference between Free and Premium?",
        "answer": (
            "Free covers the core scanners with a daily scan limit. Premium removes "
            "the limit and unlocks batch scanning, the watchlist, and full forensic "
            "detail (hosting, WHOIS, SSL, redirect chains). Upgrade from Settings."
        ),
        "keywords": ["premium", "free", "upgrade", "plan", "billing", "limit",
                     "pricing", "subscription"],
    },
    {
        "question": "How do I report a wrong verdict?",
        "answer": (
            "On a URL result, use '🚩 Report incorrect verdict' to tell us the "
            "correct label — it goes to our reviewers and helps retrain the model. "
            "For anything else, use the contact form on this Support page."
        ),
        "keywords": ["report", "wrong verdict", "incorrect", "false positive",
                     "mistake", "feedback"],
    },
]

_STOP = {
    "the", "a", "an", "is", "are", "do", "does", "how", "what", "why", "to",
    "of", "on", "in", "my", "me", "i", "it", "this", "that", "and", "or",
    "for", "with", "can", "you", "your", "we", "us", "if", "be", "am", "so",
    "mean", "means", "work", "works", "help",
}

_MATCH_THRESHOLD = 0.3


def _tokens(text: str) -> list:
    return [w for w in re.findall(r"[a-z0-9]+", (text or "").lower()) if w not in _STOP]


def _entry_terms(entry: dict) -> Counter:
    terms = _tokens(entry["question"]) + _tokens(entry["answer"])
    for kw in entry.get("keywords", []):
        terms += _tokens(kw)
        if " " in kw:
            terms.append(kw.lower())   # keep multi-word phrases whole too
    return Counter(terms)


_ENTRY_TERMS = [_entry_terms(e) for e in FAQ]


def _score(question: str, terms: Counter) -> float:
    q = _tokens(question)
    ql = (question or "").lower()
    if not q:
        return 0.0
    hits = 0.0
    for w in set(q):
        if w in terms:
            hits += 1
    # phrase bonus: a multi-word keyword appearing verbatim is a strong signal
    for phrase, _c in terms.items():
        if " " in phrase and phrase in ql:
            hits += 1.5
    return hits / max(3, len(set(q)))


def answer_question(question: str) -> dict:
    """
    Return {matched, confidence, question, answer, related[]}.
    matched is False (with a contact-us fallback answer) when nothing scores
    above the threshold.
    """
    scores = [(_score(question, terms), i) for i, terms in enumerate(_ENTRY_TERMS)]
    scores.sort(reverse=True)
    best_score, best_i = scores[0]

    related = [FAQ[i]["question"] for s, i in scores[1:4] if s > 0]

    if best_score < _MATCH_THRESHOLD:
        return {
            "matched": False,
            "confidence": round(best_score, 2),
            "question": None,
            "answer": (
                "I'm not sure about that one. Try rephrasing, browse the FAQ "
                "below, or use the contact form to send our support team a "
                "message — they'll get back to you."
            ),
            "related": related or [FAQ[0]["question"], FAQ[3]["question"]],
        }

    best = FAQ[best_i]
    return {
        "matched": True,
        "confidence": round(min(1.0, best_score), 2),
        "question": best["question"],
        "answer": best["answer"],
        "related": related,
    }
